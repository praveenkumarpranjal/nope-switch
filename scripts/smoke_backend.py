"""Exercise real HTTP, RBAC, persistence and Semgrep in an isolated test ledger.

Approvals in this check are automated test fixtures, never human sign-off.
NOPE_SMOKE_DATABASE_URL may point to a disposable PostgreSQL test database.
The developer's normal DATABASE_URL and ledger are never used.
"""

from __future__ import annotations

import hashlib
import json
import os
import secrets
import socket
import tempfile
import threading
import time
from pathlib import Path
from typing import Any

import httpx
import uvicorn
from nope_core.paths import data_root, project_root
from nope_core.rule_lab import RuleLab


def main() -> None:
    root = project_root()
    destination = data_root()
    destination.mkdir(parents=True, exist_ok=True)
    keys = {role: secrets.token_hex(24) for role in ("agent", "challenger", "approver", "admin", "ci")}
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        port = listener.getsockname()[1]
    with tempfile.TemporaryDirectory(prefix="nope-smoke-", dir=destination) as temporary:
        folder = Path(temporary)
        database = os.getenv("NOPE_SMOKE_DATABASE_URL") or f"sqlite:///{folder / 'ledger.db'}"
        environment = {**os.environ, "DATABASE_URL": database, "NOPE_ENV": "production",
            "NOPE_WORKDIR": str(folder), "NOPE_ALLOW_ANONYMOUS": "false",
            "NOPE_API_KEYS": ",".join(f"{key}:{'agent' if role == 'challenger' else role}"
                                      for role, key in keys.items())}
        os.environ.update(environment)
        from nope_core.db import engine
        from nope_core.main import app

        server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=port,
                                              access_log=False, log_level="warning"))
        worker = threading.Thread(target=server.run, daemon=True)
        worker.start()
        try:
            with httpx.Client(base_url=f"http://127.0.0.1:{port}", timeout=150) as client:
                deadline = time.monotonic() + 30
                while True:
                    try:
                        response = client.get("/health")
                        response.raise_for_status()
                        break
                    except httpx.HTTPError:
                        if not worker.is_alive() or time.monotonic() >= deadline:
                            raise RuntimeError("Isolated backend did not become healthy") from None
                        time.sleep(0.2)

                def call(path: str, payload: dict[str, Any], role: str = "agent", status: int = 200) -> dict[str, Any]:
                    response = client.post(path, json=payload, headers={"X-NOPE-Key": keys[role]})
                    if response.status_code != status:
                        raise RuntimeError(f"{path}: expected HTTP {status}, received {response.status_code}: {response.text[:300]}")
                    return dict(response.json())

                assert client.get("/v1/scars").status_code == 401
                fixture = root / "demo-app/fixtures"
                proposal = json.loads((fixture / "teach.json").read_text(encoding="utf-8"))
                proposal["repository"] = "smoke/isolated"
                scar = call("/v1/scars", proposal, status=201)
                path = f"/v1/scars/{scar['number']}"
                original = {"name": "original.ts", "content": (fixture / "bad-authorization-log.ts").read_text(encoding="utf-8")}
                corrected = {"name": "corrected.ts", "content": (fixture / "good-redacted-log.ts").read_text(encoding="utf-8")}
                rule = (root / "config/.semgrep/nope-active.yml").read_text(encoding="utf-8")
                validation = call(path + "/validate?sync=true", {"rule_yaml": rule, "original": original,
                    "corrected": corrected, "bad_examples": [original], "good_examples": [corrected]})
                assert validation["passed"] and validation["replay"]["original_detected"] and validation["replay"]["corrected_passes"]
                challenge = json.loads((fixture / "adversarial-challenge.json").read_text(encoding="utf-8"))
                metrics = call(path + "/adversarial", challenge, "challenger")
                assert metrics["passed"] and metrics["misses"] == 0 and metrics["false_positives"] == 0
                request = call(path + "/approval-request", {"revision_id": validation["revision_id"]})
                decision = {**request, "approver": "AUTOMATED SMOKE FIXTURE",
                            "reason": "Isolated automated test; this is not human approval"}
                call(path + "/approve", decision, status=403)
                call(path + "/approve", {**decision, "evidence_sha256": "0" * 64}, "approver", 409)
                call(path + "/approve", decision, "approver")
                call(path + "/activate", {"authorized_by": "AUTOMATED SMOKE FIXTURE",
                    "reason": "Isolated automated break-glass test; never a production activation"}, "admin")
                exported = client.get("/v1/rules/active.yml", headers={"X-NOPE-Key": keys["ci"]})
                exported.raise_for_status()
                replay = RuleLab().validate(exported.text, [(original["name"], original["content"])],
                                            [(corrected["name"], corrected["content"])])
                assert replay.passed, replay.rule_errors
                finding = call("/v1/ci/failure", {"repository": proposal["repository"], "sha": "a" * 40,
                    "scar_number": scar["number"], "check_url": "https://ci.example/isolated-smoke",
                    "revision_id": validation["revision_id"]}, "ci")
                assert finding["revision_id"] == validation["revision_id"] and finding["tests"]
                report = {"status": "passed", "approval": "AUTOMATED TEST ONLY",
                    "database": "postgresql" if database.startswith("postgresql") else "sqlite",
                    "http_rbac": "passed", "counterfactual_replay": validation["replay"],
                    "detections": metrics["detections"], "misses": metrics["misses"],
                    "false_positives": metrics["false_positives"],
                    "approval_substitution_rejected": True, "export_replay": replay.passed,
                    "rule_sha256": hashlib.sha256(rule.encode()).hexdigest(), "ci_provenance": "passed"}
                output = destination / f"backend-smoke-{report['database']}.json"
                output.write_text(json.dumps(report, indent=2), encoding="utf-8")
                print(json.dumps(report, indent=2))
        finally:
            server.should_exit = True
            worker.join(timeout=15)
            engine.dispose()
            if worker.is_alive():
                raise RuntimeError("Isolated backend did not shut down cleanly")


if __name__ == "__main__":
    main()
