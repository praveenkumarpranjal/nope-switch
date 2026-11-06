from __future__ import annotations

import argparse
import json
import shutil
import subprocess
from pathlib import Path
from typing import Any

from nope_core import assurance, scar_service
from nope_core.db import Scar, SessionLocal, init_db
from nope_core.rule_lab import RuleLab
from nope_core.schemas import CreateScarRequest
from sqlalchemy import select

REPO_ROOT = Path(__file__).resolve().parents[4]
DEMO = REPO_ROOT / "demo-app"


def _load_json(path: Path) -> dict[str, Any]:
    parsed = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(parsed, dict):
        raise SystemExit(f"{path} must contain a JSON object")
    return parsed


def _print(title: str, body: object) -> None:
    print(f"\n== {title} ==")
    if isinstance(body, str):
        print(body)
    else:
        print(json.dumps(body, indent=2, default=str))


def reset() -> None:
    root = REPO_ROOT / ".data"
    if root.exists() and REPO_ROOT in root.parents:
        shutil.rmtree(root)
    root.mkdir(parents=True, exist_ok=True)
    init_db()
    print(f"Reset local ledger at {root}.")


def teach() -> None:
    init_db()
    payload = CreateScarRequest.model_validate(_load_json(DEMO / "fixtures" / "teach.json"))
    with SessionLocal() as db:
        scar = scar_service.create_scar(db, payload, "demo:offline-switch-agent")
        db.commit()
        _print("Scar created", scar_service.scar_response(scar).model_dump())


def validate() -> None:
    init_db()
    bad_path = DEMO / "fixtures" / "bad-authorization-log.ts"
    good_path = DEMO / "fixtures" / "good-redacted-log.ts"
    rule = REPO_ROOT / "config" / ".semgrep" / "nope-active.yml"
    with SessionLocal() as db:
        scar = db.scalar(select(Scar).order_by(Scar.number.desc()))
        if not scar:
            raise SystemExit("No scar found; run `uv run nope-demo teach` first.")
        original = {"name": "original.ts", "content": bad_path.read_text(encoding="utf-8")}
        corrected = {"name": "corrected.ts", "content": good_path.read_text(encoding="utf-8")}
        version = scar_service.add_rule_version(db, scar, rule.read_text(encoding="utf-8"))
        db.flush()
        revision = assurance.build_revision(db, scar, version, "demo:offline-switch-agent",
            {"original": original, "corrected": corrected, "bad": [original], "good": [corrected], "target_path": str(DEMO / "src")}, RuleLab())
        scar.status = "validated" if revision.state == "validated" else "proposed"
        scar_service._audit(db, "demo:offline-switch-agent", "scar.replay_completed", {"revision_id": revision.id, **json.loads(revision.report)}, scar.id)
        db.commit()
        _print("Counterfactual replay and validation", json.loads(revision.report))
        if revision.state != "validated":
            raise SystemExit("Rule did not pass. See output above.")


def adversarial() -> None:
    init_db()
    with SessionLocal() as db:
        scar = db.scalar(select(Scar).order_by(Scar.number.desc()))
        if scar is None:
            raise SystemExit("Create and validate a Scar first")
        revision = assurance.latest(db, scar)
        if revision is None:
            raise SystemExit("Validate a rule revision first")
        bundle = _load_json(DEMO / "fixtures" / "adversarial-challenge.json")
        metrics = assurance.adversarial(db, revision, "demo:independent-adversary", bundle, RuleLab())
        scar_service._audit(db, "demo:independent-adversary", "scar.adversarial_completed", {"revision_id": revision.id, **metrics}, scar.id)
        db.commit()
        _print("Independent adversarial challenge", metrics)
        if not metrics["passed"]:
            raise SystemExit("Challenge quality threshold not met; reviewer must reject or request a revision")


def approve(number: int) -> None:
    init_db()
    with SessionLocal() as db:
        scar = db.scalar(select(Scar).where(Scar.number == number))
        if not scar:
            raise SystemExit(f"Scar {number} not found")
        scar = scar_service.approve_scar(db, scar, "demo:human-approver", "sre@acme.example", "This rule is exact, tested and links to INC-014.")
        db.commit()
        _print("Approved", scar_service.scar_response(scar).model_dump())


def activate(number: int) -> None:
    init_db()
    with SessionLocal() as db:
        scar = db.scalar(select(Scar).where(Scar.number == number))
        if not scar:
            raise SystemExit(f"Scar {number} not found")
        scar = scar_service.activate_scar(db, scar, "demo:human-approver")
        db.commit()
        _print("Active", scar_service.scar_response(scar).model_dump())


def _semgrep(path: Path, expect_findings: bool) -> int:
    semgrep = shutil.which("semgrep")
    config = REPO_ROOT / "config" / ".semgrep" / "nope-active.yml"
    if not semgrep:
        print("semgrep not installed; run `uv sync --extra semgrep` or brew install semgrep")
        return 3
    command = [semgrep, "scan", "--config", str(config), "--json", "--quiet", str(path)]
    completed = subprocess.run(command, capture_output=True, text=True, check=False)
    if completed.returncode not in (0, 1):
        print(completed.stderr or completed.stdout)
        return completed.returncode
    findings = len(json.loads(completed.stdout or "{}").get("results", []))
    if expect_findings and findings:
        print(f"BLOCKED: {findings} qualifying credential log finding(s) with Scar 001.", end="\n\n")
        print("NOPE Scar 001 — Never expose authentication credentials in logs")
        print("Reason: INC-014; credentials reached customer support through monitoring.")
        print("Fix: delete the credential from the log or log user.id instead.")
        return 42
    if expect_findings:
        print(f"Expected a finding in {path}, but Semgrep reported none.")
        return 1
    if findings:
        print(f"Desk is unsafe: {findings} finding(s) in {path}.")
        return 1
    print(f"Clean: no Scar 001 findings in {path}")
    return 0


def main() -> None:
    parser = argparse.ArgumentParser(prog="nope-demo", description="Deterministic, offline NOPE demonstration")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("reset")
    sub.add_parser("teach")
    sub.add_parser("validate")
    sub.add_parser("adversarial")
    approval = sub.add_parser("approve")
    approval.add_argument("number", type=int)
    activation = sub.add_parser("activate")
    activation.add_argument("number", type=int)
    sub.add_parser("scan-good")
    sub.add_parser("scan-bad")
    args = parser.parse_args()
    if args.command == "reset":
        reset()
    elif args.command == "teach":
        teach()
    elif args.command == "validate":
        validate()
    elif args.command == "adversarial":
        adversarial()
    elif args.command == "approve":
        approve(args.number)
    elif args.command == "activate":
        activate(args.number)
    elif args.command == "scan-good":
        raise SystemExit(_semgrep(DEMO / "src", False))
    elif args.command == "scan-bad":
        raise SystemExit(_semgrep(DEMO / "fixtures" / "bad-authorization-log.ts", True))

if __name__ == "__main__":
    main()
