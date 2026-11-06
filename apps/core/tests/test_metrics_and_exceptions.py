from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, cast

from fastapi.testclient import TestClient
from nope_core.auth import Role, issue_token
from nope_core.db import Base, ExceptionRecord, Revision, RuleVersion, SessionLocal, engine
from nope_core.main import app
from nope_core.metrics import REGISTRY
from nope_core.reporter import process_scan_file


def reset_schema() -> None:
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)


def _create_scar(client: TestClient, token: str, repo: str = "acme/auth", proposed_by: str = "test-author") -> dict[str, Any]:
    res = client.post(
        "/v1/scars",
        headers={"Authorization": f"Bearer {token}"},
        json={
            "title": "Never leak credentials in application logs",
            "incident_summary": "Incident summary explaining the credential exposure vulnerability",
            "invariant": "Never leak credentials in application logs",
            "rationale": "Logs are broad and retained indefinitely",
            "remediation": "Do not log credentials",
            "repository": repo,
            "scope": "src/",
            "severity": "high",
            "enforcement": "semgrep",
            "origin": "INC-099",
            "proposed_by": proposed_by,
        },
    )
    assert res.status_code == 201
    return cast(dict[str, Any], res.json())


def test_exception_lifecycle_approval_and_query() -> None:
    reset_schema()
    agent_token = issue_token("test-author", Role.AGENT)
    approver_token = issue_token("security-lead@acme.com", Role.APPROVER)
    ci_token = issue_token("ci-runner", Role.CI)

    with TestClient(app) as client:
        scar = _create_scar(client, agent_token)
        scar_id = scar["id"]

        # 1. Challenge scar requesting a scoped exception for legacy migration
        chal_resp = client.post(
            f"/v1/scars/{scar_id}/challenge",
            headers={"Authorization": f"Bearer {agent_token}"},
            json={
                "challenger": "test-author",
                "requested_by": "test-author",
                "reason": "Temporary exception while migrating legacy auth handler to v2",
                "path_pattern": "src/legacy/",
                "expires_in_days": 14,
            },
        )
        assert chal_resp.status_code == 202
        exc_id = chal_resp.json()["exception_id"]
        assert exc_id is not None

        # 2. Before approval, active exceptions endpoint returns 0 exceptions
        active_before = client.get("/v1/exceptions/active", headers={"Authorization": f"Bearer {ci_token}"})
        assert active_before.status_code == 200
        assert len(active_before.json()) == 0

        # 3. Approver approves the exception
        app_resp = client.post(
            f"/v1/exceptions/{exc_id}/approve",
            headers={"Authorization": f"Bearer {approver_token}"},
            json={"approver": "security-lead@acme.com", "reason": "Approved for 14 day migration window"},
        )
        assert app_resp.status_code == 200
        exc_data = app_resp.json()
        assert exc_data["status"] == "approved"
        assert exc_data["approver"] == "security-lead@acme.com"
        assert exc_data["path_pattern"] == "src/legacy/"
        assert exc_data["is_expired"] is False

        # 4. Now active exceptions endpoint returns the approved exception
        active_after = client.get("/v1/exceptions/active", headers={"Authorization": f"Bearer {ci_token}"})
        assert active_after.status_code == 200
        items = active_after.json()
        assert len(items) == 1
        assert items[0]["id"] == exc_id
        assert items[0]["scar_number"] == 1


def test_expired_exception_enforcement_in_ci(tmp_path: Path, monkeypatch: Any) -> None:
    reset_schema()
    monkeypatch.setenv("GITHUB_REPOSITORY", "acme/auth")
    monkeypatch.setenv("GITHUB_SHA", "abcdef1234567890abcdef1234567890abcdef12")
    admin_token = issue_token("admin", Role.ADMIN)
    ci_token = issue_token("ci-runner", Role.CI)

    with TestClient(app) as client:
        scar = _create_scar(client, admin_token, repo="acme/auth", proposed_by="admin")
        scar_id = scar["id"]

        with SessionLocal() as db:
            rule_ver = RuleVersion(
                id="rv-auth-01",
                scar_id=scar_id,
                version=1,
                rule_yaml="rules: []",
                sha256="auth-rule-hash",
            )
            db.add(rule_ver)
            rev = Revision(
                id="rev-auth-01",
                scar_id=scar_id,
                organization_id="default",
                rule_id=rule_ver.id,
                sequence=1,
                author="admin",
                state="active",
                fixtures=json.dumps({"original": {}, "corrected": {}, "bad": [], "good": []}),
                report=json.dumps({}),
            )
            db.add(rev)
            db.commit()

        # Create challenge exception
        chal_resp = client.post(
            f"/v1/scars/{scar_id}/challenge",
            headers={"Authorization": f"Bearer {admin_token}"},
            json={
                "challenger": "admin",
                "requested_by": "admin",
                "reason": "Expiring exception for legacy path",
                "path_pattern": "src/legacy/",
                "expires_in_days": 1,
            },
        )
        exc_id = chal_resp.json()["exception_id"]

        # Approve the exception
        client.post(
            f"/v1/exceptions/{exc_id}/approve",
            headers={"Authorization": f"Bearer {admin_token}"},
            json={"approver": "admin", "reason": "Approved"},
        )

        # Create a mock Semgrep results file flagging a finding in src/legacy/auth.ts
        scan_file = tmp_path / "semgrep.json"
        scan_file.write_text(
            json.dumps({
                "results": [
                    {
                        "path": "src/legacy/auth.ts",
                        "start": {"line": 15, "col": 5},
                        "extra": {
                            "message": "Credential logged in legacy auth",
                            "metadata": {"scar": "SCAR-001", "remediation": "Redact token"},
                        },
                    }
                ],
                "errors": [],
            }),
            encoding="utf-8",
        )

        # Mock adapter to route reporter calls to client
        import httpx

        def test_client_factory(*args: Any, **kwargs: Any) -> Any:
            class ClientAdapter:
                def __init__(self, tc: TestClient, headers: dict[str, str]) -> None:
                    self.tc = tc
                    self.headers = headers

                def __enter__(self) -> ClientAdapter:
                    return self

                def __exit__(self, *a: Any) -> None:
                    pass

                def get(self, url: str, **kw: Any) -> Any:
                    h = {**self.headers, **kw.get("headers", {})}
                    return self.tc.get(url, headers=h, params=kw.get("params"))

                def post(self, url: str, **kw: Any) -> Any:
                    h = {**self.headers, **kw.get("headers", {})}
                    return self.tc.post(url, headers=h, json=kw.get("json"))

            return ClientAdapter(client, kwargs.get("headers", {}))

        monkeypatch.setattr(httpx, "Client", test_client_factory)

        # Case A: Exception is unexpired -> finding is excluded, exit code is 0!
        exit_code_active = process_scan_file(
            scan_json_path=scan_file,
            base_url="http://testserver",
            ci_key=ci_token,
        )
        assert exit_code_active == 0

        # Case B: Manually expire the exception in database
        with SessionLocal() as db:
            exc = db.get(ExceptionRecord, exc_id)
            assert exc is not None
            exc.expires_at = datetime.now(UTC) - timedelta(days=2)
            db.commit()

        # Run reporter again -> exception expired alert is emitted, finding is NOT excluded, exit code is 1!
        exit_code_expired = process_scan_file(
            scan_json_path=scan_file,
            base_url="http://testserver",
            ci_key=ci_token,
        )
        assert exit_code_expired == 1


def test_prometheus_metrics_endpoint() -> None:
    reset_schema()
    REGISTRY.reset()
    admin_token = issue_token("admin", Role.ADMIN)
    ci_token = issue_token("ci-runner", Role.CI)

    with TestClient(app) as client:
        # Create a scar
        scar = _create_scar(client, admin_token, repo="acme/service", proposed_by="admin")

        with SessionLocal() as db:
            rule_ver = RuleVersion(
                id="rv-svc-01",
                scar_id=scar["id"],
                version=1,
                rule_yaml="rules: []",
                sha256="svc-rule-hash",
            )
            db.add(rule_ver)
            rev = Revision(
                id="rev-svc-01",
                scar_id=scar["id"],
                organization_id="default",
                rule_id=rule_ver.id,
                sequence=1,
                author="admin",
                state="active",
                fixtures=json.dumps({"original": {}, "corrected": {}, "bad": [], "good": []}),
                report=json.dumps({}),
            )
            db.add(rev)
            db.commit()

        # Record a CI failure to increment failure counter
        ci_resp = client.post(
            "/v1/ci/failure",
            headers={"Authorization": f"Bearer {ci_token}"},
            json={
                "repository": "acme/service",
                "sha": "abcdef1234567890abcdef1234567890abcdef12",
                "scar_number": scar["number"],
                "check_url": "https://ci.acme.com/jobs/101",
            },
        )
        assert ci_resp.status_code == 200

        # Fetch /metrics
        metrics_resp = client.get("/metrics")
        assert metrics_resp.status_code == 200
        assert "text/plain" in metrics_resp.headers["content-type"]
        body = metrics_resp.text

        # Verify Core Prometheus Metrics
        assert "# TYPE nope_request_duration_seconds histogram" in body
        assert "# TYPE nope_scars_total gauge" in body
        assert "# TYPE nope_ci_failures_total counter" in body
        assert "# TYPE nope_exceptions_total gauge" in body
        assert "# TYPE nope_active_rules_total gauge" in body

        # Verify specific counter values
        assert 'nope_ci_failures_total{scar_number="1",repository="acme/service"} 1.0' in body
        assert 'nope_scars_total{status="proposed",organization_id="default"} 1.0' in body
