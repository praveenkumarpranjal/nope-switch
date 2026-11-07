from __future__ import annotations

import hashlib
import hmac
import json
from pathlib import Path
from typing import Any, cast

import pytest
import yaml
from fastapi.testclient import TestClient
from nope_core.cli import sync_rules_to_file, verify_rules_sync
from nope_core.db import AuditEvent, RuleVersion, Scar, SessionLocal
from nope_core.main import app
from nope_core.schemas import ScarStatus
from sqlalchemy import select


def _make_github_signature(payload_bytes: bytes, secret: str) -> str:
    return "sha256=" + hmac.new(secret.encode("utf-8"), payload_bytes, hashlib.sha256).hexdigest()


def test_webhook_ping_event() -> None:
    with TestClient(app) as client:
        resp = client.post(
            "/v1/webhooks/github",
            headers={"X-GitHub-Event": "ping"},
            json={"zen": "Keep it logically awesome."},
        )
        assert resp.status_code == 200
        assert resp.json() == {"status": "ok", "message": "PONG"}


def test_webhook_signature_verification(monkeypatch: pytest.MonkeyPatch) -> None:
    secret = "super-secret-key-12345"
    monkeypatch.setenv("GITHUB_WEBHOOK_SECRET", secret)

    payload = {"zen": "Signature verification test"}
    body_bytes = json.dumps(payload).encode("utf-8")

    with TestClient(app) as client:
        # 1. Missing signature header
        resp = client.post(
            "/v1/webhooks/github",
            headers={"X-GitHub-Event": "ping"},
            content=body_bytes,
        )
        assert resp.status_code == 401
        assert "Invalid or missing GitHub signature" in resp.json()["detail"]

        # 2. Invalid signature header
        resp = client.post(
            "/v1/webhooks/github",
            headers={
                "X-GitHub-Event": "ping",
                "X-Hub-Signature-256": "sha256=0000000000000000000000000000000000000000000000000000000000000000",
            },
            content=body_bytes,
        )
        assert resp.status_code == 401

        # 3. Valid signature header
        sig = _make_github_signature(body_bytes, secret)
        resp = client.post(
            "/v1/webhooks/github",
            headers={
                "X-GitHub-Event": "ping",
                "X-Hub-Signature-256": sig,
            },
            content=body_bytes,
        )
        assert resp.status_code == 200
        assert resp.json() == {"status": "ok", "message": "PONG"}


def test_webhook_secret_missing_in_production(monkeypatch: pytest.MonkeyPatch) -> None:
    import dataclasses

    import nope_core.config
    prod_settings = dataclasses.replace(nope_core.config.settings, env="production", github_webhook_secret="")
    monkeypatch.setattr("nope_core.main.settings", prod_settings)
    monkeypatch.delenv("GITHUB_WEBHOOK_SECRET", raising=False)

    with TestClient(app) as client:
        resp = client.post(
            "/v1/webhooks/github",
            headers={"X-GitHub-Event": "ping"},
            json={"zen": "production test"},
        )
        assert resp.status_code == 503
        assert "GitHub webhook secret is not configured" in resp.json()["detail"]


def test_webhook_ignores_non_merge_events() -> None:
    with TestClient(app) as client:
        # Non-PR event
        resp = client.post(
            "/v1/webhooks/github",
            headers={"X-GitHub-Event": "issues"},
            json={"action": "opened"},
        )
        assert resp.status_code == 200
        assert resp.json()["status"] == "ignored"

        # PR opened (not merged)
        resp = client.post(
            "/v1/webhooks/github",
            headers={"X-GitHub-Event": "pull_request"},
            json={
                "action": "opened",
                "pull_request": {"merged": False},
            },
        )
        assert resp.status_code == 200
        assert resp.json()["status"] == "ignored"
        assert "not closed and merged" in resp.json()["reason"]

        # PR closed but not merged
        resp = client.post(
            "/v1/webhooks/github",
            headers={"X-GitHub-Event": "pull_request"},
            json={
                "action": "closed",
                "pull_request": {"merged": False},
            },
        )
        assert resp.status_code == 200
        assert resp.json()["status"] == "ignored"


def _create_approved_scar(client: TestClient) -> dict[str, Any]:
    scar_payload = {
        "title": "Prevent SQL injection in raw query runner",
        "incident_summary": "Raw SQL concatenation led to database dump",
        "invariant": "Raw SQL strings must always use bound parameters",
        "rationale": "Direct concatenation is vulnerable",
        "remediation": "Use prepared statements with params tuple",
        "repository": "acme/payments",
        "scope": "src/",
        "severity": "critical",
        "enforcement": "semgrep",
        "origin": "INC-888",
        "proposed_by": "sec-ops",
    }
    resp = client.post("/v1/scars", headers={"X-NOPE-Key": "agent"}, json=scar_payload)
    assert resp.status_code == 201
    scar_data = resp.json()
    scar_id = scar_data["id"]

    rule_yaml = """rules:
  - id: acme.payments.no-raw-sql
    message: Never interpolate variables into raw queries
    severity: ERROR
    languages: [typescript, javascript]
    pattern: db.raw($QUERY)
    metadata:
      remediation: Use parameterized db.query(sql, params)
"""
    val_resp = client.post(
        f"/v1/scars/{scar_id}/validate",
        headers={"X-NOPE-Key": "agent"},
        json={
            "rule_yaml": rule_yaml,
            "bad_examples": [{"name": "bad.ts", "content": "db.raw('SELECT ' + id);"}],
            "good_examples": [{"name": "good.ts", "content": "db.query('SELECT ?', [id]);"}],
            "original": {"name": "original.ts", "content": "db.raw('SELECT ' + id);"},
            "corrected": {"name": "corrected.ts", "content": "db.query('SELECT ?', [id]);"},
        },
    )
    assert val_resp.status_code == 200
    assert val_resp.json()["passed"] is True

    challenge = client.post(f"/v1/scars/{scar_id}/adversarial", headers={"X-NOPE-Key": "admin"}, json={
        "generated_by": "independent-test-agent",
        "bad_examples": [{"name": f"variant-{i}.ts", "content": f"db.raw('SELECT {i}' + account);"} for i in range(6)],
        "good_examples": [{"name": f"safe-{i}.ts", "content": f"db.query('SELECT {i} WHERE id = ?', [account]);"} for i in range(4)],
    })
    assert challenge.status_code == 200, challenge.text
    assert challenge.json()["passed"] is True

    requested = client.post(f"/v1/scars/{scar_id}/approval-request", headers={"X-NOPE-Key": "agent"},
                            json={"revision_id": val_resp.json()["revision_id"]})
    assert requested.status_code == 200, requested.text
    appr_resp = client.post(
        f"/v1/scars/{scar_id}/approve",
        headers={"X-NOPE-Key": "approver"},
        json={**requested.json(), "approver": "alice@acme.com", "reason": "Verified in test lab"},
    )
    assert appr_resp.status_code == 200
    assert appr_resp.json()["status"] == ScarStatus.APPROVED.value
    return cast(dict[str, Any], scar_data)


def test_webhook_pr_merge_activates_approved_scar() -> None:
    with TestClient(app) as client:
        scar = _create_approved_scar(client)
        scar_number = scar["number"]

        pr_payload = {
            "action": "closed",
            "pull_request": {
                "number": 42,
                "html_url": "https://github.com/acme/payments/pull/42",
                "merged": True,
                "merge_commit_sha": "d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5",
                "merged_by": {"login": "dev-lead"},
                "head": {"ref": f"nope/scar-{scar_number}"},
                "title": f"NOPE rule for Scar #{scar_number}",
                "body": f"Enforces policy for SCAR-{scar_number:03d}",
            },
        }

        resp = client.post(
            "/v1/webhooks/github",
            headers={"X-GitHub-Event": "pull_request"},
            json=pr_payload,
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "activated"
        assert data["scar_number"] == scar_number
        assert data["commit_sha"] == "d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5"
        assert data["merged_by"] == "dev-lead"

        # Verify scar is now ACTIVE in database
        scar_resp = client.get(f"/v1/scars/{scar['id']}", headers={"X-NOPE-Key": "agent"})
        assert scar_resp.status_code == 200
        assert scar_resp.json()["status"] == ScarStatus.ACTIVE.value
        assert scar_resp.json()["active"] is True

        # Verify audit log recorded scar.activated_via_merge
        with SessionLocal() as db:
            event = db.scalar(
                select(AuditEvent)
                .where(AuditEvent.scar_id == scar["id"], AuditEvent.action == "scar.activated_via_merge")
            )
            assert event is not None
            assert event.actor == "github:dev-lead"
            detail = json.loads(event.detail)
            assert detail["merge_commit_sha"] == "d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5"
            assert detail["pr_number"] == 42


def test_webhook_pr_merge_warns_on_unapproved_scar() -> None:
    with TestClient(app) as client:
        # Create scar, but DO NOT approve it (remains PROPOSED)
        scar_payload = {
            "title": "Unapproved rule test",
            "incident_summary": "Test incident",
            "invariant": "Must be approved before activation",
            "rationale": "Guard against unreviewed PR merges",
            "remediation": "Get formal sign-off",
            "repository": "acme/payments",
            "scope": "src/",
            "severity": "medium",
            "enforcement": "semgrep",
            "origin": "INC-099",
            "proposed_by": "untrusted",
        }
        resp = client.post("/v1/scars", headers={"X-NOPE-Key": "agent"}, json=scar_payload)
        assert resp.status_code == 201
        scar_number = resp.json()["number"]
        scar_id = resp.json()["id"]

        pr_payload = {
            "action": "closed",
            "pull_request": {
                "number": 99,
                "merged": True,
                "merge_commit_sha": "1111222233334444555566667777888899990000",
                "merged_by": {"login": "rogue-dev"},
                "head": {"ref": f"nope/scar-{scar_number}"},
            },
        }

        webhook_resp = client.post(
            "/v1/webhooks/github",
            headers={"X-GitHub-Event": "pull_request"},
            json=pr_payload,
        )
        assert webhook_resp.status_code == 200
        data = webhook_resp.json()
        assert data["status"] == "ignored"
        assert "must be 'approved' before activation via merge" in data["reason"]

        # Verify scar is NOT active in database
        scar_check = client.get(f"/v1/scars/{scar_id}", headers={"X-NOPE-Key": "agent"})
        assert scar_check.json()["status"] == ScarStatus.PROPOSED.value
        assert scar_check.json()["active"] is False

        # Verify warning audit event recorded
        with SessionLocal() as db:
            warning_evt = db.scalar(
                select(AuditEvent)
                .where(AuditEvent.scar_id == scar_id, AuditEvent.action == "scar.merge_unapproved_warning")
            )
            assert warning_evt is not None
            assert warning_evt.actor == "github:rogue-dev"


def test_webhook_pr_metadata_extraction_variants() -> None:
    with TestClient(app) as client:
        scar = _create_approved_scar(client)
        scar_number = scar["number"]

        # 1. Extraction from Title when head ref is generic
        pr_payload_title = {
            "action": "closed",
            "pull_request": {
                "number": 101,
                "merged": True,
                "merge_commit_sha": "aaaabbbbccccddddeeeeffff0000111122223333",
                "merged_by": {"login": "merger1"},
                "head": {"ref": "patch-1"},
                "title": f"Feat: Enforce [SCAR-{scar_number:03d}] guardrails",
                "body": "No reference in body",
            },
        }
        resp = client.post(
            "/v1/webhooks/github",
            headers={"X-GitHub-Event": "pull_request"},
            json=pr_payload_title,
        )
        assert resp.status_code == 200
        assert resp.json()["status"] == "activated"

        # 2. Re-triggering on already active scar returns already_active
        resp2 = client.post(
            "/v1/webhooks/github",
            headers={"X-GitHub-Event": "pull_request"},
            json=pr_payload_title,
        )
        assert resp2.status_code == 200
        assert resp2.json()["status"] == "already_active"


def test_active_rules_yaml_endpoint() -> None:
    with TestClient(app) as client:
        # Empty ledger returns empty rules YAML
        empty_resp = client.get("/v1/rules/active.yml", headers={"X-NOPE-Key": "ci"})
        assert empty_resp.status_code == 200
        assert "application/x-yaml" in empty_resp.headers["content-type"]
        empty_doc = yaml.safe_load(empty_resp.text)
        assert empty_doc == {"rules": []}

        # Create, validate, and activate a scar via break-glass admin route
        scar = _create_approved_scar(client)
        act_resp = client.post(
            f"/v1/scars/{scar['id']}/activate",
            headers={"X-NOPE-Key": "admin"},
            json={"authorized_by": "sec-admin", "reason": "Authorized break-glass activation for test setup"},
        )
        assert act_resp.status_code == 200

        # Now GET /v1/rules/active.yml returns the rule
        rules_resp = client.get("/v1/rules/active.yml", headers={"X-NOPE-Key": "ci"})
        assert rules_resp.status_code == 200
        assert "application/x-yaml" in rules_resp.headers["content-type"]

        doc = yaml.safe_load(rules_resp.text)
        assert "rules" in doc
        assert len(doc["rules"]) == 1
        rule = doc["rules"][0]
        assert rule["id"] == "acme.payments.no-raw-sql"
        assert rule["metadata"]["scar"] == f"SCAR-{scar['number']:03d}"


def test_cli_rule_sync_and_verify_roundtrip(tmp_path: Path) -> None:
    # Set up in-process database state with an active rule
    with TestClient(app) as client:
        scar = _create_approved_scar(client)
        client.post(
            f"/v1/scars/{scar['id']}/activate",
            headers={"X-NOPE-Key": "admin"},
            json={"authorized_by": "sec-admin", "reason": "Authorized break-glass activation for CLI sync test"},
        )

        with SessionLocal() as db:
            active_scars = list(db.scalars(select(Scar).where(Scar.active.is_(True))).all())
            assert len(active_scars) == 1
            rule_ver = db.scalar(select(RuleVersion).where(RuleVersion.scar_id == active_scars[0].id))
            assert rule_ver is not None

    # Point CLI functions to test server using mock client
    rule_file = tmp_path / "nope-active.yml"

    # Verify matching contents passes verification
    class MockResponse:
        def __init__(self, text: str) -> None:
            self.text = text

        def raise_for_status(self) -> None:
            pass

    import httpx

    class MockHttpClient:
        def __init__(self, *args: Any, **kwargs: Any) -> None:
            pass

        def __enter__(self) -> MockHttpClient:
            return self

        def __exit__(self, *args: Any) -> None:
            pass

        def get(self, url: str, headers: dict[str, str]) -> MockResponse:
            with TestClient(app) as c:
                r = c.get(url, headers=headers)
                return MockResponse(r.text)

    monkeypatch_client = pytest.MonkeyPatch()
    monkeypatch_client.setattr(httpx, "Client", MockHttpClient)
    try:
        # 1. Test sync_rules_to_file via mock client
        assert sync_rules_to_file(rule_file, base_url="http://testserver", key="ci") == 0
        assert rule_file.is_file()
        saved_doc = yaml.safe_load(rule_file.read_text(encoding="utf-8"))
        assert len(saved_doc["rules"]) == 1

        # 2. Test verify_rules_sync with identical content -> 0
        assert verify_rules_sync(rule_file, base_url="http://testserver", key="ci") == 0

        # 3. Tamper with rule_file (drift) -> verify returns 1
        drifted_content = yaml.safe_dump({"rules": [{"id": "unrelated.fake.rule"}]})
        rule_file.write_text(drifted_content, encoding="utf-8")
        assert verify_rules_sync(rule_file, base_url="http://testserver", key="ci") == 1

        # 4. Non-existent rule_file -> verify returns 1
        non_existent = tmp_path / "does-not-exist.yml"
        assert verify_rules_sync(non_existent, base_url="http://testserver", key="ci") == 1
    finally:
        monkeypatch_client.undo()


def test_webhook_delivery_idempotency() -> None:
    with TestClient(app) as client:
        scar = _create_approved_scar(client)
        delivery_id = "77d2429a-d8cb-4f35-8664-d4b3df36c572"
        pr_payload = {
            "action": "closed",
            "pull_request": {
                "number": 105,
                "merged": True,
                "merge_commit_sha": "eeeeffff11112222333344445555666677778888",
                "merged_by": {"login": "ci-bot"},
                "head": {"ref": f"nope/scar-{scar['number']}"},
            },
        }
        resp1 = client.post(
            "/v1/webhooks/github",
            headers={"X-GitHub-Event": "pull_request", "X-GitHub-Delivery": delivery_id},
            json=pr_payload,
        )
        assert resp1.status_code == 200
        assert resp1.json()["status"] == "activated"

        resp2 = client.post(
            "/v1/webhooks/github",
            headers={"X-GitHub-Event": "pull_request", "X-GitHub-Delivery": delivery_id},
            json=pr_payload,
        )
        assert resp2.status_code == 200
        assert resp2.json()["status"] == "already_processed"
        assert resp2.json()["delivery_id"] == delivery_id


def test_webhook_payload_size_limit() -> None:
    with TestClient(app) as client:
        huge_payload = "a" * (1_048_576 + 10)
        resp = client.post(
            "/v1/webhooks/github",
            headers={"X-GitHub-Event": "pull_request"},
            content=huge_payload.encode("utf-8"),
        )
        assert resp.status_code == 413
        assert "Webhook payload exceeds 1MB limit" in resp.json()["detail"]


def test_webhook_target_branch_filtering() -> None:
    with TestClient(app) as client:
        scar = _create_approved_scar(client)
        pr_payload = {
            "action": "closed",
            "pull_request": {
                "number": 106,
                "merged": True,
                "merge_commit_sha": "3333444455556666777788889999000011112222",
                "merged_by": {"login": "dev1"},
                "head": {"ref": f"nope/scar-{scar['number']}"},
                "base": {"ref": "feature-branch"},
            },
        }
        resp = client.post(
            "/v1/webhooks/github",
            headers={"X-GitHub-Event": "pull_request"},
            json=pr_payload,
        )
        assert resp.status_code == 200
        assert resp.json()["status"] == "ignored"
        assert "does not match expected base branch" in resp.json()["reason"]

        scar_check = client.get(f"/v1/scars/{scar['id']}", headers={"X-NOPE-Key": "agent"})
        assert scar_check.json()["status"] == ScarStatus.APPROVED.value
        assert scar_check.json()["active"] is False
