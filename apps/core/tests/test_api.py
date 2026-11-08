from __future__ import annotations

import concurrent.futures
import json
from typing import Any, cast

import pytest
from fastapi.testclient import TestClient
from nope_core.db import AuditEvent, Base, ScarCounter, SessionLocal, engine
from nope_core.main import app
from sqlalchemy import delete, select


@pytest.mark.parametrize("identifier", ["²", "9" * 5000])
def test_unrepresentable_scar_number_returns_not_found(identifier: str) -> None:
    with TestClient(app) as client:
        response = client.get(f"/v1/scars/{identifier}", headers={"X-NOPE-Key": "agent"})
    assert response.status_code == 404


def reset_schema() -> None:
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)


def test_health_is_public_and_ledger_is_protected() -> None:
    reset_schema()
    with TestClient(app) as client:
        health = client.get("/health")
        assert health.status_code == 200
        assert health.json()["status"] == "ok"
        denied = client.get("/v1/scars")
        assert denied.status_code == 401
        listed = client.get("/v1/scars", headers={"X-NOPE-Key": "agent"})
        assert listed.status_code == 200


def test_create_then_show_scar() -> None:
    reset_schema()
    payload = {
        "title": "Never expose credentials in logs",
        "incident_summary": "Authorization headers reached monitoring through the application logger",
        "invariant": "Credential material must never reach application logs",
        "rationale": "Application logs are widely copied and retained",
        "remediation": "Log an actor correlation ID instead",
        "repository": "acme/payments",
        "scope": "src/",
        "severity": "critical",
        "enforcement": "semgrep",
        "origin": "INC-014",
        "proposed_by": "test",
    }
    with TestClient(app) as client:
        created = client.post("/v1/scars", headers={"X-NOPE-Key": "agent"}, json=payload)
        assert created.status_code == 201
        scar_id = created.json()["id"]
        listed = client.get(f"/v1/scars/{scar_id}", headers={"X-NOPE-Key": "agent"})
        assert listed.status_code == 200
        assert listed.json()["origin"] == "INC-014"


def test_concurrent_create_scar_assigns_unique_contiguous_numbers() -> None:
    def post_scar(idx: int) -> dict[str, Any]:
        payload = {
            "title": f"Concurrent Scar Policy Rule #{idx}",
            "incident_summary": f"Incident summary for concurrency test #{idx}",
            "invariant": f"Invariant rule requirement #{idx}",
            "rationale": f"Rationale for concurrency test #{idx}",
            "remediation": f"Remediation steps for policy #{idx}",
            "repository": "acme/payments",
            "scope": "src/",
            "severity": "high",
            "enforcement": "semgrep",
            "origin": f"INC-TEST-{idx:03d}",
            "proposed_by": f"thread-{idx}",
        }
        with TestClient(app) as client:
            resp = client.post("/v1/scars", headers={"X-NOPE-Key": "agent"}, json=payload)
            assert resp.status_code == 201
            return cast(dict[str, Any], resp.json())

    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
        results = list(executor.map(post_scar, range(1, 11)))

    numbers = [int(r["number"]) for r in results]
    assert len(numbers) == 10
    assert len(set(numbers)) == 10
    assert sorted(numbers) == list(range(1, 11))


def test_break_glass_activation_requires_admin_and_audits() -> None:
    reset_schema()
    payload = {
        "title": "Break glass security policy",
        "incident_summary": "Urgent zero-day response requiring immediate policy enforcement",
        "invariant": "All unsafe calls must be blocked instantly",
        "rationale": "High severity threat actively exploited in wild",
        "remediation": "Do not invoke vulnerable API",
        "repository": "acme/payments",
        "scope": "src/",
        "severity": "critical",
        "enforcement": "semgrep",
        "origin": "INC-ZERO-DAY",
        "proposed_by": "sec-ops",
    }
    with TestClient(app) as client:
        created = client.post("/v1/scars", headers={"X-NOPE-Key": "agent"}, json=payload)
        assert created.status_code == 201
        scar_id = created.json()["id"]

        # Validate scar
        val_resp = client.post(
            f"/v1/scars/{scar_id}/validate",
            headers={"X-NOPE-Key": "agent"},
            json={
                "rule_yaml": "rules:\n  - id: zero.day\n    message: blocked\n    severity: ERROR\n    languages: [typescript]\n    pattern: bad()",
                "bad_examples": [{"name": "bad.ts", "content": "bad();"}],
                "good_examples": [{"name": "good.ts", "content": "ok();"}],
                "original": {"name": "original.ts", "content": "bad();"},
                "corrected": {"name": "corrected.ts", "content": "ok();"},
            },
        )
        assert val_resp.status_code == 200

        independent = client.post(f"/v1/scars/{scar_id}/adversarial", headers={"X-NOPE-Key": "admin"}, json={
            "generated_by": "independent-test-agent",
            "bad_examples": [{"name": f"variant-{i}.ts", "content": f"const variant = {i}; bad();"} for i in range(6)],
            "good_examples": [{"name": f"safe-{i}.ts", "content": f"const variant = {i}; ok();"} for i in range(4)],
        })
        assert independent.status_code == 200, independent.text
        assert independent.json()["passed"] is True

        # Approve scar
        requested = client.post(f"/v1/scars/{scar_id}/approval-request", headers={"X-NOPE-Key": "agent"},
                                json={"revision_id": val_resp.json()["revision_id"]})
        assert requested.status_code == 200, requested.text
        appr_resp = client.post(
            f"/v1/scars/{scar_id}/approve",
            headers={"X-NOPE-Key": "approver"},
            json={**requested.json(), "approver": "lead@acme.com", "reason": "Immediate zero-day approval"},
        )
        assert appr_resp.status_code == 200

        # 1. Non-admin key (approver or agent) is rejected with 403 Forbidden
        denied = client.post(
            f"/v1/scars/{scar_id}/activate",
            headers={"X-NOPE-Key": "approver"},
            json={"authorized_by": "lead@acme.com", "reason": "Attempt without admin role"},
        )
        assert denied.status_code == 403

        # 2. Admin key without valid reason is rejected with 422
        bad_req = client.post(
            f"/v1/scars/{scar_id}/activate",
            headers={"X-NOPE-Key": "admin"},
            json={"authorized_by": "sec-admin", "reason": "too short"},
        )
        assert bad_req.status_code == 422

        # 3. Admin key with valid payload succeeds and records break-glass audit
        success = client.post(
            f"/v1/scars/{scar_id}/activate",
            headers={"X-NOPE-Key": "admin"},
            json={
                "authorized_by": "sec-admin",
                "reason": "Emergency production hotfix bypassing GitOps PR merge",
            },
        )
        assert success.status_code == 200
        assert success.json()["active"] is True

        with SessionLocal() as db:
            event = db.scalar(
                select(AuditEvent).where(
                    AuditEvent.scar_id == scar_id, AuditEvent.action == "scar.activated_break_glass"
                )
            )
            assert event is not None
            detail = json.loads(event.detail)
            assert detail["authorized_by"] == "sec-admin"
            assert "BREAK-GLASS MANUAL ACTIVATION" in detail["warning"]


def test_counter_fallback_initialization_under_unseeded_database() -> None:
    reset_schema()
    # Explicitly clear scar_counters table so counter row is unseeded
    with SessionLocal() as db:
        db.execute(delete(ScarCounter))
        db.commit()

    def post_scar(idx: int) -> dict[str, Any]:
        payload = {
            "title": f"Unseeded DB Scar Policy #{idx}",
            "incident_summary": f"Incident summary for concurrency test #{idx}",
            "invariant": f"Invariant rule requirement #{idx}",
            "rationale": f"Rationale for concurrency test #{idx}",
            "remediation": f"Remediation steps for policy #{idx}",
            "repository": "acme/payments",
            "scope": "src/",
            "severity": "high",
            "enforcement": "semgrep",
            "origin": f"INC-UNSEEDED-{idx:03d}",
            "proposed_by": f"thread-{idx}",
        }
        with TestClient(app) as client:
            resp = client.post("/v1/scars", headers={"X-NOPE-Key": "agent"}, json=payload)
            assert resp.status_code == 201
            return cast(dict[str, Any], resp.json())

    # Launch concurrent threads against an unseeded database
    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
        results = list(executor.map(post_scar, range(1, 6)))

    numbers = [int(r["number"]) for r in results]
    assert len(numbers) == 5
    assert len(set(numbers)) == 5
    assert sorted(numbers) == list(range(1, 6))
