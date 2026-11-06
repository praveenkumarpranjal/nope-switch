from __future__ import annotations

import concurrent.futures
from typing import Any, cast

from fastapi.testclient import TestClient
from nope_core.db import Base, engine
from nope_core.main import app


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
