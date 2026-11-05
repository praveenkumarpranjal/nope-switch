from __future__ import annotations

from fastapi.testclient import TestClient

from nope_core.db import Base, SessionLocal, engine
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
