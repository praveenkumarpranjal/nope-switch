from __future__ import annotations

import json
import os

import pytest
from fastapi.testclient import TestClient
from nope_core.auth import AuthIdentity, Role, issue_token, parse_api_keys, verify_token
from nope_core.db import AuditEvent, SessionLocal
from nope_core.main import app
from sqlalchemy import select


def test_api_keys_are_explicit_and_role_checked() -> None:
    assert os.environ["NOPE_API_KEYS"] == "admin:admin,approver:approver,agent:agent,ci:ci"
    assert parse_api_keys()["approver"] == Role.APPROVER
    assert parse_api_keys()["agent"] < Role.APPROVER


def test_per_user_api_key_parsing(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("NOPE_API_KEYS", "user-secret-1:approver:alice@acme.com:corp-a,sec-key:admin:admin@acme.com")
    keys = parse_api_keys()
    alice = keys["user-secret-1"]
    assert isinstance(alice, AuthIdentity)
    assert alice.subject == "alice@acme.com"
    assert alice.role == Role.APPROVER
    assert alice.organization == "corp-a"
    assert alice.is_user_identity is True
    assert alice.auth_type == "api_key"

    admin_user = keys["sec-key"]
    assert admin_user.subject == "admin@acme.com"
    assert admin_user.role == Role.ADMIN
    assert admin_user.organization == "default"


def test_token_issuance_verification_and_tamper_detection() -> None:
    token = issue_token("alice@acme.com", Role.APPROVER, expires_in_seconds=3600, organization="payments-team")
    assert isinstance(token, str)
    assert len(token.split(".")) == 3

    identity = verify_token(token)
    assert identity.subject == "alice@acme.com"
    assert identity.role == Role.APPROVER
    assert identity.organization == "payments-team"
    assert identity.is_user_identity is True

    # Tampered signature must fail
    header, payload, sig = token.split(".")
    tampered = f"{header}.{payload}.{sig[:-4]}fake"
    with pytest.raises(ValueError, match="Invalid token signature"):
        verify_token(tampered)

    # Expired token must fail
    expired_token = issue_token("bob@acme.com", Role.AGENT, expires_in_seconds=-10)
    with pytest.raises(ValueError, match="Token has expired"):
        verify_token(expired_token)


def test_bearer_token_authorization_and_introspection() -> None:
    agent_token = issue_token("agent-runner-01", Role.AGENT)
    admin_token = issue_token("secops-lead", Role.ADMIN)

    with TestClient(app) as client:
        # Introspect with Bearer token
        me = client.get("/v1/auth/me", headers={"Authorization": f"Bearer {agent_token}"})
        assert me.status_code == 200
        data = me.json()
        assert data["subject"] == "agent-runner-01"
        assert data["role"] == "agent"
        assert data["auth_type"] == "bearer_token"

        # Agent token cannot access admin endpoints
        denied = client.post(
            "/v1/auth/tokens",
            headers={"Authorization": f"Bearer {agent_token}"},
            json={"subject": "bob", "role": "approver"},
        )
        assert denied.status_code == 403

        # Admin token can issue new tokens
        created = client.post(
            "/v1/auth/tokens",
            headers={"Authorization": f"Bearer {admin_token}"},
            json={"subject": "carol@acme.com", "role": "approver", "organization": "security"},
        )
        assert created.status_code == 201
        res = created.json()
        assert res["token_type"] == "Bearer"
        assert res["subject"] == "carol@acme.com"
        assert res["role"] == "approver"
        assert res["organization"] == "security"

        # Verify issued token works
        carol_token = res["token"]
        carol_me = client.get("/v1/auth/me", headers={"Authorization": f"Bearer {carol_token}"})
        assert carol_me.status_code == 200
        assert carol_me.json()["subject"] == "carol@acme.com"


def test_anti_impersonation_in_approvals() -> None:
    alice_token = issue_token("alice@acme.com", Role.APPROVER)
    agent_token = issue_token("scanner-agent", Role.AGENT)

    with TestClient(app) as client:
        # Create a scar
        scar_resp = client.post(
            "/v1/scars",
            headers={"Authorization": f"Bearer {agent_token}"},
            json={
                "title": "Anti-impersonation security verification policy",
                "incident_summary": "Testing cryptographic actor attribution on approval",
                "invariant": "Approver identity must match token subject strictly",
                "rationale": "Prevents approval fraud and compliance audit failures",
                "remediation": "Do not forge approver identity",
                "repository": "acme/auth",
                "scope": "src/",
                "severity": "high",
                "enforcement": "semgrep",
                "origin": "INC-AUTH-1",
                "proposed_by": "scanner-agent",
            },
        )
        assert scar_resp.status_code == 201
        scar_id = scar_resp.json()["id"]

        # Validate the scar
        rule_yaml = """rules:
  - id: acme.auth.no-impersonation
    message: Anti-impersonation
    severity: ERROR
    languages: [typescript]
    pattern: forgeIdentity($X)
"""
        val_resp = client.post(
            f"/v1/scars/{scar_id}/validate?sync=true",
            headers={"Authorization": f"Bearer {agent_token}"},
            json={
                "rule_yaml": rule_yaml,
                "bad_examples": [{"name": "bad.ts", "content": "forgeIdentity(1);"}],
                "good_examples": [{"name": "good.ts", "content": "verifyIdentity(1);"}],
                "original": {"name": "orig.ts", "content": "forgeIdentity(1);"},
                "corrected": {"name": "corr.ts", "content": "verifyIdentity(1);"},
            },
        )
        assert val_resp.status_code == 200
        assert val_resp.json()["passed"] is True

        # Challenge the scar with a different agent
        challenge_token = issue_token("challenger-agent", Role.AGENT)
        chal_resp = client.post(
            f"/v1/scars/{scar_id}/adversarial",
            headers={"Authorization": f"Bearer {challenge_token}"},
            json={
                "generated_by": "challenger-agent",
                "bad_examples": [{"name": f"bad-{i}.ts", "content": f"const x = {i}; forgeIdentity(x);"} for i in range(6)],
                "good_examples": [{"name": f"good-{i}.ts", "content": f"const x = {i}; verifyIdentity(x);"} for i in range(4)],
            },
        )
        assert chal_resp.status_code == 200

        # Attempt to approve as bob@acme.com using Alice's token -> MUST BE REJECTED 403
        impersonation = client.post(
            f"/v1/scars/{scar_id}/approve",
            headers={"Authorization": f"Bearer {alice_token}"},
            json={"approver": "bob@acme.com", "reason": "Attempting to forge Bob's identity"},
        )
        assert impersonation.status_code == 403
        assert "Identity impersonation forbidden" in impersonation.json()["detail"]

        # Approve matching Alice's identity -> SUCCESS
        approved = client.post(
            f"/v1/scars/{scar_id}/approve",
            headers={"Authorization": f"Bearer {alice_token}"},
            json={"approver": "alice@acme.com", "reason": "Legitimate approval by verified Alice"},
        )
        assert approved.status_code == 200
        assert approved.json()["status"] == "approved"

        # Verify Audit Log recorded Alice's verified identity
        with SessionLocal() as db:
            audit = db.scalar(
                select(AuditEvent).where(AuditEvent.scar_id == scar_id, AuditEvent.action == "scar.approved")
            )
            assert audit is not None
            detail = json.loads(audit.detail)
            assert detail["approver"] == "alice@acme.com"
