from __future__ import annotations

from typing import Any

import yaml
from fastapi.testclient import TestClient
from nope_core.auth import Role, issue_token
from nope_core.db import Base, engine
from nope_core.main import app


def reset_schema() -> None:
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)


def _make_scar_payload(repo: str, title: str, author: str = "agent-author") -> dict[str, Any]:
    return {
        "title": title,
        "incident_summary": f"Incident summary for {title} with sufficient length",
        "invariant": f"Invariant policy for {title}",
        "rationale": f"Rationale explanation for {title}",
        "remediation": f"Remediation steps for {title}",
        "repository": repo,
        "scope": "src/",
        "severity": "high",
        "enforcement": "semgrep",
        "origin": "INC-TENANT-001",
        "proposed_by": author,
    }


def _make_rule_payload(rule_id: str) -> dict[str, Any]:
    rule_yaml = f"""rules:
  - id: {rule_id}
    message: Security violation detected
    severity: ERROR
    languages: [typescript]
    pattern: dangerousCall($X)
"""
    return {
        "rule_yaml": rule_yaml,
        "bad_examples": [{"name": f"bad-{i}.ts", "content": f"const x = {i}; dangerousCall(x);"} for i in range(6)],
        "good_examples": [{"name": f"good-{i}.ts", "content": f"const x = {i}; safeCall(x);"} for i in range(4)],
        "original": {"name": "orig.ts", "content": "dangerousCall(1);"},
        "corrected": {"name": "corr.ts", "content": "safeCall(1);"},
    }


def test_independent_scar_numbering_across_tenants_and_repos() -> None:
    reset_schema()
    token_alpha = issue_token("agent-alpha", Role.AGENT, organization="tenant-alpha")
    token_beta = issue_token("agent-beta", Role.AGENT, organization="tenant-beta")

    with TestClient(app) as client:
        # Create first scar in tenant-alpha
        res1 = client.post(
            "/v1/scars",
            headers={"Authorization": f"Bearer {token_alpha}"},
            json=_make_scar_payload("alpha-corp/backend", "Alpha first rule for backend", author="agent-alpha"),
        )
        assert res1.status_code == 201
        scar_alpha_1 = res1.json()
        assert scar_alpha_1["number"] == 1
        assert scar_alpha_1["organization_id"] == "tenant-alpha"

        # Create second scar in tenant-alpha
        res2 = client.post(
            "/v1/scars",
            headers={"Authorization": f"Bearer {token_alpha}"},
            json=_make_scar_payload("alpha-corp/backend", "Alpha second rule for backend", author="agent-alpha"),
        )
        assert res2.status_code == 201
        scar_alpha_2 = res2.json()
        assert scar_alpha_2["number"] == 2
        assert scar_alpha_2["organization_id"] == "tenant-alpha"

        # Create first scar in tenant-beta (should start at 1 independently!)
        res3 = client.post(
            "/v1/scars",
            headers={"Authorization": f"Bearer {token_beta}"},
            json=_make_scar_payload("beta-corp/payments", "Beta first rule for payments", author="agent-beta"),
        )
        assert res3.status_code == 201
        scar_beta_1 = res3.json()
        assert scar_beta_1["number"] == 1
        assert scar_beta_1["organization_id"] == "tenant-beta"

        # Create second scar in tenant-beta
        res4 = client.post(
            "/v1/scars",
            headers={"Authorization": f"Bearer {token_beta}"},
            json=_make_scar_payload("beta-corp/payments", "Beta second rule for payments", author="agent-beta"),
        )
        assert res4.status_code == 201
        scar_beta_2 = res4.json()
        assert scar_beta_2["number"] == 2
        assert scar_beta_2["organization_id"] == "tenant-beta"


def test_cross_tenant_isolation_reads_and_mutations() -> None:
    reset_schema()
    agent_alpha = issue_token("agent-alpha", Role.AGENT, organization="tenant-alpha")
    agent_beta = issue_token("agent-beta", Role.AGENT, organization="tenant-beta")
    approver_beta = issue_token("approver-beta@beta.com", Role.APPROVER, organization="tenant-beta")

    with TestClient(app) as client:
        # Create scar in tenant-alpha
        create_resp = client.post(
            "/v1/scars",
            headers={"Authorization": f"Bearer {agent_alpha}"},
            json=_make_scar_payload("alpha/repo", "Alpha sensitive scar", author="agent-alpha"),
        )
        assert create_resp.status_code == 201
        alpha_scar_id = create_resp.json()["id"]

        # Tenant-beta queries alpha scar by ID -> must receive 404
        read_by_id = client.get(
            f"/v1/scars/{alpha_scar_id}",
            headers={"Authorization": f"Bearer {agent_beta}"},
        )
        assert read_by_id.status_code == 404
        assert read_by_id.json()["detail"] == "Scar not found"

        # Tenant-beta queries scar by number 1 -> returns 404 (doesn't exist in tenant-beta)
        read_by_num = client.get(
            "/v1/scars/1",
            headers={"Authorization": f"Bearer {agent_beta}"},
        )
        assert read_by_num.status_code == 404

        # Tenant-beta cannot validate alpha's scar -> 404
        val_resp = client.post(
            f"/v1/scars/{alpha_scar_id}/validate?sync=true",
            headers={"Authorization": f"Bearer {agent_beta}"},
            json=_make_rule_payload("beta.spoof"),
        )
        assert val_resp.status_code == 404

        # Tenant-beta approver cannot approve alpha's scar -> 404
        approve_resp = client.post(
            f"/v1/scars/{alpha_scar_id}/approve",
            headers={"Authorization": f"Bearer {approver_beta}"},
            json={
                "request_id": "app_req_dummy",
                "revision_id": "rev_dummy",
                "evidence_sha256": "0" * 64,
                "repository": "alpha/repo",
                "scope": "src/",
                "approver": "approver-beta@beta.com",
                "reason": "Attempting cross tenant approval",
            },
        )
        assert approve_resp.status_code == 404

        # Listing scars: tenant-alpha sees 1, tenant-beta sees 0
        list_alpha = client.get("/v1/scars", headers={"Authorization": f"Bearer {agent_alpha}"})
        assert list_alpha.status_code == 200
        assert len(list_alpha.json()) == 1

        list_beta = client.get("/v1/scars", headers={"Authorization": f"Bearer {agent_beta}"})
        assert list_beta.status_code == 200
        assert len(list_beta.json()) == 0


def test_cross_tenant_creation_denied() -> None:
    reset_schema()
    agent_alpha = issue_token("agent-alpha", Role.AGENT, organization="tenant-alpha")

    with TestClient(app) as client:
        # Agent in tenant-alpha attempts to create a scar claiming organization_id="tenant-beta"
        payload = _make_scar_payload("beta/repo", "Attempting cross-tenant creation", author="agent-alpha")
        payload["organization_id"] = "tenant-beta"

        res = client.post(
            "/v1/scars",
            headers={"Authorization": f"Bearer {agent_alpha}"},
            json=payload,
        )
        assert res.status_code == 403
        assert "Identity forbidden" in res.json()["detail"]


def test_active_rules_export_isolated_by_tenant() -> None:
    reset_schema()
    admin_alpha = issue_token("admin-alpha", Role.ADMIN, organization="tenant-alpha")
    adv_alpha_token = issue_token("adv-alpha", Role.AGENT, organization="tenant-alpha")
    admin_beta = issue_token("admin-beta", Role.ADMIN, organization="tenant-beta")
    adv_beta_token = issue_token("adv-beta", Role.AGENT, organization="tenant-beta")
    ci_alpha = issue_token("ci-alpha", Role.CI, organization="tenant-alpha")
    ci_beta = issue_token("ci-beta", Role.CI, organization="tenant-beta")

    with TestClient(app) as client:
        # 1. Setup tenant-alpha active scar
        res_a = client.post(
            "/v1/scars",
            headers={"Authorization": f"Bearer {admin_alpha}"},
            json=_make_scar_payload("alpha/repo", "Alpha active rule enforcement", author="admin-alpha"),
        )
        scar_a_id = res_a.json()["id"]
        val_a = client.post(
            f"/v1/scars/{scar_a_id}/validate?sync=true",
            headers={"Authorization": f"Bearer {admin_alpha}"},
            json=_make_rule_payload("alpha.active.rule"),
        )
        assert val_a.status_code == 200
        adv_a = client.post(
            f"/v1/scars/{scar_a_id}/adversarial",
            headers={"Authorization": f"Bearer {adv_alpha_token}"},
            json={
                "generated_by": "adv-alpha",
                "bad_examples": [{"name": f"adv-bad-{i}.ts", "content": f"function testA{i}() {{ dangerousCall('adv_{i}'); }}"} for i in range(6)],
                "good_examples": [{"name": f"adv-good-{i}.ts", "content": f"function testA{i}() {{ safeCall('adv_{i}'); }}"} for i in range(4)],
            },
        )
        assert adv_a.status_code == 200
        req_a = client.post(
            f"/v1/scars/{scar_a_id}/approval-request",
            headers={"Authorization": f"Bearer {admin_alpha}"},
            json={"revision_id": val_a.json()["revision_id"]},
        )
        assert req_a.status_code == 200
        ticket_a = req_a.json()
        app_a = client.post(
            f"/v1/scars/{scar_a_id}/approve",
            headers={"Authorization": f"Bearer {admin_alpha}"},
            json={**ticket_a, "approver": "admin-alpha", "reason": "Approving tenant alpha rule"},
        )
        assert app_a.status_code == 200
        act_a = client.post(
            f"/v1/scars/{scar_a_id}/activate",
            headers={"Authorization": f"Bearer {admin_alpha}"},
            json={"authorized_by": "admin-alpha", "reason": "Break-glass activation for alpha"},
        )
        assert act_a.status_code == 200

        # 2. Setup tenant-beta active scar
        res_b = client.post(
            "/v1/scars",
            headers={"Authorization": f"Bearer {admin_beta}"},
            json=_make_scar_payload("beta/repo", "Beta active rule enforcement", author="admin-beta"),
        )
        scar_b_id = res_b.json()["id"]
        val_b = client.post(
            f"/v1/scars/{scar_b_id}/validate?sync=true",
            headers={"Authorization": f"Bearer {admin_beta}"},
            json=_make_rule_payload("beta.active.rule"),
        )
        assert val_b.status_code == 200
        adv_b = client.post(
            f"/v1/scars/{scar_b_id}/adversarial",
            headers={"Authorization": f"Bearer {adv_beta_token}"},
            json={
                "generated_by": "adv-beta",
                "bad_examples": [{"name": f"adv-bad-{i}.ts", "content": f"function testB{i}() {{ dangerousCall('adv_{i}'); }}"} for i in range(6)],
                "good_examples": [{"name": f"adv-good-{i}.ts", "content": f"function testB{i}() {{ safeCall('adv_{i}'); }}"} for i in range(4)],
            },
        )
        assert adv_b.status_code == 200
        req_b = client.post(
            f"/v1/scars/{scar_b_id}/approval-request",
            headers={"Authorization": f"Bearer {admin_beta}"},
            json={"revision_id": val_b.json()["revision_id"]},
        )
        assert req_b.status_code == 200
        ticket_b = req_b.json()
        app_b = client.post(
            f"/v1/scars/{scar_b_id}/approve",
            headers={"Authorization": f"Bearer {admin_beta}"},
            json={**ticket_b, "approver": "admin-beta", "reason": "Approving tenant beta rule"},
        )
        assert app_b.status_code == 200
        act_b = client.post(
            f"/v1/scars/{scar_b_id}/activate",
            headers={"Authorization": f"Bearer {admin_beta}"},
            json={"authorized_by": "admin-beta", "reason": "Break-glass activation for beta"},
        )
        assert act_b.status_code == 200

        # 3. Export rules for tenant-alpha
        export_a = client.get("/v1/rules/active.yml", headers={"Authorization": f"Bearer {ci_alpha}"})
        assert export_a.status_code == 200
        doc_a = yaml.safe_load(export_a.text)
        rules_a = doc_a.get("rules", [])
        assert len(rules_a) == 1
        assert rules_a[0]["id"] == "alpha.active.rule"

        # 4. Export rules for tenant-beta
        export_b = client.get("/v1/rules/active.yml", headers={"Authorization": f"Bearer {ci_beta}"})
        assert export_b.status_code == 200
        doc_b = yaml.safe_load(export_b.text)
        rules_b = doc_b.get("rules", [])
        assert len(rules_b) == 1
        assert rules_b[0]["id"] == "beta.active.rule"


def test_validation_jobs_and_audit_isolation() -> None:
    reset_schema()
    agent_alpha = issue_token("agent-alpha", Role.AGENT, organization="tenant-alpha")
    agent_beta = issue_token("agent-beta", Role.AGENT, organization="tenant-beta")
    approver_alpha = issue_token("approver-alpha", Role.APPROVER, organization="tenant-alpha")
    approver_beta = issue_token("approver-beta", Role.APPROVER, organization="tenant-beta")

    with TestClient(app) as client:
        # Create scar and submit async validation in tenant-alpha
        res = client.post(
            "/v1/scars",
            headers={"Authorization": f"Bearer {agent_alpha}"},
            json=_make_scar_payload("alpha/repo", "Alpha async validation job", author="agent-alpha"),
        )
        scar_id = res.json()["id"]

        val_job_resp = client.post(
            f"/v1/scars/{scar_id}/validate",
            headers={"Authorization": f"Bearer {agent_alpha}"},
            json=_make_rule_payload("alpha.job.rule"),
        )
        assert val_job_resp.status_code == 202
        job_id = val_job_resp.json()["job_id"]

        # Tenant-alpha can query its validation job
        job_alpha = client.get(
            f"/v1/validations/{job_id}",
            headers={"Authorization": f"Bearer {agent_alpha}"},
        )
        assert job_alpha.status_code == 200
        assert job_alpha.json()["job_id"] == job_id

        # Tenant-beta CANNOT query tenant-alpha's validation job -> 404
        job_beta = client.get(
            f"/v1/validations/{job_id}",
            headers={"Authorization": f"Bearer {agent_beta}"},
        )
        assert job_beta.status_code == 404

        # Audit event isolation: approver_alpha sees the scar.proposed event
        audit_alpha = client.get("/v1/audit", headers={"Authorization": f"Bearer {approver_alpha}"})
        assert audit_alpha.status_code == 200
        assert len(audit_alpha.json()) >= 1
        assert all(e["organization_id"] == "tenant-alpha" for e in audit_alpha.json())

        # approver_beta sees 0 audit events
        audit_beta = client.get("/v1/audit", headers={"Authorization": f"Bearer {approver_beta}"})
        assert audit_beta.status_code == 200
        assert len(audit_beta.json()) == 0


def test_superadmin_cross_tenant_access() -> None:
    reset_schema()
    agent_alpha = issue_token("agent-alpha", Role.AGENT, organization="tenant-alpha")
    superadmin = issue_token("super-admin", Role.ADMIN, organization="*")

    with TestClient(app) as client:
        res = client.post(
            "/v1/scars",
            headers={"Authorization": f"Bearer {agent_alpha}"},
            json=_make_scar_payload("alpha/repo", "Superadmin test scar", author="agent-alpha"),
        )
        scar_id = res.json()["id"]

        # Superadmin with org="*" can view any tenant's scar
        scar_view = client.get(
            f"/v1/scars/{scar_id}",
            headers={"Authorization": f"Bearer {superadmin}"},
        )
        assert scar_view.status_code == 200
        assert scar_view.json()["id"] == scar_id

        # Superadmin can list scars across all tenants
        all_scars = client.get("/v1/scars", headers={"Authorization": f"Bearer {superadmin}"})
        assert all_scars.status_code == 200
        assert len(all_scars.json()) == 1
