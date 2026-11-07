from __future__ import annotations

from typing import Any

import pytest
import yaml
from fastapi.testclient import TestClient
from nope_core.main import app
from nope_core.rule_lab import CandidateResult, RuleLab

AGENT = {"X-NOPE-Key": "agent"}
ADVERSARY = {"X-NOPE-Key": "admin"}
APPROVER = {"X-NOPE-Key": "approver"}
RULE = """rules:
- id: prevent-danger
  message: Prevent the original dangerous operation
  severity: ERROR
  languages: [typescript]
  pattern: danger(...)
"""


@pytest.fixture
def client(monkeypatch: pytest.MonkeyPatch) -> Any:
    # Stub only the scanner boundary. Real Semgrep runs in check_assurance.py and test_gitops.
    def scan(
        self: RuleLab,
        rule: str,
        bad: list[tuple[str, str]],
        good: list[tuple[str, str]],
        *args: Any,
        **kwargs: Any,
    ) -> CandidateResult:
        token = "newDanger(" if "weak-rule" in rule else "danger("
        bad_hits = {name: int(token in code) for name, code in bad}
        good_hits = {name: int(token in code) for name, code in good}
        return CandidateResult(
            all(bad_hits.values()) and not any(good_hits.values()), bad_hits, good_hits, [], []
        )

    monkeypatch.setattr(RuleLab, "validate", scan)
    with TestClient(app) as c:
        yield c


def create(client: TestClient) -> str:
    response = client.post(
        "/v1/scars",
        headers=AGENT,
        json={
            "title": "Never repeat the dangerous operation",
            "incident_summary": "Original operation caused a production incident",
            "invariant": "Never call danger",
            "rationale": "Dangerous operations destroy incident evidence",
            "remediation": "Use the safe operation instead",
            "repository": "acme/service",
            "scope": "src/",
            "origin": "INC-123",
            "proposed_by": "rule-author",
        },
    )
    assert response.status_code == 201
    return str(response.json()["number"])


def validate(client: TestClient, scar: str, rule: str = RULE) -> dict[str, Any]:
    response = client.post(
        f"/v1/scars/{scar}/validate",
        headers=AGENT,
        json={
            "rule_yaml": rule,
            "original": {"name": "original.ts", "content": "danger(1);"},
            "corrected": {"name": "corrected.ts", "content": "safe(1);"},
            "bad_examples": [{"name": "author-bad.ts", "content": "danger(2);"}],
            "good_examples": [{"name": "author-good.ts", "content": "safe(2);"}],
        },
    )
    assert response.status_code == 200, response.text
    payload = response.json()
    assert isinstance(payload, dict)
    return payload


def bundle(bad_count: int = 6, good_count: int = 4) -> dict[str, Any]:
    return {
        "generated_by": "separate-agent",
        "bad_examples": [
            {"name": f"variant-{i}.ts", "content": f"danger({i + 10});"} for i in range(bad_count)
        ],
        "good_examples": [
            {"name": f"control-{i}.ts", "content": f"safe({i + 10});"} for i in range(good_count)
        ],
    }


def approve(client: TestClient, scar: str) -> Any:
    evidence = client.get(f"/v1/scars/{scar}/provenance", headers=AGENT).json()
    revisions = evidence["revisions"]
    requested = client.post(f"/v1/scars/{scar}/approval-request", headers=AGENT,
                            json={"revision_id": revisions[-1]["id"] if revisions else "missing"})
    if requested.status_code != 200:
        return requested
    return client.post(
        f"/v1/scars/{scar}/approve", headers=APPROVER,
        json={**requested.json(), "approver": "reviewer", "reason": "Reviewed replay and independent evidence"},
    )


def activate(client: TestClient, scar: str) -> None:
    assert approve(client, scar).status_code == 200
    response = client.post(f"/v1/scars/{scar}/activate", headers={"X-NOPE-Key": "admin"},
                           json={"authorized_by": "test-administrator", "reason": "Activate verified test revision through reviewed manual path"})
    assert response.status_code == 200, response.text


def decision(client: TestClient, scar: str, revision_id: str) -> dict[str, Any]:
    requested = client.post(f"/v1/scars/{scar}/approval-request", headers=AGENT,
                            json={"revision_id": revision_id})
    assert requested.status_code == 200, requested.text
    return {**requested.json(), "approver": "Security approver",
            "reason": "Reviewed the exact incident replay and independent challenge"}


@pytest.mark.parametrize("field,value", [
    ("revision_id", "rev-another-candidate"), ("evidence_sha256", "0" * 64),
    ("repository", "another/repository"), ("scope", "other/"),
    ("request_id", "approval-invented"),
])
def test_bound_approval_rejects_substitution(client: TestClient, field: str, value: str) -> None:
    scar = create(client)
    revision = validate(client, scar)["revision_id"]
    assert client.post(f"/v1/scars/{scar}/adversarial", headers=ADVERSARY, json=bundle()).json()["passed"]
    payload = decision(client, scar, revision)
    payload[field] = value
    rejected = client.post(f"/v1/scars/{scar}/approve", headers=APPROVER, json=payload)
    assert rejected.status_code == 409, rejected.text
    assert client.get(f"/v1/scars/{scar}", headers=AGENT).json()["status"] == "validated"


def test_exact_human_role_approval_and_replay_rejection(client: TestClient) -> None:
    scar = create(client)
    revision = validate(client, scar)["revision_id"]
    client.post(f"/v1/scars/{scar}/adversarial", headers=ADVERSARY, json=bundle())
    payload = decision(client, scar, revision)
    assert client.post(f"/v1/scars/{scar}/approve", headers=AGENT, json=payload).status_code == 403
    assert client.post(f"/v1/scars/{scar}/approve", json=payload).status_code == 401
    assert client.post(f"/v1/scars/{scar}/approve", headers=APPROVER,
                       json={"approver": "Security", "reason": "Approved in a chat message"}).status_code == 422
    accepted = client.post(f"/v1/scars/{scar}/approve", headers=APPROVER, json=payload)
    assert accepted.status_code == 200, accepted.text
    assert client.post(f"/v1/scars/{scar}/approve", headers=APPROVER, json=payload).status_code == 409
    events = client.get(f"/v1/scars/{scar}/provenance", headers=AGENT).json()["decisions"]
    approved = next(e for e in events if e["action"] == "scar.approved")
    assert approved["actor"].startswith("api-key:approver:")
    assert approved["detail"]["evidence_sha256"] == payload["evidence_sha256"]


def test_new_validation_invalidates_previous_approval_request(client: TestClient) -> None:
    scar = create(client)
    revision = validate(client, scar)["revision_id"]
    client.post(f"/v1/scars/{scar}/adversarial", headers=ADVERSARY, json=bundle())
    payload = decision(client, scar, revision)
    validate(client, scar)
    client.post(f"/v1/scars/{scar}/adversarial", headers=ADVERSARY, json=bundle())
    rejected = client.post(f"/v1/scars/{scar}/approve", headers=APPROVER, json=payload)
    assert rejected.status_code == 409 and "revision_id" in rejected.text


def test_expired_approval_request_is_rejected(client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    from datetime import UTC, datetime, timedelta

    from nope_core import approvals

    scar = create(client)
    revision = validate(client, scar)["revision_id"]
    client.post(f"/v1/scars/{scar}/adversarial", headers=ADVERSARY, json=bundle())
    payload = decision(client, scar, revision)
    future = datetime.now(UTC) + timedelta(days=2)

    class FutureClock(datetime):
        @classmethod
        def now(cls, tz: Any = None) -> FutureClock:
            return cls.fromtimestamp(future.timestamp(), tz or UTC)

    monkeypatch.setattr(approvals, "datetime", FutureClock)
    rejected = client.post(f"/v1/scars/{scar}/approve", headers=APPROVER, json=payload)
    assert rejected.status_code == 409 and "expired" in rejected.text


def test_activation_rechecks_approved_scope(client: TestClient) -> None:
    from nope_core.db import Scar, SessionLocal
    from sqlalchemy import select

    scar = create(client)
    validate(client, scar)
    client.post(f"/v1/scars/{scar}/adversarial", headers=ADVERSARY, json=bundle())
    assert approve(client, scar).status_code == 200
    with SessionLocal() as db:
        stored = db.scalar(select(Scar).where(Scar.number == int(scar)))
        assert stored is not None
        stored.scope = "changed/"
        db.commit()
    rejected = client.post(f"/v1/scars/{scar}/activate", headers=ADVERSARY,
                           json={"authorized_by": "admin", "reason": "Review exact evidence before activating"})
    assert rejected.status_code == 409 and "evidence hash" in rejected.text


def test_replay_and_separate_agent_are_required(client: TestClient) -> None:
    scar = create(client)
    evidence = validate(client, scar)
    assert evidence["replay"] == {
        "passed": True,
        "original_detected": True,
        "corrected_passes": True,
        "errors": [],
    }
    assert approve(client, scar).status_code == 409
    assert (
        client.post(f"/v1/scars/{scar}/adversarial", headers=AGENT, json=bundle()).status_code
        == 409
    )
    response = client.post(f"/v1/scars/{scar}/adversarial", headers=ADVERSARY, json=bundle())
    assert response.json()["detections"] == 6
    assert response.json()["misses"] == 0
    assert response.json()["false_positives"] == 0
    activate(client, scar)
    assert (
        client.post(f"/v1/scars/{scar}/adversarial", headers=ADVERSARY, json=bundle()).status_code
        == 409
    )


def test_threshold_rejection_is_recorded_and_cannot_be_overwritten(client: TestClient) -> None:
    scar = create(client)
    validate(client, scar)
    response = client.post(f"/v1/scars/{scar}/adversarial", headers=ADVERSARY, json=bundle(2, 1))
    assert response.status_code == 200
    assert response.json()["passed"] is False
    assert approve(client, scar).status_code == 409
    assert (
        client.post(f"/v1/scars/{scar}/adversarial", headers=ADVERSARY, json=bundle()).status_code
        == 409
    )
    rejected = client.post(
        f"/v1/scars/{scar}/reject",
        headers=APPROVER,
        json={"approver": "reviewer", "reason": "Too few independent test examples"},
    )
    assert rejected.status_code == 200
    provenance = client.get(f"/v1/scars/{scar}/provenance", headers={"X-NOPE-Key": "ci"}).json()
    assert provenance["revisions"][0]["state"] == "rejected"
    assert any(e["action"] == "scar.rejected" for e in provenance["decisions"])


def test_failed_replacement_preserves_active_rule_and_historical_evidence(
    client: TestClient,
) -> None:
    scar = create(client)
    original = validate(client, scar)
    client.post(f"/v1/scars/{scar}/adversarial", headers=ADVERSARY, json=bundle())
    activate(client, scar)
    before = client.get("/v1/rules/active.yml", headers={"X-NOPE-Key": "ci"}).text
    response = client.post(
        f"/v1/scars/{scar}/challenge",
        headers=AGENT,
        json={
            "challenger": "developer",
            "requested_by": "developer",
            "reason": "Propose a narrower replacement rule",
            "proposed_rule_yaml": RULE.replace("prevent-danger", "weak-rule"),
            "bad_examples": [{"name": "new.ts", "content": "newDanger(1);"}],
        },
    )
    assert response.status_code == 202, response.text
    assert response.json()["replacement_validation"] is False
    regression = response.json()["regression"]
    assert regression["passed"] is False
    assert regression["bad_examples"] == 8  # incident + author fixture + six independent variants
    assert regression["good_examples"] == 6
    assert approve(client, scar).status_code == 409
    assert client.get("/v1/rules/active.yml", headers={"X-NOPE-Key": "ci"}).text == before
    meta = yaml.safe_load(before)["rules"][0]["metadata"]
    assert meta["revision_id"] == original["revision_id"]
    assert client.get(meta["tests"], headers={"X-NOPE-Key": "ci"}).json()["challenge"]["metrics"][
        "passed"
    ]
    failure = client.post(
        "/v1/ci/failure",
        headers={"X-NOPE-Key": "ci"},
        json={
            "repository": "acme/service",
            "sha": "abcdef123",
            "scar_number": int(scar),
            "check_url": "https://ci.example/run/1",
            "revision_id": original["revision_id"],
        },
    )
    assert failure.status_code == 200
    assert failure.json()["tests"] == meta["tests"]
    assert failure.json()["approved_rule"] == meta["approved_rule"]


def test_replacement_requires_fresh_challenge_and_preserves_old_ci_links(
    client: TestClient,
) -> None:
    scar = create(client)
    first = validate(client, scar)
    client.post(f"/v1/scars/{scar}/adversarial", headers=ADVERSARY, json=bundle())
    activate(client, scar)
    second = validate(client, scar, RULE.replace("prevent-danger", "prevent-danger-v2"))
    assert second["regression"]["passed"]
    assert approve(client, scar).status_code == 409
    client.post(f"/v1/scars/{scar}/adversarial", headers=ADVERSARY, json=bundle())
    activate(client, scar)
    provenance = client.get(f"/v1/scars/{scar}/provenance", headers=AGENT).json()
    assert [r["state"] for r in provenance["revisions"]] == ["superseded", "active"]
    old = client.get(f"/v1/scars/{scar}/revisions/{first['revision_id']}/tests", headers=AGENT)
    assert old.status_code == 200


def test_replay_failure_and_missing_ci_evidence_cannot_pass(client: TestClient) -> None:
    scar = create(client)
    assert (
        client.post(
            "/v1/ci/failure",
            headers={"X-NOPE-Key": "ci"},
            json={
                "repository": "acme/service",
                "sha": "abcdef123",
                "scar_number": int(scar),
                "check_url": "https://ci.example/run/1",
            },
        ).status_code
        == 409
    )
    evidence = validate(client, scar, RULE.replace("prevent-danger", "weak-rule"))
    assert evidence["passed"] is False
    assert evidence["replay"]["original_detected"] is False
    assert approve(client, scar).status_code == 409


def test_challenge_misses_false_positives_and_author_fixture_reuse(client: TestClient) -> None:
    scar = create(client)
    validate(client, scar)
    reused = bundle()
    reused["bad_examples"][0]["content"] = "danger(1);"
    assert (
        client.post(f"/v1/scars/{scar}/adversarial", headers=ADVERSARY, json=reused).status_code
        == 409
    )
    challenge = bundle()
    challenge["bad_examples"][0]["content"] = "unrecognizedDanger();"
    challenge["good_examples"][0]["content"] = "danger(100);"
    metrics = client.post(f"/v1/scars/{scar}/adversarial", headers=ADVERSARY, json=challenge).json()
    assert metrics["detections"] == 5
    assert metrics["misses"] == 1
    assert metrics["false_positives"] == 1
    assert metrics["passed"] is False
    assert approve(client, scar).status_code == 409
