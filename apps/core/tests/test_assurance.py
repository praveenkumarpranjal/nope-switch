from __future__ import annotations

from typing import Any, cast

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
        f"/v1/scars/{scar}/validate?sync=true",
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
    return cast(dict[str, Any], response.json())


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
    return client.post(
        f"/v1/scars/{scar}/approve",
        headers=APPROVER,
        json={"approver": "reviewer", "reason": "Reviewed replay and independent evidence"},
    )


def activate(client: TestClient, scar: str) -> None:
    assert approve(client, scar).status_code == 200
    response = client.post(f"/v1/scars/{scar}/activate", headers={"X-NOPE-Key": "admin"},
                           json={"authorized_by": "test-administrator", "reason": "Activate verified test revision through reviewed manual path"})
    assert response.status_code == 200, response.text


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
    from nope_core import validation_jobs

    assert validation_jobs.run_once() == 1
    job_response = client.get(response.json()["replacement_status_url"], headers=AGENT)
    assert job_response.status_code == 200
    assert job_response.json()["status"] == "completed"
    replacement_result = job_response.json()["result"]
    assert replacement_result["passed"] is False
    regression = replacement_result["regression"]
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
