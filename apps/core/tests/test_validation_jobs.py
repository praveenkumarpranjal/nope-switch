from __future__ import annotations

import concurrent.futures
from typing import Any, cast

import pytest
from fastapi.testclient import TestClient
from nope_core import validation_jobs
from nope_core.db import SessionLocal, ValidationJob
from nope_core.main import app
from nope_core.rule_lab import CandidateResult, RuleLab

AGENT = {"X-NOPE-Key": "agent"}
RULE = """rules:
- id: prevent-danger
  message: Prevent the original dangerous operation
  severity: ERROR
  languages: [typescript]
  pattern: danger(...)
"""


@pytest.fixture
def client(monkeypatch: pytest.MonkeyPatch) -> Any:
    def scan(
        self: RuleLab,
        rule: str,
        bad: list[tuple[str, str]],
        good: list[tuple[str, str]],
        *args: Any,
        **kwargs: Any,
    ) -> CandidateResult:
        if "invalid-danger" in rule:
            raise RuntimeError("boom")
        bad_hits = {name: int("danger(" in code) for name, code in bad}
        good_hits = {name: int("danger(" in code) for name, code in good}
        return CandidateResult(all(bad_hits.values()) and not any(good_hits.values()), bad_hits, good_hits, [], [])

    monkeypatch.setattr(RuleLab, "validate", scan)
    with TestClient(app) as c:
        yield c


def create_scar(client: TestClient, suffix: str = "one") -> int:
    response = client.post(
        "/v1/scars",
        headers=AGENT,
        json={
            "title": f"Never repeat the dangerous operation {suffix}",
            "incident_summary": "Original operation caused a production incident",
            "invariant": f"Never call danger {suffix}",
            "rationale": "Dangerous operations destroy incident evidence",
            "remediation": "Use the safe operation instead",
            "repository": f"acme/service-{suffix}",
            "scope": "src/",
            "origin": f"INC-{suffix}",
            "proposed_by": f"rule-author-{suffix}",
        },
    )
    assert response.status_code == 201
    return int(response.json()["number"])


def validation_payload() -> dict[str, Any]:
    return {
        "rule_yaml": RULE,
        "original": {"name": "original.ts", "content": "danger(1);"},
        "corrected": {"name": "corrected.ts", "content": "safe(1);"},
        "bad_examples": [{"name": "author-bad.ts", "content": "danger(2);"}],
        "good_examples": [{"name": "author-good.ts", "content": "safe(2);"}],
    }


def test_validate_returns_202_and_worker_completes(client: TestClient) -> None:
    scar = create_scar(client, "async")
    response = client.post(f"/v1/scars/{scar}/validate", headers=AGENT, json=validation_payload())

    assert response.status_code == 202
    assert response.headers["Location"] == f"/v1/validations/{response.json()['job_id']}"
    assert response.json()["status_url"] == response.headers["Location"]

    assert validation_jobs.run_once() == 1
    job = client.get(response.headers["Location"], headers=AGENT)
    assert job.status_code == 200
    body = cast(dict[str, Any], job.json())
    assert body["status"] == "completed"
    assert body["result"]["passed"] is True
    assert body["result"]["revision_id"]


def test_five_concurrent_validations_return_202_and_drain(client: TestClient) -> None:
    scar = create_scar(client, "concurrent")

    def submit() -> str:
        response = client.post(f"/v1/scars/{scar}/validate", headers=AGENT, json=validation_payload())
        assert response.status_code == 202
        return str(response.json()["job_id"])

    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
        job_ids = list(executor.map(lambda _: submit(), range(5)))

    assert len(set(job_ids)) == 5
    assert validation_jobs.run_worker(poll_interval=0.0, max_jobs=5) == 5

    with SessionLocal() as db:
        rows = list(db.query(ValidationJob).filter(ValidationJob.id.in_(job_ids)).all())
    assert {row.status for row in rows} == {"completed"}
    assert all(row.result for row in rows)


def test_worker_records_failure_instead_of_silent_success(client: TestClient) -> None:
    scar = create_scar(client, "failure")
    payload = validation_payload()
    payload["rule_yaml"] = RULE.replace("prevent-danger", "invalid-danger")

    response = client.post(f"/v1/scars/{scar}/validate", headers=AGENT, json=payload)

    assert response.status_code == 202
    assert validation_jobs.run_once() == 1
    job = client.get(response.headers["Location"], headers=AGENT)
    assert job.json()["status"] == "failed"
    assert "boom" in job.json()["error"]
