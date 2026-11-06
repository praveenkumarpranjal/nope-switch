from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient
from nope_core.agent import (
    GitBranchAndPRService,
    SessionManager,
    SessionState,
    SwitchAgentDispatcher,
)
from nope_core.auth import issue_token
from nope_core.db import Base, engine
from nope_core.main import app


def reset_schema() -> None:
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)


@pytest.fixture
def temp_git_repo(tmp_path: Path) -> Path:
    """Create a temporary git repository for testing branch creation and commits."""
    repo = tmp_path / "target-repo"
    repo.mkdir()
    subprocess.run(["git", "init"], cwd=str(repo), check=True, capture_output=True)
    subprocess.run(["git", "config", "user.name", "Test Runner"], cwd=str(repo), check=True, capture_output=True)
    subprocess.run(["git", "config", "user.email", "runner@acme.com"], cwd=str(repo), check=True, capture_output=True)
    subprocess.run(["git", "config", "commit.gpgsign", "false"], cwd=str(repo), check=True, capture_output=True)
    (repo / "README.md").write_text("# Target Repo\n", encoding="utf-8")
    subprocess.run(["git", "add", "README.md"], cwd=str(repo), check=True, capture_output=True)
    subprocess.run(["git", "commit", "-m", "initial commit"], cwd=str(repo), check=True, capture_output=True)
    return repo


def test_session_state_machine_lifecycle() -> None:
    manager = SessionManager(default_timeout_seconds=2.0)
    session = manager.create("thread-1", "alice")
    assert session.state == SessionState.INIT
    assert manager.get("thread-1") is not None

    # Verify expiration
    session.updated_at -= 5.0
    assert session.is_expired(timeout_seconds=2.0)
    expired = manager.cleanup_expired()
    assert "thread-1" in expired
    assert manager.get("thread-1") is None


def test_hard_merge_restriction_guard() -> None:
    with pytest.raises(PermissionError) as exc_info:
        GitBranchAndPRService.merge_pull_request(42)
    assert "agent is forbidden from merging pull requests" in str(exc_info.value)


def test_branch_naming_restriction_guard(temp_git_repo: Path) -> None:
    with pytest.raises(ValueError) as exc_info:
        GitBranchAndPRService.commit_rule_and_fixtures(
            temp_git_repo,
            "main",  # forbidden target branch
            scar_number=1,
            rule_yaml="rules: []",
            fixtures={},
        )
    assert "Refusing to commit to non-nope branch" in str(exc_info.value)


def test_full_teach_and_pr_generation_workflow(temp_git_repo: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reset_schema()

    with TestClient(app) as test_client:
        mock_pr_url = "https://github.com/acme/target-repo/pull/101"

        def mock_gh_executor(repo_dir: Path, branch: str, title: str, body: str) -> str:
            assert branch.startswith("nope/scar-")
            assert "DO NOT MERGE" in title
            assert "Never log credentials" in body
            return mock_pr_url

        dispatcher = SwitchAgentDispatcher(
            base_url="http://testserver",
            repo_dir=temp_git_repo,
            gh_executor=mock_gh_executor,
        )

        import httpx

        def test_client_factory(*args: Any, **kwargs: Any) -> Any:
            # Route requests through starlette TestClient
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
                    return self.tc.get(url, headers=h)

                def post(self, url: str, **kw: Any) -> Any:
                    h = {**self.headers, **kw.get("headers", {})}
                    return self.tc.post(url, headers=h, json=kw.get("json"))

            return ClientAdapter(test_client, kwargs.get("headers", {}))

        monkeypatch.setattr(httpx, "Client", test_client_factory)

        thread_id = "switch-room-thread-42"
        user_id = "carol@acme.com"

        # Step 1: Initiate @nope teach
        prompt_1 = '@nope teach We had INC-042: credentials logged to datadog. Never log credentials in this service.'
        reply_1 = dispatcher.handle_message(thread_id, user_id, prompt_1)
        assert "INC-042" in reply_1
        assert "Never log credentials" in reply_1
        assert "confirm the following two parameters" in reply_1

        session = dispatcher.sessions.get(thread_id)
        assert session is not None
        assert session.state == SessionState.AWAITING_SCOPE_AND_ROLLOUT

        # Step 2: Answer Scope & Rollout questions
        prompt_2 = 'repo: acme/auth-service, scope: src/auth/, rollout: blocking'
        reply_2 = dispatcher.handle_message(thread_id, user_id, prompt_2)
        assert "Created & Tested" in reply_2
        assert "Rule Lab Verification" in reply_2

        session = dispatcher.sessions.get(thread_id)
        assert session is not None
        assert session.state == SessionState.AWAITING_APPROVAL
        assert session.scar_id is not None
        assert session.scar_number == 1

        # Step 3: Approve and trigger branch & PR generation
        prompt_3 = '@nope approve Legitimate security policy confirmed by SRE'
        reply_3 = dispatcher.handle_message(thread_id, user_id, prompt_3)
        assert "Approved & PR Generated!" in reply_3
        assert mock_pr_url in reply_3

        session = dispatcher.sessions.get(thread_id)
        assert session is not None
        assert session.state == SessionState.COMPLETED
        assert session.pr_branch is not None
        assert session.pr_branch.startswith("nope/scar-1-")

        # Verify files were actually committed in the git repository
        committed_rule = temp_git_repo / "config" / "semgrep" / "nope-scar-001.yml"
        assert committed_rule.is_file()
        assert "rules:" in committed_rule.read_text(encoding="utf-8")

        # Check status command
        status_reply = dispatcher.handle_message(thread_id, user_id, "@nope status")
        assert "completed" in status_reply


def test_challenge_workflow_through_agent(monkeypatch: pytest.MonkeyPatch) -> None:
    reset_schema()

    with TestClient(app) as test_client:
        dispatcher = SwitchAgentDispatcher(base_url="http://testserver")

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
                    return self.tc.get(url, headers=h)

                def post(self, url: str, **kw: Any) -> Any:
                    h = {**self.headers, **kw.get("headers", {})}
                    return self.tc.post(url, headers=h, json=kw.get("json"))

            return ClientAdapter(test_client, kwargs.get("headers", {}))

        monkeypatch.setattr(httpx, "Client", test_client_factory)

        # Create a scar first
        admin_token = issue_token("admin", "admin")
        created = test_client.post(
            "/v1/scars",
            headers={"Authorization": f"Bearer {admin_token}"},
            json={
                "title": "Never leak credentials in logs",
                "incident_summary": "Incident summary with sufficient description length",
                "invariant": "Never leak credentials in logs",
                "rationale": "Logs are broad and retained",
                "remediation": "Do not log credentials",
                "repository": "acme/auth",
                "scope": "src/",
                "severity": "high",
                "enforcement": "semgrep",
                "origin": "INC-099",
                "proposed_by": "admin",
            },
        )
        assert created.status_code == 201

        # Dispatcher challenges the scar
        chal_msg = "@nope challenge 1 Need temporary exception during auth migration"
        chal_reply = dispatcher.handle_message("thread-chal", "dev@acme.com", chal_msg)
        assert "Challenge Recorded for Scar #001" in chal_reply
        assert "Exception ID" in chal_reply
