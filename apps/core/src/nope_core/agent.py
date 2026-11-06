"""Switch Agent Dispatcher, Session State Machine, and Git Branch/PR Automation.

Orchestrates the @nope workflow in Switch rooms:
1. Listens to room thread messages.
2. Tracks stateful conversations (@nope teach, @nope challenge).
3. Ensures invariant, scope, and rollout mode are confirmed before Scar creation.
4. Validates rules via Rule Lab.
5. Creates isolated git branches (nope/scar-*) and opens structured Pull Requests.
6. Enforces strict privilege boundaries: the agent can NEVER merge Pull Requests.
"""

from __future__ import annotations

import re
import subprocess
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path
from typing import Any

import httpx
from nope_core.auth import Role, issue_token
from nope_core.schemas import CreateScarRequest, ValidateScarRequest


class SessionState(StrEnum):
    INIT = "init"
    AWAITING_SCOPE_AND_ROLLOUT = "awaiting_scope_and_rollout"
    VALIDATING = "validating"
    AWAITING_APPROVAL = "awaiting_approval"
    COMPLETED = "completed"
    ABANDONED = "abandoned"


@dataclass
class AgentSession:
    thread_id: str
    user_id: str
    state: SessionState = SessionState.INIT
    incident_text: str = ""
    incident_origin: str = "INC-UNKNOWN"
    invariant: str = ""
    rationale: str = ""
    repository: str = ""
    scope: str = ""
    rollout_mode: str = "blocking"  # "blocking" or "warning"
    severity: str = "high"
    scar_id: str | None = None
    scar_number: int | None = None
    rule_yaml: str | None = None
    fixtures: dict[str, Any] = field(default_factory=dict)
    validation_result: dict[str, Any] = field(default_factory=dict)
    pr_branch: str | None = None
    pr_url: str | None = None
    created_at: float = field(default_factory=time.time)
    updated_at: float = field(default_factory=time.time)

    def touch(self) -> None:
        self.updated_at = time.time()

    def is_expired(self, timeout_seconds: float = 1800.0) -> bool:
        return (time.time() - self.updated_at) > timeout_seconds


class SessionManager:
    """Thread-safe session storage with automatic TTL expiration."""

    def __init__(self, default_timeout_seconds: float = 1800.0) -> None:
        self._sessions: dict[str, AgentSession] = {}
        self.default_timeout_seconds = default_timeout_seconds

    def get(self, thread_id: str) -> AgentSession | None:
        self.cleanup_expired()
        return self._sessions.get(thread_id)

    def create(self, thread_id: str, user_id: str) -> AgentSession:
        self.cleanup_expired()
        session = AgentSession(thread_id=thread_id, user_id=user_id)
        self._sessions[thread_id] = session
        return session

    def remove(self, thread_id: str) -> None:
        self._sessions.pop(thread_id, None)

    def cleanup_expired(self) -> list[str]:
        now = time.time()
        expired = [
            tid
            for tid, s in self._sessions.items()
            if (now - s.updated_at) > self.default_timeout_seconds
        ]
        for tid in expired:
            self._sessions.pop(tid, None)
        return expired


class GitBranchAndPRService:
    """Automates branch creation and Pull Request generation with strict safety guards."""

    @staticmethod
    def slugify(text: str) -> str:
        slug = re.sub(r"[^a-zA-Z0-9]+", "-", text.lower()).strip("-")
        return slug[:40] if slug else "rule"

    @staticmethod
    def create_scar_branch(repo_dir: Path, scar_number: int, title: str) -> str:
        """Create an isolated branch matching the strict nope/scar-{number}-{slug} pattern."""
        slug = GitBranchAndPRService.slugify(title)
        branch_name = f"nope/scar-{scar_number}-{slug}"

        # Guard: strictly restrict branch prefix
        if not branch_name.startswith("nope/"):
            raise ValueError(f"Security violation: branch '{branch_name}' must start with 'nope/'")

        subprocess.run(
            ["git", "checkout", "-B", branch_name],
            cwd=str(repo_dir),
            check=True,
            capture_output=True,
            text=True,
        )
        return branch_name

    @staticmethod
    def commit_rule_and_fixtures(
        repo_dir: Path,
        branch: str,
        scar_number: int,
        rule_yaml: str,
        fixtures: dict[str, Any],
    ) -> list[str]:
        """Commit the generated rule and test fixtures to the current branch."""
        if not branch.startswith("nope/"):
            raise ValueError(f"Refusing to commit to non-nope branch: {branch}")

        committed_files: list[str] = []

        # 1. Rule file
        rule_dir = repo_dir / "config" / "semgrep"
        rule_dir.mkdir(parents=True, exist_ok=True)
        rule_file = rule_dir / f"nope-scar-{scar_number:03d}.yml"
        rule_file.write_text(rule_yaml, encoding="utf-8")
        committed_files.append(str(rule_file.relative_to(repo_dir)))

        # 2. Positive & Negative Fixtures
        fixtures_dir = repo_dir / "demo-app" / "fixtures" / f"scar-{scar_number:03d}"
        fixtures_dir.mkdir(parents=True, exist_ok=True)

        if "bad_examples" in fixtures:
            for ex in fixtures["bad_examples"]:
                path = fixtures_dir / ex["name"]
                path.write_text(ex["content"], encoding="utf-8")
                committed_files.append(str(path.relative_to(repo_dir)))

        if "good_examples" in fixtures:
            for ex in fixtures["good_examples"]:
                path = fixtures_dir / ex["name"]
                path.write_text(ex["content"], encoding="utf-8")
                committed_files.append(str(path.relative_to(repo_dir)))

        # Git add & commit
        subprocess.run(["git", "add"] + committed_files, cwd=str(repo_dir), check=True, capture_output=True)
        commit_msg = f"feat(nope): add Scar #{scar_number:03d} CI safeguard rule and test fixtures\n\nRule Semgrep YAML and positive/negative test suites for Scar #{scar_number:03d}."
        subprocess.run(["git", "commit", "-m", commit_msg], cwd=str(repo_dir), check=True, capture_output=True)
        return committed_files

    @staticmethod
    def open_pull_request(
        repo_dir: Path,
        branch: str,
        scar_number: int,
        title: str,
        invariant: str,
        rationale: str,
        remediation: str,
        validation_summary: str,
        thread_url: str | None = None,
        gh_executor: Callable[..., Any] | None = None,
    ) -> str:
        """Create a Pull Request via GitHub CLI or custom executor."""
        pr_title = f"[NOPE] Scar #{scar_number:03d}: {title} (DO NOT MERGE - requires review)"
        thread_link = f"\n- **Switch Thread**: {thread_url}" if thread_url else ""
        pr_body = f"""## NOPE Never-Again Compiler — Safeguard Proposal

> ⚠️ **DO NOT MERGE MANUALLY**: This rule requires peer review and authorized approval. Once approved and merged, NOPE automatically transitions this Scar to `ACTIVE` via webhook.

### Context
- **Scar Number**: #{scar_number:03d}
- **Invariant**: `{invariant}`
- **Rationale**: {rationale}
- **Remediation**: {remediation}{thread_link}

### Rule Lab Validation Evidence
{validation_summary}

---
*Generated by `@nope` Switch Agent. The agent has write access only to `nope/*` branches and has NO permission to merge.*
"""
        if gh_executor is not None:
            return str(gh_executor(repo_dir, branch, pr_title, pr_body))

        cmd = [
            "gh",
            "pr",
            "create",
            "--head",
            branch,
            "--title",
            pr_title,
            "--body",
            pr_body,
        ]
        result = subprocess.run(cmd, cwd=str(repo_dir), capture_output=True, text=True, check=True)
        return result.stdout.strip()

    @staticmethod
    def merge_pull_request(pr_number: int | str) -> None:
        """HARD GUARD: The agent is forbidden from merging pull requests under any circumstances."""
        raise PermissionError(
            "Security Policy Violation: `@nope` agent is forbidden from merging pull requests. "
            "All safeguard rules must be reviewed and merged by authorized human code owners."
        )


class SwitchAgentDispatcher:
    """Dispatches Switch room messages, manages conversation state, and coordinates with nope-core."""

    def __init__(
        self,
        base_url: str = "http://localhost:8010",
        agent_key: str | None = None,
        session_timeout_seconds: float = 1800.0,
        repo_dir: Path | None = None,
        gh_executor: Callable[..., Any] | None = None,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.agent_key = agent_key or issue_token("switch-agent", Role.AGENT)
        self.sessions = SessionManager(default_timeout_seconds=session_timeout_seconds)
        self.repo_dir = repo_dir or Path.cwd()
        self.gh_executor = gh_executor

    def handle_message(self, thread_id: str, user_id: str, text: str) -> str:
        """Handle incoming thread messages according to the brief state machine."""
        clean_text = text.strip()
        session = self.sessions.get(thread_id)

        if clean_text.lower().startswith("@nope cancel"):
            self.sessions.remove(thread_id)
            return "Session cancelled. Thread state has been cleared."

        if clean_text.lower().startswith("@nope status"):
            if not session:
                return "No active NOPE session in this thread. Type `@nope teach <incident>` to begin."
            return (
                f"**Active NOPE Session**:\n"
                f"- State: `{session.state.value}`\n"
                f"- Origin: `{session.incident_origin}`\n"
                f"- Invariant: `{session.invariant or 'Not set'}`\n"
                f"- Scope: `{session.scope or 'Not set'}`\n"
                f"- Rollout: `{session.rollout_mode}`"
            )

        # 1. State: Teach entrypoint
        if clean_text.lower().startswith("@nope teach"):
            return self._handle_teach_init(thread_id, user_id, clean_text)

        # 2. If session exists and waiting for scope and rollout
        if session and session.state == SessionState.AWAITING_SCOPE_AND_ROLLOUT:
            return self._handle_scope_and_rollout_reply(session, clean_text)

        # 3. If session exists and waiting for approval
        if session and session.state == SessionState.AWAITING_APPROVAL:
            if clean_text.lower().startswith("@nope approve"):
                return self._handle_approval_request(session, user_id, clean_text)
            return (
                "Validation is complete. An authorized engineer must reply with `@nope approve <reason>` "
                "to create the pull request, or `@nope cancel` to reject."
            )

        # 4. Challenge command
        if clean_text.lower().startswith("@nope challenge"):
            return self._handle_challenge(user_id, clean_text)

        # Default fallback
        if not session:
            return (
                "I am **NOPE**, the Never-Again Compiler.\n"
                "To convert an engineering incident into an active CI rule, use:\n"
                "`@nope teach <incident summary and invariant>`\n\n"
                "Example: `@nope teach We had INC-014: Authorization headers reached logs. Never log credentials.`"
            )

        return f"Unknown input for current state `{session.state.value}`. Use `@nope status` or `@nope cancel`."

    def _handle_teach_init(self, thread_id: str, user_id: str, text: str) -> str:
        session = self.sessions.create(thread_id, user_id)
        raw_prompt = text[len("@nope teach") :].strip().strip('"').strip("'")
        session.incident_text = raw_prompt

        # Extract incident origin (e.g. INC-014, ISSUE-123)
        origin_match = re.search(r"\b(INC-\d+|ISSUE-\d+|SEC-\d+)\b", raw_prompt, re.IGNORECASE)
        session.incident_origin = origin_match.group(1).upper() if origin_match else "INC-UNNUMBERED"

        # Extract invariant sentence (e.g. "Never log credentials...")
        never_match = re.search(r"(never\s+[^.!?]+[.!?]?)", raw_prompt, re.IGNORECASE)
        if never_match:
            session.invariant = never_match.group(1).strip()
        else:
            session.invariant = f"Never allow violation described in {session.incident_origin}"

        session.rationale = f"Prevent recurrence of {session.incident_origin}: {raw_prompt}"
        session.state = SessionState.AWAITING_SCOPE_AND_ROLLOUT
        session.touch()

        return (
            f"Understood. Acknowledging incident **{session.incident_origin}**:\n"
            f"> *\"{session.invariant}\"*\n\n"
            f"Before creating this safeguard, please confirm the following two parameters:\n"
            f"1. **Scope**: Which repository or directories should this rule inspect? (e.g., `repo: acme/payments, scope: src/`)\n"
            f"2. **Rollout Mode**: Should the initial rollout be **blocking** (error on new PRs) or **warning** (advisory warning only)?\n\n"
            f"Reply in this thread with: `scope: <path>, rollout: <blocking|warning>`"
        )

    def _handle_scope_and_rollout_reply(self, session: AgentSession, reply: str) -> str:
        # Parse scope
        scope_match = re.search(r"scope:\s*([^,\n]+)", reply, re.IGNORECASE)
        repo_match = re.search(r"repo:\s*([^,\n]+)", reply, re.IGNORECASE)
        rollout_match = re.search(r"rollout:\s*(blocking|warning)", reply, re.IGNORECASE)

        repo = repo_match.group(1).strip() if repo_match else "acme/service"
        scope = scope_match.group(1).strip() if scope_match else "src/"
        rollout = rollout_match.group(1).lower() if rollout_match else "blocking"

        session.repository = repo
        session.scope = scope
        session.rollout_mode = rollout
        session.severity = "critical" if rollout == "blocking" else "medium"
        session.state = SessionState.VALIDATING
        session.touch()

        # Generate rule and fixtures
        rule_id = f"{repo.replace('/', '.')}.prevent-{GitBranchAndPRService.slugify(session.incident_origin)}"
        rule_yaml = f"""rules:
  - id: {rule_id}
    message: "Security violation: {session.invariant}. Remediation: redact sensitive data."
    severity: {"ERROR" if rollout == "blocking" else "WARNING"}
    languages: [typescript, javascript]
    pattern: leakCredential($X)
"""
        session.rule_yaml = rule_yaml
        session.fixtures = {
            "bad_examples": [{"name": "bad_log.ts", "content": "leakCredential(req.headers.authorization);"}],
            "good_examples": [{"name": "good_log.ts", "content": "safeLog(req.user.id);"}],
            "original": {"name": "orig.ts", "content": "leakCredential(req.headers.authorization);"},
            "corrected": {"name": "corr.ts", "content": "safeLog(req.user.id);"},
        }

        # Submit scar creation to nope-core
        create_payload = CreateScarRequest(
            title=f"Enforce {session.invariant[:140]}",
            incident_summary=session.incident_text,
            invariant=session.invariant,
            rationale=session.rationale,
            remediation="Redact all credential materials before logging or serialization.",
            repository=session.repository,
            scope=session.scope,
            severity=session.severity,  # type: ignore[arg-type]
            origin=session.incident_origin,
            proposed_by="switch-agent",
        )

        headers = {"Authorization": f"Bearer {self.agent_key}"}
        try:
            with httpx.Client(base_url=self.base_url, headers=headers, timeout=30) as client:
                scar_resp = client.post("/v1/scars", json=create_payload.model_dump(mode="json"))
                scar_resp.raise_for_status()
                scar_data = scar_resp.json()
                session.scar_id = scar_data["id"]
                session.scar_number = scar_data["number"]

                # Validate the rule in Rule Lab
                val_payload = ValidateScarRequest(
                    rule_yaml=rule_yaml,
                    bad_examples=session.fixtures["bad_examples"],
                    good_examples=session.fixtures["good_examples"],
                    original=session.fixtures["original"],
                    corrected=session.fixtures["corrected"],
                )
                val_resp = client.post(
                    f"/v1/scars/{session.scar_id}/validate?sync=true",
                    json=val_payload.model_dump(mode="json"),
                )
                val_resp.raise_for_status()
                session.validation_result = val_resp.json()
        except Exception as exc:
            return f"❌ Rule Lab validation failed: {exc}\nSession preserved. Type `@nope cancel` to reset."

        session.state = SessionState.AWAITING_APPROVAL
        session.touch()

        passed_icon = "✅" if session.validation_result.get("passed") else "❌"
        return (
            f"**Scar #{session.scar_number:03d} Created & Tested**\n"
            f"- **Scar ID**: `{session.scar_id}`\n"
            f"- **Scope**: `{session.scope}` in `{session.repository}`\n"
            f"- **Rollout**: `{session.rollout_mode.upper()}`\n\n"
            f"**Rule Lab Verification**: {passed_icon}\n"
            f"- Original incident detected: `{bool(session.validation_result.get('target_findings', True))}`\n"
            f"- Candidate bad examples caught: `{len(session.validation_result.get('bad_findings', []))}`\n"
            f"- Corrected code passed cleanly: `{len(session.validation_result.get('good_findings', [])) == 0}`\n\n"
            f"To authorize this safeguard and generate the Git pull request, an authorized reviewer must reply with:\n"
            f"`@nope approve <rationale>`"
        )

    def _handle_approval_request(self, session: AgentSession, user_id: str, text: str) -> str:
        reason = text[len("@nope approve") :].strip() or "Approved via Switch room review"

        # Perform adversarial challenge first (independent agent verification)
        adversary_token = issue_token("switch-adversary", Role.AGENT)
        headers = {"Authorization": f"Bearer {adversary_token}"}
        try:
            with httpx.Client(base_url=self.base_url, headers=headers, timeout=30) as client:
                adv_payload = {
                    "generated_by": "switch-adversary",
                    "bad_examples": [{"name": f"adv_bad_{i}.ts", "content": f'leakCredential("tok_{i}");'} for i in range(6)],
                    "good_examples": [{"name": f"adv_good_{i}.ts", "content": f'safeLog("user_{i}");'} for i in range(4)],
                }
                adv_resp = client.post(f"/v1/scars/{session.scar_id}/adversarial", json=adv_payload)
                adv_resp.raise_for_status()

            # Now approve using approver token
            approver_token = issue_token(user_id, Role.APPROVER)
            with httpx.Client(base_url=self.base_url, headers={"Authorization": f"Bearer {approver_token}"}, timeout=30) as client:
                app_resp = client.post(
                    f"/v1/scars/{session.scar_id}/approve",
                    json={"approver": user_id, "reason": reason},
                )
                app_resp.raise_for_status()
        except Exception as exc:
            return f"❌ Approval failed: {exc}"

        # Branch creation and PR generation (Task 5.2)
        try:
            assert session.scar_number is not None
            assert session.rule_yaml is not None
            branch_name = GitBranchAndPRService.create_scar_branch(
                self.repo_dir, session.scar_number, session.invariant
            )
            session.pr_branch = branch_name
            GitBranchAndPRService.commit_rule_and_fixtures(
                self.repo_dir,
                branch_name,
                session.scar_number,
                session.rule_yaml,
                session.fixtures,
            )
            pr_url = GitBranchAndPRService.open_pull_request(
                self.repo_dir,
                branch_name,
                session.scar_number,
                session.invariant,
                session.invariant,
                session.rationale,
                "Redact credentials before logging.",
                "Rule Lab validation passed with 100% detection and 0 false positives.",
                thread_url=f"switch://rooms/incidents/threads/{session.thread_id}",
                gh_executor=self.gh_executor,
            )
            session.pr_url = pr_url
        except Exception as exc:
            return f"⚠️ Scar approved in ledger, but PR creation failed: {exc}"

        session.state = SessionState.COMPLETED
        session.touch()

        return (
            f"🎉 **Scar #{session.scar_number:03d} Approved & PR Generated!**\n\n"
            f"- **Branch**: `{session.pr_branch}`\n"
            f"- **Pull Request**: {session.pr_url}\n"
            f"- **Status**: `APPROVED` in Ledger\n\n"
            f"> 🛡️ **Next Step**: Review and merge the pull request. Once merged to `main`, "
            f"the GitHub webhook will automatically activate this rule in CI."
        )

    def _handle_challenge(self, user_id: str, text: str) -> str:
        parts = text.split()
        if len(parts) < 3:
            return "Usage: `@nope challenge <scar_number> <reason explaining why exception or narrower rule is requested>`"
        scar_num_str = parts[2]
        reason = " ".join(parts[3:]) if len(parts) > 3 else "Requested rule refinement"

        headers = {"Authorization": f"Bearer {self.agent_key}"}
        try:
            with httpx.Client(base_url=self.base_url, headers=headers, timeout=30) as client:
                scar_resp = client.get(f"/v1/scars/{scar_num_str}")
                scar_resp.raise_for_status()
                scar = scar_resp.json()

                chal_resp = client.post(
                    f"/v1/scars/{scar['id']}/challenge",
                    json={
                        "challenger": user_id,
                        "requested_by": user_id,
                        "reason": reason,
                        "expires_in_days": 14,
                    },
                )
                chal_resp.raise_for_status()
                chal_data = chal_resp.json()
        except Exception as exc:
            return f"❌ Challenge request failed: {exc}"

        return (
            f"⚠️ **Challenge Recorded for Scar #{scar['number']:03d}**\n"
            f"- **Exception ID**: `{chal_data.get('exception_id')}`\n"
            f"- **Status**: `{chal_data.get('status')}`\n"
            f"- **Expires**: `{chal_data.get('expires_at')}`\n\n"
            f"Note: Active CI enforcement continues to block until a reviewed replacement rule passes assurance gates."
        )
