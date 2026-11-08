from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import httpx
import pytest
from nope_core.rule_lab import CandidateResult, RuleLab
from nope_switch.cli import parser, run, verify_preflights
from nope_switch.config import RoomSettings
from nope_switch.console import load_credentials
from nope_switch.evidence import (
    Experiment,
    compliance,
    courtroom_from_ledger,
    failure_message,
    scar_document,
    verify_room_source,
)
from nope_switch.live import discover, receive, roundtrip
from nope_switch.pull_request import approved_proposal, description
from nope_switch.transport import SwitchClient, SwitchError
from pydantic import ValidationError


def ledger() -> dict[str, Any]:
    return {
        "scar": {
            "number": 1,
            "title": "Never log credentials",
            "incident_url": "https://issues.example/INC-014",
            "origin": "INC-014",
            "invariant": "Credentials must not reach logs",
            "rationale": "Logs are retained",
            "remediation": "Log an actor ID instead",
        },
        "revisions": [{"id": "rev-approved", "state": "active", "rule_sha256": "approved-hash"}],
        "decisions": [
            {
                "action": "scar.proposed",
                "detail": {"teach_message_url": "https://chat.example/teach"},
            },
            {
                "action": "scar.approved",
                "detail": {"revision_id": "rev-approved", "approver": "security-reviewer"},
            },
        ],
    }


def scan() -> dict[str, Any]:
    return {
        "results": [
            {
                "path": "src/auth.ts",
                "start": {"line": 7},
                "extra": {"metadata": {"scar": "SCAR-001", "revision_id": "rev-approved"}},
            }
        ],
        "errors": [],
    }


class Bridge:
    """Deterministic protocol double, never a claimed real Switch connection."""

    def __init__(self) -> None:
        self.calls: list[httpx.Request] = []
        self.timeline: list[dict[str, Any]] = [
            {
                "id": "teach-id",
                "sender": "developer",
                "sender_name": "Developer",
                "body": "@nope teach INC-014 never log tokens",
                "timestamp": 1,
            },
            {"id": "chat-approval", "sender": "developer", "body": "@nope approve 1"},
            {"id": "challenge-id", "sender": "developer", "body": "@nope challenge 1 too broad"},
        ]
        self.reply_sender = "red-agent"

    def respond(self, request: httpx.Request) -> httpx.Response:
        self.calls.append(request)
        path = request.url.path
        if path == "/health":
            return httpx.Response(200, json={"status": "ok"})
        if path.endswith("/ops"):
            properties = {
                "read_context": ["room_id", "since", "limit"],
                "send_targeted_message": ["body", "target_names"],
                "create_room_document": ["name", "description", "instructions", "content"],
                "list_rooms": [],
                "list_bridges": [],
                "list_agents": ["name_contains"],
                "get_room_detail": ["room_id"],
            }
            return httpx.Response(
                200,
                json={
                    "operations": {
                        name: {"input_schema": {"properties": dict.fromkeys(fields, {})}}
                        for name, fields in properties.items()
                    }
                },
            )
        body = json.loads(request.content or "{}")
        if path.endswith("/message"):
            self.timeline.append(
                {"id": "posted-event", "sender": "nope-id", "body": body["content"]}
            )
            return httpx.Response(200, json={"ok": True, "event_id": "posted-event"})
        operation = path.rsplit("/", 1)[-1]
        results: dict[str, Any] = {
            "list_rooms": [{"room_id": "actual-room", "name": "nope-never-again"}],
            "list_bridges": [
                {
                    "id": "bridge-id",
                    "type": "mattermost",
                    "status": "active",
                    "display_name": "Local Mattermost",
                }
            ],
            "list_agents": [{"id": "nope-id", "name": "nope"}],
            "get_room_detail": {
                "id": "actual-room",
                "name": "nope-never-again",
                "bridge_id": "bridge-id",
            },
            "create_room_document": {"document_id": "doc-id"},
        }
        if operation == "read_context":
            results[operation] = {
                "threads": [{"root": entry, "replies": []} for entry in self.timeline]
            }
        if operation == "send_targeted_message":
            ack = body["body"].split("exactly ")[1].split(".")[0]
            self.timeline.append({"id": "probe-request", "sender": "nope-id", "body": body["body"]})
            self.timeline.append({"id": "agent-reply", "sender": self.reply_sender, "body": ack})
            results[operation] = {"event_id": "probe-request"}
        return httpx.Response(200, json={"result": results.get(operation)})


def client(bridge: Bridge, connection: str | None = "existing-console-connection") -> SwitchClient:
    return SwitchClient(
        "https://switch.example",
        "nope-id",
        "test-key",
        "actual-room",
        connection,
        httpx.Client(transport=httpx.MockTransport(bridge.respond)),
    )


def settings() -> RoomSettings:
    return RoomSettings(True, "https://switch.example", "actual-room", "", "", "nope")


def test_notification_is_outbound_http_without_event_connection() -> None:
    bridge = Bridge()
    room = client(bridge, None)
    assert room.post("Measured results")["event_id"] == "posted-event"
    assert bridge.calls[0].url.path == "/agents/nope-id/message"
    assert json.loads(bridge.calls[0].content) == {
        "room_id": "actual-room",
        "content": "Measured results",
    }
    assert bridge.calls[0].headers["authorization"] == "Bearer test-key"
    assert all("/connection" not in str(call.url) for call in bridge.calls)


def test_documents_need_existing_connection_and_use_discovered_operation() -> None:
    bridge = Bridge()
    with pytest.raises(SwitchError, match="existing Console session"):
        client(bridge, None).create_document("scar-001", "summary")
    room = client(bridge)
    assert room.create_document("scar-001", "summary")["document_id"] == "doc-id"
    request = bridge.calls[-1]
    assert request.headers["x-switch-connection-id"] == "existing-console-connection"
    assert json.loads(request.content)["content"] == "summary"
    with pytest.raises(SwitchError, match="discovered arguments"):
        room.operation("create_room_document", {"made_up_field": "not sent"}, connected=True)


def test_probe_requires_matching_agent_nonce_reply() -> None:
    bridge = Bridge()
    receipt = client(bridge).probe("red-team", "red-agent", timeout=1)
    assert receipt["verified"] and receipt["reply_id"] == "agent-reply"
    assert receipt["target_agent_id"] == "red-agent"


def test_preflight_file_alone_cannot_claim_a_live_exchange(tmp_path: Path) -> None:
    bridge = Bridge()
    room = client(bridge)
    receipt = room.probe("red-team", "red-agent", timeout=1)
    path = tmp_path / "probe.json"
    path.write_text(json.dumps(receipt))
    verify_preflights([path], room, {"red-team"})
    bridge.timeline = []
    with pytest.raises(SwitchError, match="actual room timeline"):
        verify_preflights([path], room, {"red-team"})


def test_probe_rejects_another_senders_reply(monkeypatch: pytest.MonkeyPatch) -> None:
    bridge = Bridge()
    bridge.reply_sender = "someone-else"
    ticks = iter([0.0, 0.0, 1.0, 2.0])
    monkeypatch.setattr("nope_switch.transport.time.monotonic", lambda: next(ticks))
    monkeypatch.setattr("nope_switch.transport.time.sleep", lambda _: None)
    with pytest.raises(SwitchError, match="UNVERIFIED"):
        client(bridge).probe("red-team", "red-agent", timeout=0.1)


def test_discovery_cannot_claim_live_without_roundtrip() -> None:
    report = discover(client(Bridge()), settings(), "nope-never-again")
    assert report["status"] == "BLOCKED"
    assert report["room"]["id"] == "actual-room"
    assert report["room_url"] is None  # never invent the platform's URL
    assert report["milestones"]["mattermost_bridge_connected"]


def test_roundtrip_requires_observed_source_and_reply() -> None:
    bridge = Bridge()
    report = roundtrip(client(bridge), settings(), "nope-never-again", "teach-id")
    assert report["status"] == "LIVE"  # protocol-double assertion, not a live deployment claim
    assert report["source_message"]["author_id"] == "developer"
    assert report["observed_reply"]["id"] == "posted-event"
    with pytest.raises(SwitchError, match="was not observed"):
        roundtrip(client(Bridge()), settings(), "nope-never-again", "invented-id")


def test_receive_does_not_execute_chat_approval() -> None:
    bridge = Bridge()
    requests = receive(client(bridge), "nope")
    assert [r["command"] for r in requests] == ["teach", "challenge"]
    assert requests[0]["message_id"] == "teach-id"
    assert all("/approve" not in request.url.path for request in bridge.calls)


def test_disabled_configuration_is_blocked_without_network(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("NOPE_SWITCH_ENABLED", raising=False)
    output = tmp_path / "status.json"
    assert run(parser().parse_args(["discover", "--output", str(output)])) == 2
    assert json.loads(output.read_text())["status"] == "BLOCKED"


def test_failure_and_document_preserve_teach_link_and_approver() -> None:
    message = failure_message(scan(), ledger())
    assert "SCAR-001" in message and "https://chat.example/teach" in message
    assert "security-reviewer" in message and "src/auth.ts:7" in message
    assert "advisory" in scar_document(ledger())
    assert "not cryptographically signed" in scar_document(ledger())
    wrong = scan()
    wrong["results"][0]["extra"]["metadata"]["revision_id"] = "other-revision"
    with pytest.raises(ValueError, match="different revisions"):
        failure_message(wrong, ledger())
    data = ledger()
    data["decisions"] = data["decisions"][1:]
    with pytest.raises(ValueError, match="teach message URL"):
        failure_message(scan(), data)


@pytest.mark.parametrize("scan_exit", [0, 1, 3, 42])
def test_room_delivery_never_changes_scan_exit(
    scan_exit: int, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import subprocess

    output = tmp_path / "ping.json"
    monkeypatch.setattr(
        "nope_switch.cli.subprocess.run",
        lambda *a, **kw: subprocess.CompletedProcess([], scan_exit),
    )
    monkeypatch.setattr("nope_switch.cli.provenance", lambda *a: ledger())
    output.with_suffix(".scan.json").write_text(json.dumps(scan()))
    monkeypatch.setattr(
        SwitchClient,
        "from_env",
        classmethod(lambda cls, **kw: (_ for _ in ()).throw(SwitchError("offline"))),
    )
    assert run(parser().parse_args(["scan-bad", "--post", "--output", str(output)])) == scan_exit
    if scan_exit == 42:
        assert json.loads(output.read_text())["delivery"] == "failed"
    else:
        assert not output.exists()


def test_compliance_uses_five_pairs_and_rejects_contamination(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    trials = []
    for pair in range(5):
        for condition in ("without_scar", "with_scar"):
            path = tmp_path / f"{condition}-{pair}.ts"
            path.write_text("safe();" if condition == "with_scar" else "unsafe();")
            trials.append(
                {
                    "pair": str(pair),
                    "condition": condition,
                    "room_id": f"{condition}-{pair}",
                    "response_url": f"https://chat.example/{condition}/{pair}",
                    "code_path": str(path),
                    "document_id": "actual-doc" if condition == "with_scar" else None,
                    "task_completed": True,
                }
            )
    payload: dict[str, Any] = {
        "agent": "dev-agent",
        "model": "test-double",
        "prompt": "Identical task",
        "trials": trials,
    }
    manifest = tmp_path / "manifest.json"
    manifest.write_text(json.dumps(payload))

    def check(
        self: RuleLab, rule: str, bad: list[Any], good: list[tuple[str, str]], *args: Any
    ) -> CandidateResult:
        hits = {name: int("unsafe();" in code) for name, code in good}
        return CandidateResult(not any(hits.values()), {}, hits, [], [])

    monkeypatch.setattr(RuleLab, "validate", check)
    rule = tmp_path / "rule.yml"
    rule.write_text("test-double")
    report = compliance(manifest, rule)
    assert report["summary"]["without_scar"]["attempts"] == 5
    assert report["summary"]["with_scar"]["compliance_rate"] == 1.0
    assert report["summary"]["without_scar"]["compliance_rate"] == 0.0
    payload["trials"][1]["room_id"] = payload["trials"][0]["room_id"]
    with pytest.raises(ValidationError, match="fresh room"):
        Experiment.model_validate(payload)


def test_console_credentials_are_reused_in_memory_without_provider_login(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    path = tmp_path / "existing-console-credentials.json"
    path.write_text(
        json.dumps(
            {
                "env": {
                    "SWITCH_API_ENDPOINT": "https://actual.example",
                    "SWITCH_API_TOKEN": "private-test-token",
                    "SWITCH_AGENT_ID": "real-agent",
                },
                "providerLogin": "not-needed",
            }
        )
    )
    for key in (
        "NOPE_SWITCH_BASE_URL",
        "SWITCH_API_ENDPOINT",
        "SWITCH_API_TOKEN",
        "SWITCH_AGENT_ID",
        "NOPE_SWITCH_ENABLED",
    ):
        monkeypatch.delenv(key, raising=False)
    load_credentials(path)
    config = RoomSettings.from_env()
    assert config.enabled and config.base_url == "https://actual.example"
    assert "private-test-token" not in capsys.readouterr().out
    assert json.loads(path.read_text())["providerLogin"] == "not-needed"


def proposal() -> dict[str, Any]:
    data = ledger()
    data["scar"]["status"] = "approved"
    data["scar"].update({"repository": "acme/service", "scope": "src/"})
    revision = data["revisions"][0]
    revision.update(
        {
            "state": "approved",
            "sequence": 1,
            "author": "api-key:agent:author",
            "adversary": "api-key:agent:challenger",
            "report": {
                "replay": {"passed": True, "errors": []},
                "candidate": {"passed": True},
                "regression": {"passed": True},
            },
            "challenge": {
                "bad_examples": [{"name": "bad.ts", "content": "bad();"}],
                "good_examples": [{"name": "good.ts", "content": "safe();"}],
                "metrics": {
                    "passed": True,
                    "detections": 6,
                    "misses": 0,
                    "false_positives": 0,
                    "errors": [],
                },
            },
        }
    )
    data["revisions"][0]["evidence_sha256"] = "a" * 64
    binding = {"request_id": "approval-exact", "revision_id": "rev-approved",
               "evidence_sha256": "a" * 64, "repository": "acme/service", "scope": "src/"}
    data["decisions"][-1]["detail"].update(binding)
    data["decisions"][-1]["actor"] = "api-key:approver:authenticated-identity"
    data["decisions"].insert(-1, {"id": "approval-exact", "action": "scar.approval_requested",
                                "detail": dict(binding)})
    return data


def test_pr_requires_latest_revision_and_rbac_approval() -> None:
    data = proposal()
    assert "security-reviewer" in description(data)
    data["decisions"][-1]["actor"] = "chat:someone-said-approved"
    with pytest.raises(ValueError, match="authenticated"):
        approved_proposal(data)
    data = proposal()
    data["revisions"][0]["challenge"]["metrics"]["passed"] = False
    with pytest.raises(ValueError, match="independent challenge"):
        approved_proposal(data)


@pytest.mark.parametrize("field,value", [
    ("evidence_sha256", "0" * 64), ("repository", "other/service"), ("scope", "changed/"),
])
def test_pr_rejects_changed_approval_binding(field: str, value: str) -> None:
    data = proposal()
    data["decisions"][-1]["detail"][field] = value
    with pytest.raises(ValueError, match="evidence hash, repository and scope"):
        approved_proposal(data)


def test_pr_checks_actual_committed_rule_before_external_write(monkeypatch: pytest.MonkeyPatch) -> None:
    import hashlib
    import subprocess

    from nope_switch.pull_request import verify_pr_tree

    rule = "rules: []\n"
    repository = "acme/service"

    def command(args: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        if args[0] == "gh":
            value = repository
        elif args[-1] == "HEAD:config/.semgrep/nope-active.yml":
            value = rule
        elif args[-1] == "HEAD:.github/workflows/nope-enforce.yml":
            value = "jobs:\n  policy:\n    name: NOPE / policy\n"
        else:
            value = "committed regression artifact"
        return subprocess.CompletedProcess(args, 0, stdout=value)

    monkeypatch.setattr("nope_switch.pull_request.subprocess.run", command)
    revision = {"rule_sha256": hashlib.sha256(rule.encode()).hexdigest()}
    verify_pr_tree(Path.cwd(), revision, repository)
    with pytest.raises(ValueError, match="repository scope"):
        verify_pr_tree(Path.cwd(), revision, "another/repository")
    revision["rule_sha256"] = "0" * 64
    with pytest.raises(ValueError, match="exact approved rule hash"):
        verify_pr_tree(Path.cwd(), revision, repository)


def test_invalid_operation_registry_is_a_controlled_error() -> None:
    room = SwitchClient("https://switch.example", "nope", "test-key", "room",
                        client=httpx.Client(transport=httpx.MockTransport(
                            lambda request: httpx.Response(200, json={"operations": None}))))
    with pytest.raises(SwitchError, match="invalid operation registry"):
        room.operation("list_rooms", {})
    room.close()


def test_roundtrip_rejects_a_reply_from_another_sender(monkeypatch: pytest.MonkeyPatch) -> None:
    bridge = Bridge()
    room = client(bridge)
    bridge.timeline.append({"id": "forged-reply", "sender": "another-agent", "body": "not nope"})
    monkeypatch.setattr(room, "post", lambda content: {"ok": True, "event_id": "forged-reply"})
    monkeypatch.setattr("nope_switch.live.time.sleep", lambda _: None)
    with pytest.raises(SwitchError, match="reply was not observed"):
        roundtrip(room, settings(), "nope-never-again", "teach-id")


def test_live_document_cannot_use_local_approval_artifact() -> None:
    args = parser().parse_args(["document", "1", "--provenance", "local.json", "--post"])
    with pytest.raises(ValueError, match="canonical core provenance"):
        run(args)


def test_pr_rejects_an_unpushed_commit(monkeypatch: pytest.MonkeyPatch) -> None:
    import subprocess

    from nope_switch.pull_request import verify_published_branch

    def command(args: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(args, 0, stdout="local-sha" if args[0] == "git" else "older-remote-sha")

    monkeypatch.setattr("nope_switch.pull_request.subprocess.run", command)
    with pytest.raises(ValueError, match="Push the reviewed commit"):
        verify_published_branch(Path.cwd(), "acme/service", "nope/scar-001")


def test_live_publication_uses_immutable_workbench_corpus_and_original_room() -> None:
    data = proposal()
    first = json.loads(json.dumps(data["revisions"][0]))
    first["id"] = "naive-id"
    first["challenge"]["metrics"].update({"passed": False, "detections": 0, "misses": 6})
    data["revisions"].append(first)
    report = courtroom_from_ledger(data, "naive-id", "rev-approved")
    assert report["demonstrated"] and report["evidence_source"] == "nope-core HTTP workbench"
    first["challenge"]["bad_examples"][0]["content"] = "different();"
    with pytest.raises(ValueError, match="exact same corpus"):
        courtroom_from_ledger(data, "naive-id", "rev-approved")
    data["decisions"][0]["detail"]["source_message"] = {"room_id": "original-room"}
    verify_room_source(data, "original-room")
    with pytest.raises(ValueError, match="destination"):
        verify_room_source(data, "other-room")


def test_source_message_metadata_survives_core_proposal_audit() -> None:
    from fastapi.testclient import TestClient
    from nope_core.main import app

    with TestClient(app) as http:
        payload = {
            "title": "Never expose credentials again",
            "incident_summary": "INC-014 credential logs were exposed",
            "invariant": "Never log authorization headers",
            "rationale": "Logs are widely copied and retained",
            "remediation": "Use a correlation identifier",
            "repository": "acme/service",
            "scope": "src/",
            "origin": "INC-014",
            "proposed_by": "nope",
            "teach_message_url": "https://actual.example/message/teach",
            "source_message": {
                "room_id": "actual-room",
                "message_id": "real-message",
                "author_id": "real-author",
                "author_name": "Developer",
            },
        }
        created = http.post("/v1/scars", headers={"X-NOPE-Key": "agent"}, json=payload)
        assert created.status_code == 201
        evidence = http.get(
            f"/v1/scars/{created.json()['number']}/provenance", headers={"X-NOPE-Key": "agent"}
        ).json()
        proposed = next(e for e in evidence["decisions"] if e["action"] == "scar.proposed")
        assert proposed["detail"]["source_message"] == payload["source_message"]
        assert proposed["detail"]["teach_message_url"] == payload["teach_message_url"]
        denied = http.post(
            f"/v1/scars/{created.json()['number']}/approve",
            headers={"X-NOPE-Key": "agent"},
            json={"approver": "chat says approved", "reason": "A message is not authorization"},
        )
        assert denied.status_code == 403
