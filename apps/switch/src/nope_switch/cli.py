"""Explicit room actions and local evidence collection, outside nope-core."""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import httpx
from nope_core.paths import data_root, project_root
from nope_core.rule_lab import RuleLabError

from nope_switch.config import RoomSettings
from nope_switch.console import load_credentials
from nope_switch.evidence import (
    compliance,
    courtroom,
    courtroom_from_ledger,
    courtroom_message,
    failure_message,
    scar_document,
    verify_room_source,
)
from nope_switch.live import discover, entries, receive, roundtrip
from nope_switch.pull_request import (
    approved_proposal,
    description,
    verify_pr_tree,
    verify_published_branch,
)
from nope_switch.transport import SwitchClient, SwitchError

ROOT = project_root()
DATA = data_root()


def save(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2), encoding="utf-8")


def provenance(scar: str, path: Path | None) -> dict[str, Any]:
    if path:
        data = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            raise ValueError("Provenance must be a JSON object")
        return data
    base = os.getenv("NOPE_BASE_URL", "http://localhost:8010").rstrip("/")
    key = os.getenv("NOPE_AGENT_KEY", "agent-change-me")
    with httpx.Client(timeout=15, headers={"X-NOPE-Key": key}) as client:
        response = client.get(f"{base}/v1/scars/{scar}/provenance")
        response.raise_for_status()
        data = response.json()
        if not isinstance(data, dict):
            raise ValueError("Provenance must be a JSON object")
        return data


def verify_preflights(paths: list[Path], client: SwitchClient, names: set[str]) -> None:
    verified = set()
    for path in paths:
        receipt = json.loads(path.read_text(encoding="utf-8"))
        observed = datetime.fromisoformat(receipt["observed_at"])
        if observed.tzinfo is None:
            raise SwitchError("Preflight observation time must include its timezone")
        if (
            receipt.get("verified") is not True
            or receipt.get("room_id") != client.room_id
            or receipt.get("source_agent_id") != client.agent_id
            or not receipt.get("reply_id")
            or not timedelta(0) <= datetime.now(UTC) - observed <= timedelta(hours=1)
        ):
            raise SwitchError(
                "Addressing preflight must be a recent observed reply for this source agent and room"
            )
        context = client.operation("read_context", {"room_id": client.room_id, "limit": 100})
        timeline = entries(context)
        request_id = receipt.get("request", {}).get("event_id")
        request_seen = any(
            entry.get("id") == request_id and entry.get("sender") == client.agent_id
            for entry in timeline
        )
        reply_seen = any(
            entry.get("id") == receipt["reply_id"]
            and entry.get("sender") == receipt.get("target_agent_id")
            and entry.get("body", "").strip() == f"NOPE-ACK {receipt.get('nonce')}"
            for entry in timeline
        )
        if not request_seen or not reply_seen:
            raise SwitchError("The saved preflight is not corroborated by the actual room timeline")
        verified.add(receipt["target_name"])
    if not names <= verified:
        raise SwitchError(
            "Run and save addressing probes for both red team and reviewer before the live courtroom"
        )


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(
        prog="nope-room", description="Optional Switch demos; CI remains authoritative"
    )
    result.add_argument(
        "--console-credentials",
        type=Path,
        help="Reuse an existing Console agent credential file in memory; never copy or log its keys",
    )
    sub = result.add_subparsers(dest="command", required=True)
    discovery = sub.add_parser(
        "discover",
        help="Discover the actual room, Mattermost bridge, and agent; never asserts LIVE",
    )
    discovery.add_argument("--room-name", default="nope-never-again")
    discovery.add_argument("--output", type=Path, default=DATA / "switch-status.json")
    incoming = sub.add_parser(
        "receive", help="Record real teach/challenge messages using Console's existing identity"
    )
    incoming.add_argument("--since")
    incoming.add_argument("--output", type=Path, default=DATA / "switch-requests.json")
    trip = sub.add_parser(
        "roundtrip", help="Verify an actual room request and a persisted @nope reply"
    )
    trip.add_argument("--source-message-id", required=True)
    trip.add_argument("--room-name", default="nope-never-again")
    trip.add_argument("--output", type=Path, default=DATA / "switch-status.json")
    probe = sub.add_parser("probe", help="Test real agent-to-agent addressing with a nonce reply")
    probe.add_argument("--target", required=True)
    probe.add_argument(
        "--target-id", required=True, help="Target's sender identity in the room timeline"
    )
    probe.add_argument("--timeout", type=float, default=45)
    probe.add_argument("--output", type=Path, required=True)
    court = sub.add_parser(
        "courtroom", help="Run naive and taint candidates against the same real fixtures"
    )
    court.add_argument("--naive", type=Path, default=ROOT / "switch/courtroom/naive.yml")
    court.add_argument("--taint", type=Path, default=ROOT / "config/.semgrep/nope-active.yml")
    court.add_argument(
        "--challenge", type=Path, default=ROOT / "demo-app/fixtures/adversarial-challenge.json"
    )
    court.add_argument(
        "--challenge-response-url", help="Room link to the red team's fresh fixture submission"
    )
    court.add_argument("--scar", help="Required for live publication from the core HTTP workbench")
    court.add_argument("--naive-revision")
    court.add_argument("--taint-revision")
    court.add_argument("--red-team", default="red-team")
    court.add_argument("--reviewer", default="nope-reviewer")
    court.add_argument("--preflight", type=Path, nargs="*", default=[])
    court.add_argument("--post", action="store_true")
    court.add_argument("--output", type=Path, default=DATA / "courtroom.json")
    document = sub.add_parser("document", help="Export an approved Scar as advisory room context")
    document.add_argument("scar")
    document.add_argument("--provenance", type=Path)
    document.add_argument("--teach-url")
    document.add_argument("--post", action="store_true", help="Post the summary as a room message")
    document.add_argument(
        "--attach",
        action="store_true",
        help="Create a room document using the existing Console session",
    )
    document.add_argument("--output", type=Path, default=DATA / "scar-room.md")
    benchmark = sub.add_parser("compliance", help="Score at least five paired, real agent trials")
    benchmark.add_argument("--manifest", type=Path, required=True)
    benchmark.add_argument("--rule", type=Path, default=ROOT / "config/.semgrep/nope-active.yml")
    benchmark.add_argument("--output", type=Path, default=DATA / "compliance.json")
    scan = sub.add_parser(
        "scan-bad",
        help="Run the real demo scan; notify only after exit 42, preserving that exit code",
    )
    scan.add_argument("--scar", default="1")
    scan.add_argument("--provenance", type=Path)
    scan.add_argument("--teach-url")
    scan.add_argument("--post", action="store_true")
    scan.add_argument("--output", type=Path, default=DATA / "ci-room-ping.json")
    approval = sub.add_parser("request-approval", help="Publish the exact core approval request in its original room")
    approval.add_argument("scar")
    approval.add_argument("--revision", required=True)
    approval.add_argument("--output", type=Path, default=DATA / "approval-request.json")
    pr = sub.add_parser(
        "prepare-pr", help="Prepare a PR description only after canonical human approval"
    )
    pr.add_argument("scar")
    pr.add_argument("--head", help="Existing clean nope/scar-NNN branch, required for --create")
    pr.add_argument("--base", default="main")
    pr.add_argument(
        "--create",
        action="store_true",
        help="Create the GitHub PR with gh after checking approval and branch",
    )
    pr.add_argument("--output", type=Path, default=DATA / "scar-pr.md")
    return result


def run(args: argparse.Namespace) -> int:
    if args.console_credentials:
        load_credentials(args.console_credentials)
    client: SwitchClient | None = None
    if args.command == "request-approval":
        data = provenance(args.scar, None)
        client = SwitchClient.from_env()
        try:
            verify_room_source(data, client.room_id)
            base = os.getenv("NOPE_BASE_URL", "http://localhost:8010").rstrip("/")
            key = os.getenv("NOPE_AGENT_KEY", "agent-change-me")
            with httpx.Client(timeout=15, headers={"X-NOPE-Key": key}) as core:
                response = core.post(f"{base}/v1/scars/{args.scar}/approval-request",
                                     json={"revision_id": args.revision})
                response.raise_for_status()
                packet = response.json()
            # Persist the canonical request before attempting delivery. No approval is inferred.
            save(args.output, packet)
            metrics = packet["challenge_metrics"]
            message = (
                f"Human approval requested: SCAR-{data['scar']['number']:03d}\n"
                f"Candidate: {packet['revision_id']}\nRequest: {packet['request_id']}\n"
                f"Repository: {packet['repository']}\nScope: {packet['scope']}\n"
                f"Rule SHA-256: {packet['rule_sha256']}\n"
                f"Evidence SHA-256: {packet['evidence_sha256']}\n"
                f"Expires: {packet['expires_at']}\n"
                f"Counterfactual replay: {json.dumps(packet['report']['replay'], sort_keys=True)}\n"
                f"Historical regressions: {json.dumps(packet['report']['regression'], sort_keys=True)}\n"
                f"Independent challenge: {json.dumps(metrics, sort_keys=True)}\n"
                "An authorized human must submit this exact request through nope-core RBAC. "
                "Chat text does not authorize approval. No PR or enforcement activation has occurred."
            )
            receipt = client.post(message)
            save(args.output.with_suffix(".delivery.json"), receipt)
            print(f"Posted exact approval request; saved {args.output}")
        finally:
            client.close()
        return 0
    if args.command == "prepare-pr":
        data = provenance(args.scar, None)  # never trust a local artifact for authorization
        body = description(data)
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(body, encoding="utf-8")
        if args.create:
            import re

            match = re.fullmatch(r"nope/scar-0*(\d+)(?:[-/][A-Za-z0-9._-]+)?", args.head or "")
            if not match or int(match.group(1)) != data["scar"]["number"]:
                raise ValueError("PR creation requires a matching nope/scar-NNN branch")
            branch = subprocess.run(
                ["git", "branch", "--show-current"],
                capture_output=True,
                text=True,
                check=True,
                cwd=ROOT,
            ).stdout.strip()
            status = subprocess.run(
                ["git", "status", "--porcelain"],
                capture_output=True,
                text=True,
                check=True,
                cwd=ROOT,
            ).stdout.strip()
            if branch != args.head or status:
                raise ValueError(
                    "Commit the reviewed rule and fixtures on the selected branch before creating the PR"
                )
            revision, _ = approved_proposal(data)
            verify_pr_tree(ROOT, revision, data["scar"]["repository"])
            verify_published_branch(ROOT, data["scar"]["repository"], args.head)
            # Recheck canonical approval immediately before the external write.
            if description(provenance(args.scar, None)) != body:
                raise ValueError("Approval changed during preparation; review the current candidate")
            subprocess.run(
                [
                    "gh",
                    "pr",
                    "create",
                    "--repo",
                    data["scar"]["repository"],
                    "--head",
                    args.head,
                    "--base",
                    args.base,
                    "--title",
                    f"SCAR-{data['scar']['number']:03d}: {data['scar']['title']}",
                    "--body-file",
                    str(args.output.resolve()),
                ],
                check=True,
                cwd=ROOT,
            )
        print(f"Approved PR description saved to {args.output}")
        return 0
    if args.command in {"discover", "roundtrip", "receive"}:
        try:
            settings = RoomSettings.from_env()
            client = SwitchClient.from_env(require_room=args.command == "receive")
            if args.command == "receive":
                messages = receive(client, settings.agent_name, args.since)
                save(args.output, {"observed_messages": messages, "approvals_processed": False})
                print(
                    f"Observed {len(messages)} teach/challenge request(s); no chat approvals executed"
                )
                return 0
            report = (
                roundtrip(client, settings, args.room_name, args.source_message_id)
                if args.command == "roundtrip"
                else discover(client, settings, args.room_name)
            )
            save(args.output, report)
            print(json.dumps(report, indent=2))
            return 0 if report["status"] == "LIVE" else 2
        except SwitchError as exc:
            save(
                args.output,
                {
                    "status": "BLOCKED",
                    "reason": str(exc),
                    "checked_at": datetime.now(UTC).isoformat(),
                },
            )
            print(str(exc), file=sys.stderr)
            return 2
        finally:
            if client:
                client.close()
    if args.command == "compliance":
        report = compliance(args.manifest, args.rule)
        save(args.output, report)
        print(json.dumps(report["summary"], indent=2))
        return int(any(v["scanner_errors"] for v in report["summary"].values()))
    if args.command == "probe":
        if not 0 < args.timeout <= 55:
            raise ValueError("Probe timeout must be between 0 and 55 seconds")
        client = SwitchClient.from_env()
        try:
            receipt = client.probe(args.target, args.target_id, args.timeout)
            save(args.output, receipt)
            print(f"Observed reply from {args.target}; saved {args.output}")
        finally:
            client.close()
        return 0
    if args.command == "courtroom":
        client = None
        try:
            if args.post:
                if not args.challenge_response_url or not args.challenge_response_url.startswith(
                    ("http://", "https://")
                ):
                    raise ValueError(
                        "Live courtroom needs the red team's actual fixture-message URL"
                    )
                if not args.scar or not args.naive_revision or not args.taint_revision:
                    raise ValueError(
                        "Live publication needs --scar, --naive-revision, and --taint-revision from core CLI/HTTP validation"
                    )
                client = SwitchClient.from_env()
                verify_preflights(args.preflight, client, {args.red_team, args.reviewer})
                core_evidence = provenance(args.scar, None)
                verify_room_source(core_evidence, client.room_id)
                report = courtroom_from_ledger(
                    core_evidence, args.naive_revision, args.taint_revision
                )
            else:
                report = courtroom(
                    args.naive,
                    args.taint,
                    args.challenge,
                    ROOT / "demo-app/fixtures/bad-authorization-log.ts",
                    ROOT / "demo-app/fixtures/good-redacted-log.ts",
                )
            report["challenge_response_url"] = args.challenge_response_url
            report["connection_status"] = "LIVE" if client else "MOCK"
            report["delivery"] = []
            save(args.output, report)
            for label, candidate in report["candidates"].items():
                message = courtroom_message(label, candidate)
                print(message)
                if client:
                    report["delivery"].append(client.post(message))
                    save(args.output, report)
            if client:
                report["review_request"] = client.operation(
                    "send_targeted_message",
                    {
                        "target_names": [args.reviewer],
                        "body": "Review the two measured Rule Lab results and red-team fixtures. State which candidate should be rejected and why. Do not approve or activate a Scar.",
                    },
                    connected=True,
                )
                save(args.output, report)
            return 0 if report["demonstrated"] else 1
        finally:
            if client:
                client.close()
    if args.command == "document":
        if (args.post or args.attach) and (args.provenance or args.teach_url):
            raise ValueError("Live publication must use canonical core provenance and its original teach URL")
        data = provenance(args.scar, args.provenance)
        content = scar_document(data, args.teach_url)
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(content, encoding="utf-8")
        if args.post or args.attach:
            client = SwitchClient.from_env()
            receipt = {}
            try:
                verify_room_source(data, client.room_id)
                if args.attach:
                    receipt["document"] = client.create_document(
                        f"scar-{data['scar']['number']:03d}", content
                    )
                if args.post:
                    receipt["message"] = client.post(content)
                save(args.output.with_suffix(".receipt.json"), receipt)
            finally:
                client.close()
        print(f"Scar context saved to {args.output}; advisory guidance, enforced by CI")
        return 0
    if args.command == "scan-bad":
        scan_path = args.output.with_suffix(".scan.json")
        completed = subprocess.run(
            [sys.executable, "-m", "nope_core.demo", "scan-bad", "--report", str(scan_path)],
            check=False,
            cwd=ROOT,
        )
        if completed.returncode != 42:
            return completed.returncode
        receipt = {"scan_exit": 42, "delivery": "not_requested"}
        try:
            if args.post and (args.provenance or args.teach_url):
                raise ValueError("Live notification must use canonical core provenance and its original teach URL")
            data = provenance(args.scar, args.provenance)
            message = failure_message(
                json.loads(scan_path.read_text(encoding="utf-8")), data, args.teach_url
            )
            receipt["content"] = message
            print(message)
            if args.post:
                client = SwitchClient.from_env()
                try:
                    verify_room_source(data, client.room_id)
                    receipt["response"] = client.post(message)
                    receipt["delivery"] = "acknowledged"
                finally:
                    client.close()
        except (SwitchError, httpx.HTTPError, ValueError, KeyError, OSError) as exc:
            # A room-delivery failure must never turn a failing scan into a pass.
            receipt["delivery"] = "failed"
            receipt["error_type"] = type(exc).__name__
            print(
                "Room ping unavailable; the policy violation remains blocked (exit 42)",
                file=sys.stderr,
            )
        try:
            save(args.output, receipt)
        except OSError:
            print(
                "Could not save room-delivery evidence; the policy violation remains blocked (exit 42)",
                file=sys.stderr,
            )
        return 42
    raise ValueError("Unknown command")


def main() -> None:
    try:
        raise SystemExit(run(parser().parse_args()))
    except (
        SwitchError,
        RuleLabError,
        ValueError,
        KeyError,
        OSError,
        httpx.HTTPError,
        subprocess.SubprocessError,
    ) as exc:
        # Never include credential-bearing HTTP exceptions in user output.
        message = str(exc) if isinstance(exc, (SwitchError, ValueError)) else type(exc).__name__
        print(f"nope-room: {message}", file=sys.stderr)
        raise SystemExit(1) from None


if __name__ == "__main__":
    main()
