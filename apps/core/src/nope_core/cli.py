from __future__ import annotations

import argparse
import json
import os
import tempfile
from pathlib import Path
from typing import Any

import httpx
import yaml

BASE_URL = os.getenv("NOPE_BASE_URL", "http://localhost:8010")
DEFAULT_KEY = os.getenv("NOPE_AGENT_KEY", "agent-change-me")
APPROVER_KEY = os.getenv("NOPE_APPROVER_KEY", "approver-change-me")
ADMIN_KEY = os.getenv("NOPE_ADMIN_KEY", "admin-change-me")
CI_KEY = os.getenv("NOPE_CI_KEY", "ci-change-me")


def client(key: str | None = None) -> httpx.Client:
    headers = {"X-NOPE-Key": key or DEFAULT_KEY}
    return httpx.Client(base_url=BASE_URL, headers=headers, timeout=150)


def dump(response: httpx.Response) -> None:
    try:
        print(json.dumps(response.json(), indent=2, sort_keys=True))
    except json.JSONDecodeError:
        print(response.text)
    response.raise_for_status()


def read_structured_file(path: Path) -> str:
    if not path.is_file():
        raise SystemExit(f"Not a file: {path}")
    return path.read_text(encoding="utf-8")


def parse_examples(values: list[str]) -> list[dict[str, str]]:
    examples = []
    for value in values:
        if "=" not in value:
            raise SystemExit("Examples use NAME=PATH, for example bad-1=fixtures/bad.ts")
        name, path = value.split("=", 1)
        examples.append({"name": name, "content": read_structured_file(Path(path))})
    return examples


def rules_document(text: str) -> list[dict[str, Any]]:
    document = yaml.safe_load(text)
    if (not isinstance(document, dict) or not isinstance(document.get("rules"), list)
            or any(not isinstance(rule, dict) for rule in document["rules"])):
        raise ValueError("Active policy must contain an explicit rules list")
    return list(document["rules"])


def verify_rules_sync(rule_file: Path, base_url: str | None = None, key: str | None = None) -> int:
    target_url = (base_url or BASE_URL).rstrip("/") + "/v1/rules/active.yml"
    headers = {"X-NOPE-Key": key or CI_KEY}
    with httpx.Client(timeout=30) as http_client:
        try:
            resp = http_client.get(target_url, headers=headers)
            resp.raise_for_status()
        except Exception as exc:
            print(f"NOPE: Failed to fetch active rules from {target_url}: {exc}")
            return 1
        remote_yaml_str = resp.text

    if not rule_file.is_file():
        print(f"NOPE: Local rule file '{rule_file}' does not exist.")
        return 1

    local_yaml_str = rule_file.read_text(encoding="utf-8")
    try:
        remote_rules = rules_document(remote_yaml_str)
        local_rules = rules_document(local_yaml_str)
    except Exception as exc:
        print(f"NOPE: YAML parsing error: {exc}")
        return 1

    if remote_rules == local_rules:
        print(f"NOPE: Rule file '{rule_file}' is in sync with active rules ({len(local_rules)} rules).")
        return 0

    print(f"NOPE: Drift detected between '{rule_file}' and database active rules!")
    remote_ids = {r.get("id") for r in remote_rules if isinstance(r, dict)}
    local_ids = {r.get("id") for r in local_rules}

    missing_in_local = remote_ids - local_ids
    extra_in_local = local_ids - remote_ids
    if missing_in_local:
        print(f"  Missing locally (active in DB): {sorted(str(i) for i in missing_in_local)}")
    if extra_in_local:
        print(f"  Extra locally (not active in DB): {sorted(str(i) for i in extra_in_local)}")
    if not missing_in_local and not extra_in_local:
        print("  Rule IDs match but rule definitions or metadata differ.")
    return 1


def sync_rules_to_file(output_path: Path, base_url: str | None = None, key: str | None = None) -> int:
    target_url = (base_url or BASE_URL).rstrip("/") + "/v1/rules/active.yml"
    headers = {"X-NOPE-Key": key or CI_KEY}
    with httpx.Client(timeout=30) as http_client:
        try:
            resp = http_client.get(target_url, headers=headers)
            resp.raise_for_status()
        except Exception as exc:
            print(f"NOPE: Failed to fetch active rules from {target_url}: {exc}")
            return 1
        remote_yaml_str = resp.text

    temporary: Path | None = None
    try:
        rules_document(remote_yaml_str)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=output_path.parent,
                                         prefix=".nope-rules-", suffix=".tmp", delete=False) as stream:
            temporary = Path(stream.name)
            stream.write(remote_yaml_str)
        temporary.replace(output_path)
    except (OSError, ValueError, yaml.YAMLError) as exc:
        print(f"NOPE: Unable to sync valid policy: {exc}")
        return 1
    finally:
        if temporary:
            temporary.unlink(missing_ok=True)
    print(f"NOPE: Successfully synced active rules to '{output_path}'.")
    return 0


def main() -> None:
    parser = argparse.ArgumentParser(prog="nope", description="Operate the NOPE Scar Ledger")
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("health")
    sub.add_parser("scars")

    show = sub.add_parser("show")
    show.add_argument("scar", help="Scar ID or number")

    create = sub.add_parser("create", help="Create a proposed scar from a JSON file")
    create.add_argument("--data", type=Path, required=True, help="JSON payload matching POST /v1/scars")

    validate = sub.add_parser("validate", help="Validate an LLM-generated candidate rule")
    validate.add_argument("scar")
    validate.add_argument("--rule", type=Path, required=True)
    validate.add_argument("--bad", nargs="+", required=True, metavar="NAME=PATH")
    validate.add_argument("--good", nargs="*", default=[], metavar="NAME=PATH")
    validate.add_argument("--target", type=Path, default=None)
    validate.add_argument("--original", type=Path, required=True, help="Original incident's vulnerable code")
    validate.add_argument("--corrected", type=Path, required=True, help="Corrected incident code")

    adversarial = sub.add_parser("adversarial", help="Submit a separate agent's independent challenge")
    adversarial.add_argument("scar")
    adversarial.add_argument("--data", type=Path, required=True)

    provenance = sub.add_parser("provenance", help="Show incident, revisions, evidence and decisions")
    provenance.add_argument("scar")

    reject = sub.add_parser("reject", help="Reject a pending revision with a recorded decision")
    reject.add_argument("scar")
    reject.add_argument("--approver", required=True)
    reject.add_argument("--reason", required=True)

    request = sub.add_parser("request-approval", help="Record an exact evidence-bound approval request")
    request.add_argument("scar")
    request.add_argument("--revision", required=True)

    approve = sub.add_parser("approve")
    approve.add_argument("scar")
    approve.add_argument("--approver", required=True)
    approve.add_argument("--reason", required=True)
    approve.add_argument("--request", type=Path, required=True, help="Exact approval-request JSON reviewed by the human")

    activate = sub.add_parser("activate", help="BREAK-GLASS ONLY: Manually activate a scar bypassing GitOps PR merge")
    activate.add_argument("scar")
    activate.add_argument("--authorized-by", required=True, help="Administrator identity authorizing break-glass")
    activate.add_argument("--reason", required=True, help="Audited justification explaining why GitOps PR merge was bypassed")

    challenge = sub.add_parser("challenge", help="Request a narrowing or an expiring exception")
    challenge.add_argument("scar")
    challenge.add_argument("--requester", required=True)
    challenge.add_argument("--reason", required=True)
    challenge.add_argument("--proposed-rule", type=Path)
    challenge.add_argument("--bad", nargs="*", default=[], metavar="NAME=PATH")
    challenge.add_argument("--good", nargs="*", default=[], metavar="NAME=PATH")

    ci = sub.add_parser("ci-failure", help="Record a CI failure and receive its remediation")
    ci.add_argument("--repository", required=True)
    ci.add_argument("--sha", required=True)
    ci.add_argument("--scar-number", type=int, required=True)
    ci.add_argument("--check-url", required=True)
    ci.add_argument("--revision-id", help="Revision ID embedded in the scanned rule")

    report = sub.add_parser("report", help="Process and report Semgrep scan results")
    report.add_argument("scan_json", type=Path, help="Semgrep JSON results file")
    report.add_argument("--base-url", default=None, help="Base URL of nope-core service")
    report.add_argument("--ci-key", default=None, help="CI API key for nope-core")
    report.add_argument(
        "--fail-closed",
        action="store_true",
        default=os.getenv("NOPE_FAIL_CLOSED", "true").lower() == "true",
        help="Fail build on rule violations even if nope-core API is unreachable",
    )

    verify_sync = sub.add_parser("verify-sync", help="Verify local Semgrep rules are in sync with active database rules")
    verify_sync.add_argument("--rule-file", type=Path, default=Path("config/.semgrep/nope-active.yml"), help="Path to local rules YAML")
    verify_sync.add_argument("--base-url", default=None, help="Base URL of nope-core service")
    verify_sync.add_argument("--ci-key", default=None, help="API key for nope-core")

    sync_rules = sub.add_parser("sync-rules", help="Sync active rules from nope-core into local Semgrep rules file")
    sync_rules.add_argument("--output", type=Path, default=Path("config/.semgrep/nope-active.yml"), help="Destination path for active rules YAML")
    sync_rules.add_argument("--base-url", default=None, help="Base URL of nope-core service")
    sync_rules.add_argument("--ci-key", default=None, help="API key for nope-core")

    args = parser.parse_args()
    if args.command == "health":
        with client(None) as session:
            dump(session.get("/health", headers={}))
    elif args.command == "scars":
        with client() as session:
            dump(session.get("/v1/scars"))
    elif args.command == "show":
        with client() as session:
            dump(session.get(f"/v1/scars/{args.scar}"))
    elif args.command == "create":
        with client() as session:
            dump(session.post("/v1/scars", json=json.loads(args.data.read_text(encoding="utf-8"))))
    elif args.command == "validate":
        payload = {
            "rule_yaml": read_structured_file(args.rule),
            "bad_examples": parse_examples(args.bad),
            "good_examples": parse_examples(args.good),
            "target_path": str(args.target) if args.target else None,
            "original": {"name": args.original.name, "content": read_structured_file(args.original)},
            "corrected": {"name": args.corrected.name, "content": read_structured_file(args.corrected)},
        }
        with client() as session:
            dump(session.post(f"/v1/scars/{args.scar}/validate", json=payload))
    elif args.command == "adversarial":
        with client() as session:
            dump(session.post(f"/v1/scars/{args.scar}/adversarial", json=json.loads(read_structured_file(args.data))))
    elif args.command == "provenance":
        with client() as session:
            dump(session.get(f"/v1/scars/{args.scar}/provenance"))
    elif args.command == "reject":
        with client(APPROVER_KEY) as session:
            dump(session.post(f"/v1/scars/{args.scar}/reject", json={"approver": args.approver, "reason": args.reason}))
    elif args.command == "request-approval":
        with client() as session:
            dump(session.post(f"/v1/scars/{args.scar}/approval-request", json={"revision_id": args.revision}))
    elif args.command == "approve":
        with client(APPROVER_KEY) as session:
            dump(session.post(f"/v1/scars/{args.scar}/approve", json={**json.loads(args.request.read_text(encoding="utf-8-sig")), "approver": args.approver, "reason": args.reason}))
    elif args.command == "activate":
        with client(ADMIN_KEY) as session:
            dump(session.post(f"/v1/scars/{args.scar}/activate", json={
                "authorized_by": args.authorized_by,
                "reason": args.reason,
            }))
    elif args.command == "challenge":
        body = {
            "challenger": args.requester,
            "reason": args.reason,
            "requested_by": args.requester,
            "proposed_rule_yaml": read_structured_file(args.proposed_rule) if args.proposed_rule else None,
            "bad_examples": parse_examples(args.bad),
            "good_examples": parse_examples(args.good),
        }
        with client() as session:
            dump(session.post(f"/v1/scars/{args.scar}/challenge", json=body))
    elif args.command == "ci-failure":
        with client(CI_KEY) as session:
            dump(session.post("/v1/ci/failure", json={
                "repository": args.repository,
                "sha": args.sha,
                "scar_number": args.scar_number,
                "check_url": args.check_url,
                "revision_id": args.revision_id,
            }))
    elif args.command == "report":
        from nope_core.reporter import process_scan_file
        code = process_scan_file(
            scan_json_path=args.scan_json,
            base_url=args.base_url,
            ci_key=args.ci_key,
            fail_closed=args.fail_closed,
        )
        raise SystemExit(code)
    elif args.command == "verify-sync":
        code = verify_rules_sync(rule_file=args.rule_file, base_url=args.base_url, key=args.ci_key)
        raise SystemExit(code)
    elif args.command == "sync-rules":
        code = sync_rules_to_file(output_path=args.output, base_url=args.base_url, key=args.ci_key)
        raise SystemExit(code)

if __name__ == "__main__":
    main()
