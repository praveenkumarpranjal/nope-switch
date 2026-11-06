from __future__ import annotations

import argparse
import json
import os
from pathlib import Path

import httpx

BASE_URL = os.getenv("NOPE_BASE_URL", "http://localhost:8010")
DEFAULT_KEY = os.getenv("NOPE_AGENT_KEY", "agent-change-me")
APPROVER_KEY = os.getenv("NOPE_APPROVER_KEY", "approver-change-me")
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

    approve = sub.add_parser("approve")
    approve.add_argument("scar")
    approve.add_argument("--approver", required=True)
    approve.add_argument("--reason", required=True)

    activate = sub.add_parser("activate")
    activate.add_argument("scar")

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
        }
        with client() as session:
            dump(session.post(f"/v1/scars/{args.scar}/validate", json=payload))
    elif args.command == "approve":
        with client(APPROVER_KEY) as session:
            dump(session.post(f"/v1/scars/{args.scar}/approve", json={"approver": args.approver, "reason": args.reason}))
    elif args.command == "activate":
        with client(APPROVER_KEY) as session:
            dump(session.post(f"/v1/scars/{args.scar}/activate"))
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

if __name__ == "__main__":
    main()
