from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Any
from urllib.parse import urljoin

import httpx
from nope_core.scan_report import checked_report


def escape_property(value: Any) -> str:
    """Escape property values for GitHub Actions workflow commands."""
    return (
        str(value)
        .replace("%", "%25")
        .replace("\r", "%0D")
        .replace("\n", "%0A")
        .replace(":", "%3A")
        .replace(",", "%2C")
    )


def escape_data(value: Any) -> str:
    """Escape message body for GitHub Actions workflow commands."""
    return (
        str(value)
        .replace("%", "%25")
        .replace("\r", "%0D")
        .replace("\n", "%0A")
    )


def escape_md_cell(value: Any) -> str:
    """Escape pipes and newlines for Markdown table cells."""
    return str(value).replace("|", "\\|").replace("\r\n", "<br>").replace("\n", "<br>").replace("\r", "<br>")


def parse_scar_number(scar_str: str) -> int | None:
    match = re.search(r"\d+", scar_str)
    return int(match.group()) if match else None


def get_git_info() -> tuple[str, str]:
    repo = os.getenv("GITHUB_REPOSITORY")
    if not repo:
        try:
            out = subprocess.check_output(
                ["git", "config", "--get", "remote.origin.url"],
                text=True,
                stderr=subprocess.DEVNULL,
            ).strip()
            match = re.search(r"[:/]([A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+?)(?:\.git)?$", out)
            if match:
                repo = match.group(1)
        except Exception:
            pass
    repo = repo or "workspace/repository"

    sha = os.getenv("GITHUB_SHA")
    if not sha or not re.match(r"^[0-9a-f]{7,40}$", sha):
        try:
            sha = subprocess.check_output(
                ["git", "rev-parse", "HEAD"],
                text=True,
                stderr=subprocess.DEVNULL,
            ).strip()
        except Exception:
            sha = "0000000000000000000000000000000000000000"
    return repo, sha


def get_check_url(repo: str, sha: str) -> str:
    server_url = os.getenv("GITHUB_SERVER_URL", "https://github.com")
    run_id = os.getenv("GITHUB_RUN_ID")
    if run_id:
        return f"{server_url}/{repo}/actions/runs/{run_id}"
    return os.getenv("CI_CHECK_URL", f"https://ci.local/build/{sha[:8]}")


def report_failure_to_api(
    base_url: str,
    ci_key: str,
    repo: str,
    sha: str,
    scar_number: int,
    check_url: str,
    revision_id: str | None = None,
) -> dict[str, Any] | None:
    headers = {"X-NOPE-Key": ci_key}
    payload = {
        "repository": repo,
        "sha": sha,
        "scar_number": scar_number,
        "check_url": check_url,
        "revision_id": revision_id,
    }
    try:
        with httpx.Client(base_url=base_url, timeout=10.0, headers=headers) as client:
            resp = client.post("/v1/ci/failure", json=payload)
            if resp.status_code == 200:
                result = resp.json()
                if isinstance(result, dict):
                    return result
            print(
                f"[NOPE] Notice: API returned status {resp.status_code} for Scar #{scar_number}: {resp.text}",
                file=sys.stderr,
            )
    except httpx.HTTPError as exc:
        print(f"[NOPE] Notice: Could not reach nope-core at {base_url} ({exc}). Using offline fallback metadata.", file=sys.stderr)
    except Exception as exc:
        print(f"[NOPE] Notice: Unexpected error connecting to {base_url}: {exc}", file=sys.stderr)
    return None


def write_github_step_summary(
    summary_path: Path,
    scar_data: dict[int, dict[str, Any]],
    findings_by_scar: dict[int, list[dict[str, Any]]],
    errors: list[dict[str, Any]] | None = None,
) -> None:
    lines: list[str] = [
        "## 🚨 NOPE Policy Violations Detected",
        "",
        "The following changes violate active Never-Again safeguards committed to this repository:",
        "",
    ]
    for scar_num, data in scar_data.items():
        title = data.get("title", f"Scar #{scar_num}")
        why = data.get("why", "Unspecified rationale")
        fix = data.get("fix", "No remediation instructions provided")
        incident = data.get("incident")
        incident_md = f"[{incident}]({incident})" if incident and incident.startswith("http") else str(incident or "N/A")

        lines.extend([
            f"### Scar #{scar_num:03d} — {title}",
            f"> **Incident Origin:** {incident_md}",
            "",
            "#### Why this policy exists",
            f"{why}",
            "",
            "#### Required Remediation",
            f"{fix}",
            "",
            " | ".join(f"[{label}]({data[key]})" for key, label in
                       (("approved_rule", "Approved rule"), ("tests", "Tests and replay"), ("history", "Decision history"))
                       if data.get(key)),
            "",
            "| File | Location | Rule |",
            "|---|---|---|",
        ])
        for finding in findings_by_scar.get(scar_num, []):
            path = escape_md_cell(finding.get("path", "unknown"))
            start = finding.get("start", {})
            line = start.get("line", 1)
            col = start.get("col", 1)
            rule = escape_md_cell(finding.get("check_id", "semgrep"))
            lines.append(f"| `{path}` | Line {line}:{col} | `{rule}` |")
        lines.append("")

    if errors:
        lines.extend([
            "### ⚠️ Semgrep Scan Errors",
            "",
            "Semgrep reported scanner or rule errors during evaluation:",
            "",
        ])
        for err in errors:
            err_msg = escape_md_cell(err.get("message") or err.get("long_msg") or str(err))
            err_path = err.get("path")
            path_str = f" in `{escape_md_cell(err_path)}`" if err_path else ""
            lines.append(f"- **Error**{path_str}: {err_msg}")
        lines.append("")

    try:
        with summary_path.open("a", encoding="utf-8") as f:
            f.write("\n".join(lines) + "\n")
    except Exception as exc:
        print(f"[NOPE] Warning: Unable to write to GITHUB_STEP_SUMMARY: {exc}", file=sys.stderr)


def process_scan_file(
    scan_json_path: Path,
    base_url: str | None = None,
    ci_key: str | None = None,
    fail_closed: bool = True,
) -> int:
    if not scan_json_path.is_file():
        print(f"[NOPE] Error: Scan file not found at {scan_json_path}", file=sys.stderr)
        return 1

    try:
        content = scan_json_path.read_text(encoding="utf-8")
        raw = checked_report(json.loads(content))
    except Exception as exc:
        print(f"[NOPE] Error: Invalid JSON in {scan_json_path}: {exc}", file=sys.stderr)
        return 1

    results: list[dict[str, Any]] = raw.get("results", [])
    errors: list[dict[str, Any]] = raw.get("errors", [])

    # If both results and errors are empty, the scan was completely clean
    if not results and not errors:
        print("NOPE: no Scar policy violations.")
        return 0

    # Handle scan errors when there are no rule violation findings
    if not results and errors:
        print("\n" + "=" * 80)
        print("⚠️  SEMGREP SCAN ERRORS DETECTED")
        print("=" * 80)
        for err in errors:
            err_msg = err.get("message") or err.get("long_msg") or str(err)
            err_path = err.get("path")
            loc = f" in {err_path}" if err_path else ""
            print(f"  • [Error]{loc}: {err_msg}")
            if os.getenv("GITHUB_ACTIONS") == "true":
                loc_prop = f"file={escape_property(err_path)}," if err_path else ""
                print(
                    f"::error {loc_prop}title={escape_property('Semgrep Scan Error')}::{escape_data(err_msg)}"
                )
        print("=" * 80)

        summary_env = os.getenv("GITHUB_STEP_SUMMARY")
        if summary_env:
            write_github_step_summary(Path(summary_env), {}, {}, errors=errors)

        if fail_closed:
            print("[NOPE] Error: Semgrep encountered scan errors. Failing closed under NOPE_FAIL_CLOSED=true.", file=sys.stderr)
            return 1

        print(
            "[NOPE] ⚠️  BREAK-GLASS WARNING: Semgrep reported scan errors, but NOPE_FAIL_CLOSED=false allowed build to proceed.",
            file=sys.stderr,
        )
        if os.getenv("GITHUB_ACTIONS") == "true":
            print(
                "::warning title=NOPE Break-Glass::Semgrep scan errors detected, but NOPE_FAIL_CLOSED=false allowed build to proceed."
            )
        return 0

    resolved_base_url: str = base_url or os.getenv("NOPE_BASE_URL") or "http://localhost:8010"
    resolved_ci_key: str = ci_key or os.getenv("NOPE_CI_KEY") or "ci-change-me"
    repo, sha = get_git_info()
    check_url = get_check_url(repo, sha)

    # Group findings by scar number
    findings_by_scar: dict[int, list[dict[str, Any]]] = {}
    fallback_metadata: dict[int, dict[str, Any]] = {}

    for finding in results:
        extra = finding.get("extra", {})
        metadata = extra.get("metadata", {})
        scar_raw = str(metadata.get("scar", ""))
        scar_num = parse_scar_number(scar_raw) or 1

        findings_by_scar.setdefault(scar_num, []).append(finding)
        if scar_num not in fallback_metadata:
            fallback_metadata[scar_num] = {
                "scar_number": scar_num,
                "title": f"Scar #{scar_num:03d}",
                "why": extra.get("message", "Violation of Never-Again invariant."),
                "fix": metadata.get("remediation", "Update code to comply with the policy."),
                "incident": metadata.get("incident", "Historical incident"),
                **{key: metadata.get(key) for key in ("revision_id", "approved_rule", "tests", "history")},
            }

    # Query API or use fallback for each Scar
    scar_data: dict[int, dict[str, Any]] = {}
    api_connected = False

    for scar_num in findings_by_scar:
        api_result = report_failure_to_api(resolved_base_url, resolved_ci_key, repo, sha, scar_num, check_url,
                                           fallback_metadata[scar_num].get("revision_id"))
        if api_result:
            scar_data[scar_num] = api_result
            api_connected = True
        else:
            scar_data[scar_num] = fallback_metadata[scar_num]
        for key in ("incident", "approved_rule", "tests", "history"):
            value = scar_data[scar_num].get(key)
            if isinstance(value, str) and value.startswith("/"):
                scar_data[scar_num][key] = urljoin(resolved_base_url, value)
            elif isinstance(value, str) and "/" in value and not value.startswith(("http://", "https://")):
                server = os.getenv("GITHUB_SERVER_URL", "https://github.com")
                scar_data[scar_num][key] = f"{server}/{repo}/blob/{sha}/{value}"

    # Console Output Banner
    print("\n" + "=" * 80)
    print("🚨 NOPE POLICY VIOLATIONS DETECTED")
    print("=" * 80)

    for scar_num, data in scar_data.items():
        title = data.get("title", f"Scar #{scar_num}")
        why = data.get("why", "")
        fix = data.get("fix", "")
        incident = data.get("incident", "N/A")
        items = findings_by_scar.get(scar_num, [])

        print(f"\nScar #{scar_num:03d} — {title}")
        print(f"Incident:    {incident}")
        print(f"Why:         {why}")
        print(f"Remediation: {fix}")
        for key, label in (("approved_rule", "Approved rule"), ("tests", "Tests and replay"), ("history", "Decision history")):
            if data.get(key):
                print(f"{label}: {data[key]}")
        print(f"\nViolations ({len(items)}):")
        for finding in items:
            path = finding.get("path", "unknown")
            start = finding.get("start", {})
            line = start.get("line", 1)
            col = start.get("col", 1)
            msg = finding.get("extra", {}).get("message", "")
            print(f"  • {path}:{line}:{col} -> {msg}")

            # Emit GitHub Actions Workflow annotation with proper escaping
            if os.getenv("GITHUB_ACTIONS") == "true":
                file_prop = escape_property(path)
                title_prop = escape_property(f"NOPE Scar #{scar_num:03d}")
                msg_data = escape_data(msg)
                print(
                    f"::error file={file_prop},line={line},col={col},title={title_prop}::{msg_data}"
                )

    if errors:
        print("\n" + "-" * 80)
        print("Additional Semgrep Scan Errors:")
        for err in errors:
            err_msg = err.get("message") or err.get("long_msg") or str(err)
            print(f"  • {err_msg}")
        print("-" * 80)

    print("\n" + "=" * 80)

    # Write Step Summary if running in GitHub Actions
    summary_env = os.getenv("GITHUB_STEP_SUMMARY")
    if summary_env:
        write_github_step_summary(Path(summary_env), scar_data, findings_by_scar, errors=errors)

    if not api_connected:
        print("[NOPE] Notice: Policy server unreachable. Proceeded with offline fallback metadata.", file=sys.stderr)

    return 1


def main() -> None:
    parser = argparse.ArgumentParser(prog="nope-report", description="Report NOPE CI enforcement findings")
    parser.add_argument("scan_json", type=Path, help="Semgrep JSON results file")
    parser.add_argument("--base-url", default=None, help="Base URL of nope-core service")
    parser.add_argument("--ci-key", default=None, help="CI API key for nope-core")
    parser.add_argument(
        "--fail-closed",
        action="store_true",
        default=os.getenv("NOPE_FAIL_CLOSED", "true").lower() == "true",
        help="Fail build on rule violations even if nope-core API is unreachable",
    )
    args = parser.parse_args()

    exit_code = process_scan_file(
        scan_json_path=args.scan_json,
        base_url=args.base_url,
        ci_key=args.ci_key,
        fail_closed=args.fail_closed,
    )
    sys.exit(exit_code)


if __name__ == "__main__":
    main()
