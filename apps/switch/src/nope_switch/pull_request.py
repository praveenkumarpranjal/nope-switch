"""Prepare a reviewable PR only from canonical, authorized workbench evidence."""

from __future__ import annotations

import hashlib
import subprocess
from pathlib import Path
from typing import Any

import yaml

from nope_switch.evidence import teach_url


def verify_pr_tree(root: Path, revision: dict[str, Any], repository: str) -> None:
    """The committed PR tree must actually contain the approved rule and CI gate."""
    def git_file(path: str) -> str:
        return subprocess.run(["git", "show", f"HEAD:{path}"], cwd=root,
                              capture_output=True, text=True, check=True).stdout

    rule = git_file("config/.semgrep/nope-active.yml")
    if hashlib.sha256(rule.encode()).hexdigest() != revision["rule_sha256"]:
        raise ValueError("Committed rule differs from the exact approved rule hash")
    workflow = yaml.safe_load(git_file(".github/workflows/nope-enforce.yml"))
    if workflow.get("jobs", {}).get("policy", {}).get("name") != "NOPE / policy":
        raise ValueError("The PR must include the named NOPE / policy workflow")
    for path in ("scripts/check_regression.py", "demo-app/regression/credential-log.ts"):
        if not git_file(path).strip():
            raise ValueError(f"Missing committed regression artifact: {path}")
    actual = subprocess.run(["gh", "repo", "view", "--json", "nameWithOwner", "--jq", ".nameWithOwner"],
                            cwd=root, capture_output=True, text=True, check=True).stdout.strip()
    if actual != repository:
        raise ValueError("The selected GitHub repository differs from the approved repository scope")


def approved_proposal(provenance: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    if provenance["scar"]["status"] != "approved":
        raise ValueError(
            "The human must approve this proposal through nope-core RBAC before PR preparation"
        )
    revisions = provenance.get("revisions", [])
    if not revisions:
        raise ValueError("No rule revision exists")
    revision = max(revisions, key=lambda r: r["sequence"])
    if revision["state"] != "approved":
        raise ValueError("The latest rule revision has not been approved")
    report = revision["report"]
    challenge = revision.get("challenge")
    if (
        not all(report[part]["passed"] for part in ("replay", "candidate", "regression"))
        or not challenge
        or not challenge["metrics"]["passed"]
        or not revision.get("adversary")
        or revision["adversary"] == revision["author"]
    ):
        raise ValueError(
            "The revision must pass incident replay, historical regressions, and an independent challenge"
        )
    approvals = [
        event
        for event in provenance.get("decisions", [])
        if event.get("action") == "scar.approved"
        and event.get("detail", {}).get("revision_id") == revision["id"]
        and str(event.get("actor", "")).startswith(("api-key:approver:", "api-key:admin:"))
    ]
    if not approvals:
        raise ValueError(
            "No matching approval from an authenticated nope-core approver/admin identity"
        )
    approval = approvals[-1]
    detail = approval["detail"]
    scar = provenance["scar"]
    if (not revision.get("evidence_sha256")
            or detail.get("evidence_sha256") != revision["evidence_sha256"]
            or detail.get("repository") != scar["repository"]
            or detail.get("scope") != scar["scope"]):
        raise ValueError("Approval does not match the current evidence hash, repository and scope")
    requests = [event for event in provenance.get("decisions", [])
                if event.get("action") == "scar.approval_requested"
                and event.get("id") == detail.get("request_id")]
    binding = ("request_id", "revision_id", "evidence_sha256", "repository", "scope")
    if not requests or any(requests[-1]["detail"].get(key) != detail.get(key) for key in binding):
        raise ValueError("No matching immutable approval request")
    return revision, approval


def description(provenance: dict[str, Any]) -> str:
    revision, approval = approved_proposal(provenance)
    scar = provenance["scar"]
    evidence = revision["challenge"]["metrics"]
    link = teach_url(provenance, None)
    return (
        f"This change prevents recurrence of {scar['origin']}: {scar['invariant']}\n\n"
        f"SCAR-{scar['number']:03d} — {scar['title']}\n\n"
        f"Original room report: {link}\n\nIncident: {scar.get('incident_url') or scar['origin']}\n\n"
        f"Approved revision: `{revision['id']}`\n\n"
        f"Evidence SHA-256: `{revision['evidence_sha256']}`\n\n"
        f"Repository / scope: `{scar['repository']}` / `{scar['scope']}`\n\n"
        f"Human approver: {approval['detail']['approver']} ({approval['actor']})\n\n"
        f"Validation: incident detected; correction passes; historical regressions pass. "
        f"Independent challenge: {evidence['detections']} detections, {evidence['misses']} misses, "
        f"{evidence['false_positives']} false positives.\n\n"
        f"Remediation: {scar['remediation']}\n\n"
        "Activation follows the authorized GitOps merge path. This command does not merge or activate the rule.\n"
    )
