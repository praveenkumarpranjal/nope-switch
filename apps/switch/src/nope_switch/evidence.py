"""Render measured evidence for room demos. No room guidance authorizes a rule."""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal
from urllib.parse import urlsplit

from nope_core.rule_lab import CandidateResult, RuleLab
from pydantic import BaseModel, Field, model_validator


def digest(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


def metrics(result: CandidateResult, bad_count: int, good_count: int) -> dict[str, Any]:
    detections = sum(h > 0 for h in result.bad_hits.values())
    return {
        "passed": result.passed,
        "detections": detections,
        "misses": bad_count - detections,
        "false_positives": sum(h > 0 for h in result.good_hits.values()),
        "safe_controls": good_count,
        "bad_findings": result.bad_hits,
        "good_findings": result.good_hits,
        "errors": result.rule_errors,
    }


def courtroom(
    naive: Path, taint: Path, challenge: Path, original: Path, corrected: Path
) -> dict[str, Any]:
    bundle = json.loads(challenge.read_text(encoding="utf-8"))
    bad = [(e["name"], e["content"]) for e in bundle["bad_examples"]]
    good = [(e["name"], e["content"]) for e in bundle["good_examples"]]
    if len(bad) < 6 or len(good) < 4:
        raise ValueError("Courtroom needs at least six unsafe variants and four safe controls")
    lab = RuleLab()
    report: dict[str, Any] = {
        "measured_at": datetime.now(UTC).isoformat(),
        "generated_by": bundle["generated_by"],
        "challenge_sha256": digest(challenge.read_text(encoding="utf-8")),
        "candidates": {},
    }
    for label, path in (("naive", naive), ("taint", taint)):
        rule = path.read_text(encoding="utf-8")
        replay = lab.validate(
            rule,
            [(original.name, original.read_text(encoding="utf-8"))],
            [(corrected.name, corrected.read_text(encoding="utf-8"))],
        )
        result = lab.validate(rule, bad, good)
        report["candidates"][label] = {
            "rule_sha256": digest(rule),
            "replay": replay.__dict__,
            **metrics(result, len(bad), len(good)),
        }
    naive_result, taint_result = report["candidates"]["naive"], report["candidates"]["taint"]
    report["demonstrated"] = (
        not naive_result["errors"]
        and not naive_result["passed"]
        and naive_result["replay"]["passed"]
        and taint_result["passed"]
        and taint_result["replay"]["passed"]
    )
    return report


def courtroom_message(label: str, result: dict[str, Any]) -> str:
    return (
        f"Rule Lab courtroom — {label} candidate\n"
        f"Original incident replay: {'PASS' if result['replay']['passed'] else 'FAIL'}. "
        f"Independent variants: {result['detections']} detected, {result['misses']} missed, "
        f"{result['false_positives']} false positives across {result['safe_controls']} safe controls.\n"
        f"Quality gate: {'PASS' if result['passed'] else 'REJECT'}. "
        f"Scanner errors: {len(result['errors'])}. Rule SHA-256: {result['rule_sha256']}.\n"
        "Measured with Semgrep. Human approval and CI activation remain separate."
    )


def courtroom_from_ledger(
    provenance: dict[str, Any], naive_id: str, taint_id: str
) -> dict[str, Any]:
    """Live publication reads workbench evidence; it does not validate in the transport."""
    if naive_id == taint_id:
        raise ValueError("The courtroom needs two distinct workbench revisions")
    revisions = {r["id"]: r for r in provenance["revisions"]}
    candidates = {}
    corpora = []
    for label, revision_id in (("naive", naive_id), ("taint", taint_id)):
        revision = revisions[revision_id]
        challenge = revision.get("challenge")
        if (
            not challenge
            or not revision.get("adversary")
            or revision["adversary"] == revision["author"]
        ):
            raise ValueError(
                "Live publication requires independent challenge evidence stored by nope-core"
            )
        metrics = challenge["metrics"]
        report = revision["report"]
        corpora.append(
            {"bad_examples": challenge["bad_examples"], "good_examples": challenge["good_examples"]}
        )
        candidates[label] = {
            "replay": report["replay"],
            "rule_sha256": revision["rule_sha256"],
            "detections": metrics["detections"],
            "misses": metrics["misses"],
            "false_positives": metrics["false_positives"],
            "safe_controls": len(challenge["good_examples"]),
            "errors": [*metrics["errors"], *report["replay"]["errors"]],
            "passed": metrics["passed"]
            and report["candidate"]["passed"]
            and report["replay"]["passed"]
            and report["regression"]["passed"],
            "revision_id": revision_id,
        }
    if corpora[0] != corpora[1]:
        raise ValueError(
            "Both workbench revisions must be challenged against the exact same corpus"
        )
    return {
        "evidence_source": "nope-core HTTP workbench",
        "candidates": candidates,
        "demonstrated": not candidates["naive"]["passed"]
        and candidates["naive"]["replay"]["passed"]
        and candidates["taint"]["passed"],
        "challenge_sha256": digest(json.dumps(corpora[0], sort_keys=True)),
    }


def verify_room_source(provenance: dict[str, Any], room_id: str) -> None:
    proposed = next(
        (e for e in provenance.get("decisions", []) if e.get("action") == "scar.proposed"), None
    )
    if (
        not proposed
        or (proposed.get("detail", {}).get("source_message") or {}).get("room_id") != room_id
    ):
        raise ValueError(
            "Live publication requires the Scar's original source-message room to match the destination"
        )


def teach_url(provenance: dict[str, Any], override: str | None) -> str:
    value = override
    if not value:
        for event in provenance.get("decisions", []):
            if event.get("action") == "scar.proposed":
                value = event.get("detail", {}).get("teach_message_url")
                break
    if not value or urlsplit(value).scheme not in {"http", "https"} or not urlsplit(value).netloc:
        raise ValueError(
            "The original @nope teach message URL is required; an incident ticket is not its substitute"
        )
    return value


def approved_context(provenance: dict[str, Any]) -> tuple[dict[str, Any], str]:
    active = next((r for r in provenance.get("revisions", []) if r.get("state") == "active"), None)
    if active is None:
        raise ValueError("An activated revision is required")
    approvals = [
        e["detail"]
        for e in provenance.get("decisions", [])
        if e.get("action") == "scar.approved"
        and e.get("detail", {}).get("revision_id") == active["id"]
    ]
    if not approvals:
        raise ValueError("The activated revision has no matching approval decision")
    return active, str(approvals[-1]["approver"])


def scar_document(provenance: dict[str, Any], original_teach: str | None = None) -> str:
    scar = provenance["scar"]
    active, approver = approved_context(provenance)
    link = teach_url(provenance, original_teach)
    return (
        f"# SCAR-{scar['number']:03d}: {scar['title']}\n\n"
        f"Original teach message: {link}\n\nIncident: {scar.get('incident_url') or scar['origin']}\n\n"
        f"Invariant: {scar['invariant']}\n\nWhy: {scar['rationale']}\n\n"
        f"Correction: {scar['remediation']}\n\nApproved by: {approver}\n\n"
        f"Approved active revision: {active['id']}\n\n"
        f"Tests and replay: /v1/scars/{scar['number']}/revisions/{active['id']}/tests\n\n"
        f"Decisions: /v1/scars/{scar['number']}/provenance\n\n"
        "This room document is advisory context. Passing CI is the executable safeguard. "
        "The ledger is append-only; these records are not cryptographically signed.\n"
    )


def failure_message(
    scan: dict[str, Any], provenance: dict[str, Any], original_teach: str | None = None
) -> str:
    scar = provenance["scar"]
    active, approver = approved_context(provenance)
    link = teach_url(provenance, original_teach)
    if scan.get("errors"):
        raise ValueError("A scanner error is not a demonstrated policy violation")
    findings = scan.get("results", [])
    if not findings:
        raise ValueError("No policy violations to notify")
    files: list[str] = []
    for finding in findings:
        metadata = finding.get("extra", {}).get("metadata", {})
        if metadata.get("scar") != f"SCAR-{scar['number']:03d}":
            raise ValueError("Scan findings do not belong to the selected Scar")
        if metadata.get("revision_id") not in {None, active["id"]}:
            raise ValueError("The scan and approval refer to different revisions")
        if metadata.get("revision_id") != active["id"]:
            if (
                not active.get("rule_sha256")
                or scan.get("nope_rule_sha256") != active["rule_sha256"]
            ):
                raise ValueError("The scanned rule must match the activated revision's rule hash")
        files.append(f"{finding['path']}:{finding.get('start', {}).get('line', 1)}")
    return (
        f"CI BLOCKED — SCAR-{scar['number']:03d}: {scar['title']}\n"
        f"Original @nope teach: {link}\nApproved by: {approver}\n"
        f"Failing file(s): {', '.join(sorted(set(files)))}\nRevision: {active['id']}\n"
        f"Fix: {scar['remediation']}\nThe demo scan exited 42. CI remains blocking regardless of room delivery."
    )


class Trial(BaseModel):
    pair: str
    condition: Literal["without_scar", "with_scar"]
    room_id: str
    response_url: str
    code_path: Path
    document_id: str | None = None
    task_completed: bool


class Experiment(BaseModel):
    agent: str
    model: str
    prompt: str
    trials: list[Trial] = Field(min_length=10)

    @model_validator(mode="after")
    def paired_evidence(self) -> Experiment:
        pairs: dict[str, set[str]] = {}
        responses: set[str] = set()
        rooms: set[str] = set()
        for trial in self.trials:
            if trial.response_url in responses or urlsplit(trial.response_url).scheme not in {
                "https",
                "http",
            }:
                raise ValueError(
                    "Each trial needs a distinct HTTP(S) link to a real agent response"
                )
            if trial.room_id in rooms:
                raise ValueError("Use a fresh room per trial to avoid contaminating the comparison")
            if (trial.condition == "with_scar") != bool(trial.document_id):
                raise ValueError("Record a document ID only for trials with the Scar attached")
            conditions = pairs.setdefault(trial.pair, set())
            if trial.condition in conditions:
                raise ValueError("Each pair needs exactly one trial per condition")
            conditions.add(trial.condition)
            responses.add(trial.response_url)
            rooms.add(trial.room_id)
        if len(pairs) < 5 or any(c != {"with_scar", "without_scar"} for c in pairs.values()):
            raise ValueError("Provide at least five complete paired trials")
        return self


def compliance(manifest: Path, rule_path: Path) -> dict[str, Any]:
    experiment = Experiment.model_validate_json(manifest.read_text(encoding="utf-8"))
    rule = rule_path.read_text(encoding="utf-8")
    trials = []
    lab = RuleLab()
    for trial in experiment.trials:
        path = (
            trial.code_path if trial.code_path.is_absolute() else manifest.parent / trial.code_path
        )
        code = path.read_text(encoding="utf-8")
        if path.suffix not in {".ts", ".tsx", ".js", ".jsx"} or not code.strip():
            raise ValueError("Agent responses must contain nonempty JavaScript/TypeScript code")
        result = lab.validate(rule, [], [(path.name, code)])
        trials.append(
            {
                **trial.model_dump(mode="json"),
                "code_sha256": digest(code),
                "compliant": result.passed and trial.task_completed,
                "static_policy_passed": result.passed,
                "errors": result.rule_errors,
                "findings": result.good_hits,
            }
        )
    summary = {}
    for condition in ("without_scar", "with_scar"):
        selected = [t for t in trials if t["condition"] == condition]
        errors = sum(bool(t["errors"]) for t in selected)
        passed = sum(t["compliant"] for t in selected)
        summary[condition] = {
            "attempts": len(selected),
            "compliant": passed,
            "scanner_errors": errors,
            "incomplete_tasks": sum(not t["task_completed"] for t in selected),
            "compliance_rate": None if errors else passed / len(selected),
        }
    return {
        "agent": experiment.agent,
        "model": experiment.model,
        "prompt_sha256": digest(experiment.prompt),
        "rule_sha256": digest(rule),
        "summary": summary,
        "trials": trials,
        "interpretation": "Observed static-policy compliance only; room context is advisory and trials are operator-supplied, not proof of universal LLM compliance.",
    }
