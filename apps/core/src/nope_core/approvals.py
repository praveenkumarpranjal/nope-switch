"""Evidence-bound approval tickets. No chat text or transport grants authority."""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime, timedelta
from typing import Any

from nope_core import assurance
from nope_core.db import AuditEvent, RuleVersion, Scar, new_id
from nope_core.schemas import ApprovalDecisionRequest
from sqlalchemy import select
from sqlalchemy.orm import Session


def evidence_hash(db: Session, scar: Scar, revision: assurance.Revision) -> str:
    rule = db.get(RuleVersion, revision.rule_id)
    if rule is None or hashlib.sha256(rule.rule_yaml.encode()).hexdigest() != rule.sha256:
        raise ValueError("Revision rule content does not match its recorded hash")
    evidence = {
        "schema": "nope-approval-v1", "scar_id": scar.id,
        "revision_id": revision.id, "rule_id": rule.id, "rule_sha256": rule.sha256,
        "repository": scar.repository, "scope": scar.scope,
        "author": revision.author, "adversary": revision.adversary,
        "fixtures": json.loads(revision.fixtures), "report": json.loads(revision.report),
        "challenge": json.loads(revision.challenge) if revision.challenge else None,
    }
    canonical = json.dumps(evidence, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(canonical.encode()).hexdigest()


def request(db: Session, scar: Scar, actor: str, revision_id: str) -> dict[str, Any]:
    if scar.status != "validated":
        raise ValueError("Only a validated Scar can request approval")
    revision = assurance.require_quality(assurance.latest(db, scar))
    if revision.id != revision_id:
        raise ValueError("Approval must name the latest validated candidate")
    rule = db.get(RuleVersion, revision.rule_id)
    assert rule is not None
    now = datetime.now(UTC)
    packet = {
        "request_id": new_id("approval"), "revision_id": revision.id,
        "evidence_sha256": evidence_hash(db, scar, revision), "rule_sha256": rule.sha256,
        "repository": scar.repository, "scope": scar.scope,
        "expires_at": (now + timedelta(hours=24)).isoformat(),
        "report": json.loads(revision.report),
        "challenge_metrics": json.loads(revision.challenge or "{}")["metrics"],
    }
    db.add(AuditEvent(id=packet["request_id"], scar_id=scar.id, actor=actor,
                      action="scar.approval_requested", occurred_at=now,
                      detail=json.dumps(packet, sort_keys=True)))
    return packet


def verify(db: Session, scar: Scar, payload: ApprovalDecisionRequest) -> assurance.Revision:
    revision = assurance.require_quality(assurance.latest(db, scar))
    event = db.get(AuditEvent, payload.request_id)
    if event is None or event.scar_id != scar.id or event.action != "scar.approval_requested":
        raise ValueError("Unknown approval request for this Scar")
    ticket = json.loads(event.detail)
    if datetime.fromisoformat(ticket["expires_at"]) <= datetime.now(UTC):
        raise ValueError("Approval request has expired; request fresh evidence review")
    current = {
        "request_id": event.id, "revision_id": revision.id,
        "evidence_sha256": evidence_hash(db, scar, revision),
        "repository": scar.repository, "scope": scar.scope,
    }
    for key, value in current.items():
        if ticket.get(key) != value or getattr(payload, key) != value:
            raise ValueError(f"Stale or mismatched approval {key}; review the current candidate")
    for previous in db.scalars(select(AuditEvent).where(
        AuditEvent.scar_id == scar.id, AuditEvent.action == "scar.approved"
    )):
        if json.loads(previous.detail).get("request_id") == event.id:
            raise ValueError("Approval request has already been consumed")
    return revision


def verify_approved(db: Session, scar: Scar, revision: assurance.Revision) -> None:
    """Recheck evidence at activation, including activation from a signed webhook."""
    digest = evidence_hash(db, scar, revision)
    for event in db.scalars(select(AuditEvent).where(
        AuditEvent.scar_id == scar.id, AuditEvent.action == "scar.approved"
    )):
        detail = json.loads(event.detail)
        if (detail.get("revision_id") == revision.id
                and detail.get("evidence_sha256") == digest
                and detail.get("repository") == scar.repository
                and detail.get("scope") == scar.scope
                and detail.get("request_id")):
            return
    raise ValueError("No approval matches the current candidate, scope and evidence hash")
