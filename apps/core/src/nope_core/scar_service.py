from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime, timedelta
from typing import Any

import yaml
from nope_core.db import (
    AuditEvent,
    ExceptionRecord,
    RuleVersion,
    Scar,
    ScarCounter,
    ValidationRun,
    new_id,
)
from nope_core.db import RuleVersion as RuleVersionModel
from nope_core.rule_lab import CandidateResult
from nope_core.schemas import (
    ChallengeRequest,
    CreateScarRequest,
    ScarResponse,
    ScarStatus,
)
from sqlalchemy import func, select, update
from sqlalchemy.orm import Session


def scar_response(scar: Scar) -> ScarResponse:
    return ScarResponse(
        id=scar.id,
        number=scar.number,
        title=scar.title,
        incident_summary=scar.incident_summary,
        invariant=scar.invariant,
        rationale=scar.rationale,
        remediation=scar.remediation,
        incident_url=scar.incident_url,
        repository=scar.repository,
        scope=scar.scope,
        severity=scar.severity,  # type: ignore[arg-type]
        enforcement=scar.enforcement,  # type: ignore[arg-type]
        origin=scar.origin,
        proposed_by=scar.proposed_by,
        status=ScarStatus(scar.status),
        active=scar.active,
        approved_by=scar.approved_by,
        created_at=scar.created_at,
        updated_at=scar.updated_at,
    )


def _audit(db: Session, actor: str, action: str, detail: dict[str, Any], scar_id: str | None = None) -> None:
    db.add(AuditEvent(id=new_id("evt"), scar_id=scar_id, actor=actor, action=action, detail=json.dumps(detail, default=str, sort_keys=True)))


def get_scar(db: Session, scar_id: str) -> Scar | None:
    return db.get(Scar, scar_id)


def get_scar_by_number(db: Session, number: int) -> Scar | None:
    return db.scalar(select(Scar).where(Scar.number == number))


def list_scars(db: Session) -> list[Scar]:
    return list(db.scalars(select(Scar).order_by(Scar.number.desc())).all())


def get_next_scar_number(db: Session) -> int:
    stmt = (
        update(ScarCounter)
        .where(ScarCounter.name == "scars")
        .values(current_value=ScarCounter.current_value + 1)
        .returning(ScarCounter.current_value)
    )
    val = db.scalar(stmt)
    if val is not None:
        return int(val)

    max_num = db.scalar(select(func.coalesce(func.max(Scar.number), 0))) or 0
    allocated = int(max_num) + 1
    try:
        with db.begin_nested():
            db.add(ScarCounter(name="scars", current_value=allocated))
            db.flush()
            return allocated
    except Exception:
        val = db.scalar(stmt)
        if val is not None:
            return int(val)
        raise RuntimeError("Failed to allocate atomic scar number") from None


def create_scar(db: Session, payload: CreateScarRequest, actor: str) -> Scar:
    with db.begin():
        next_number = get_next_scar_number(db)
        incident_url = str(payload.incident_url) if payload.incident_url else None
        scar = Scar(
            id=new_id("scar"),
            number=next_number,
            title=payload.title,
            incident_summary=payload.incident_summary,
            invariant=payload.invariant,
            rationale=payload.rationale,
            remediation=payload.remediation,
            incident_url=incident_url,
            repository=payload.repository,
            scope=payload.scope,
            severity=payload.severity.value,
            enforcement=payload.enforcement.value,
            origin=payload.origin,
            proposed_by=payload.proposed_by,
            status=ScarStatus.PROPOSED.value,
            active=False,
        )
        db.add(scar)
        _audit(db, actor, "scar.proposed", payload.model_dump(mode="json"), scar.id)
    return scar


def add_rule_version(db: Session, scar: Scar, rule_yaml: str) -> RuleVersion:
    version = db.scalar(select(func.coalesce(func.max(RuleVersionModel.version), 0) + 1).where(RuleVersionModel.scar_id == scar.id))
    rule_sha = hashlib.sha256(rule_yaml.encode()).hexdigest()
    record = RuleVersion(id=new_id("rule"), scar_id=scar.id, version=int(version or 1), sha256=rule_sha, rule_yaml=rule_yaml)
    db.add(record)
    return record


def record_validation(db: Session, scar: Scar, actor: str, result: CandidateResult) -> None:
    db.add(
        ValidationRun(
            id=new_id("run"),
            scar_id=scar.id,
            passed=result.passed,
            bad_findings=json.dumps(result.bad_hits, sort_keys=True),
            good_findings=json.dumps(result.good_hits, sort_keys=True),
            rule_errors=json.dumps(result.rule_errors),
            target_findings=json.dumps(result.target_hits),
        )
    )
    scar.status = ScarStatus.VALIDATED.value if result.passed else ScarStatus.PROPOSED.value
    _audit(db, actor, "scar.validation_passed" if result.passed else "scar.validation_failed", {
        "bad_hits": result.bad_hits,
        "good_hits": result.good_hits,
        "target_hits": result.target_hits,
        "rule_errors": result.rule_errors,
    }, scar.id)


def approve_scar(db: Session, scar: Scar, actor: str, approver: str, reason: str) -> Scar:
    if scar.status != ScarStatus.VALIDATED.value:
        raise ValueError("Only a validated scar can be approved")
    scar.status = ScarStatus.APPROVED.value
    scar.approved_by = approver
    scar.approved_reason = reason
    _audit(db, actor, "scar.approved", {"approver": approver, "reason": reason}, scar.id)
    return scar


def activate_scar(db: Session, scar: Scar, actor: str) -> Scar:
    if scar.status != ScarStatus.APPROVED.value:
        raise ValueError("Only an approved scar can be activated")
    scar.status = ScarStatus.ACTIVE.value
    scar.active = True
    _audit(db, actor, "scar.activated", {"approved_by": scar.approved_by}, scar.id)
    return scar


def activate_scar_break_glass(db: Session, scar: Scar, actor: str, authorized_by: str, reason: str) -> Scar:
    if scar.status != ScarStatus.APPROVED.value:
        raise ValueError("Only an approved scar can be activated")
    scar.status = ScarStatus.ACTIVE.value
    scar.active = True
    _audit(
        db,
        actor,
        "scar.activated_break_glass",
        {
            "warning": "BREAK-GLASS MANUAL ACTIVATION BYPASSING GITOPS PR MERGE",
            "authorized_by": authorized_by,
            "reason": reason,
        },
        scar.id,
    )
    return scar


def challenge_scar(db: Session, scar: Scar, actor: str, payload: ChallengeRequest) -> ExceptionRecord:
    expires = datetime.now(UTC) + timedelta(days=payload.expires_in_days)
    record = ExceptionRecord(
        id=new_id("exc"),
        scar_id=scar.id,
        requested_by=payload.requested_by,
        reason=payload.reason,
        status="pending",
        expires_at=expires,
        approver=None,
    )
    db.add(record)
    detail = payload.model_dump(mode="json", exclude={"proposed_rule_yaml", "bad_examples", "good_examples"})
    if payload.proposed_rule_yaml:
        detail["proposed_rule_sha256"] = hashlib.sha256(payload.proposed_rule_yaml.encode()).hexdigest()
    _audit(db, actor, "scar.challenged", detail, scar.id)
    return record


def generate_active_rules_yaml(db: Session) -> str:
    scars = list(db.scalars(select(Scar).where(Scar.active.is_(True)).order_by(Scar.number.asc())).all())
    merged_rules: list[dict[str, Any]] = []
    for scar in scars:
        latest_rule_version = db.scalar(
            select(RuleVersionModel)
            .where(RuleVersionModel.scar_id == scar.id)
            .order_by(RuleVersionModel.version.desc())
            .limit(1)
        )
        if not latest_rule_version or not latest_rule_version.rule_yaml.strip():
            continue
        try:
            doc = yaml.safe_load(latest_rule_version.rule_yaml)
        except Exception:
            continue
        rules: list[Any] = []
        if isinstance(doc, dict) and "rules" in doc and isinstance(doc["rules"], list):
            rules = doc["rules"]
        elif isinstance(doc, list):
            rules = doc
        elif isinstance(doc, dict):
            rules = [doc]
        for rule in rules:
            if isinstance(rule, dict):
                rule_copy = dict(rule)
                metadata = rule_copy.setdefault("metadata", {})
                if isinstance(metadata, dict) and "scar" not in metadata:
                    metadata["scar"] = f"SCAR-{scar.number:03d}"
                merged_rules.append(rule_copy)
    return yaml.safe_dump({"rules": merged_rules}, sort_keys=False)

