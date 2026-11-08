from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime, timedelta
from typing import Any

import yaml
from nope_core import approvals, assurance
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
    ApprovalDecisionRequest,
    ChallengeRequest,
    CreateScarRequest,
    Enforcement,
    ExceptionResponse,
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
        organization_id=scar.organization_id,
        created_at=scar.created_at,
        updated_at=scar.updated_at,
    )


def _audit(db: Session, actor: str, action: str, detail: dict[str, Any], scar_id: str | None = None, organization_id: str = "default") -> None:
    db.add(AuditEvent(id=new_id("evt"), scar_id=scar_id, organization_id=organization_id, actor=actor, action=action, occurred_at=datetime.now(UTC), detail=json.dumps(detail, default=str, sort_keys=True)))


def get_scar(db: Session, scar_id: str, organization_id: str | None = None) -> Scar | None:
    if organization_id and organization_id != "*":
        return db.scalar(select(Scar).where(Scar.id == scar_id, Scar.organization_id == organization_id))
    return db.get(Scar, scar_id)


def get_scar_by_number(db: Session, number: int, organization_id: str | None = None, repository: str | None = None) -> Scar | None:
    stmt = select(Scar).where(Scar.number == number)
    if organization_id and organization_id != "*":
        stmt = stmt.where(Scar.organization_id == organization_id)
    if repository:
        stmt = stmt.where(Scar.repository == repository)
    return db.scalar(stmt)


def list_scars(db: Session, organization_id: str | None = None, repository: str | None = None) -> list[Scar]:
    stmt = select(Scar)
    if organization_id and organization_id != "*":
        stmt = stmt.where(Scar.organization_id == organization_id)
    if repository:
        stmt = stmt.where(Scar.repository == repository)
    return list(db.scalars(stmt.order_by(Scar.number.desc())).all())


def get_next_scar_number(
    db: Session,
    counter_name: str = "scars",
    organization_id: str = "default",
    repository: str | None = None,
) -> int:
    stmt = (
        update(ScarCounter)
        .where(ScarCounter.name == counter_name)
        .values(current_value=ScarCounter.current_value + 1)
        .returning(ScarCounter.current_value)
    )
    val = db.scalar(stmt)
    if val is not None:
        return int(val)

    scope_stmt = select(func.coalesce(func.max(Scar.number), 0))
    if organization_id != "*":
        scope_stmt = scope_stmt.where(Scar.organization_id == organization_id)
    if repository:
        scope_stmt = scope_stmt.where(Scar.repository == repository)

    max_num = db.scalar(scope_stmt) or 0
    allocated = int(max_num) + 1
    try:
        with db.begin_nested():
            db.add(ScarCounter(name=counter_name, current_value=allocated))
            db.flush()
            return allocated
    except Exception:
        val = db.scalar(stmt)
        if val is not None:
            return int(val)
        raise RuntimeError(f"Failed to allocate atomic scar number for {counter_name}") from None


def create_scar(db: Session, payload: CreateScarRequest, actor: str, organization_id: str = "default") -> Scar:
    org_id = payload.organization_id or organization_id or "default"
    counter_name = f"scars:{org_id}:{payload.repository}" if org_id != "default" else "scars"
    with db.begin():
        next_number = get_next_scar_number(db, counter_name=counter_name, organization_id=org_id, repository=payload.repository)
        incident_url = str(payload.incident_url) if payload.incident_url else None
        scar = Scar(
            id=new_id("scar"),
            number=next_number,
            organization_id=org_id,
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
        _audit(db, actor, "scar.proposed", payload.model_dump(mode="json"), scar.id, organization_id=org_id)
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
    }, scar.id, organization_id=scar.organization_id)


def approve_scar(db: Session, scar: Scar, actor: str, payload: ApprovalDecisionRequest) -> Scar:
    if scar.status != ScarStatus.VALIDATED.value:
        raise ValueError("Only a validated scar can be approved")
    revision = approvals.verify(db, scar, payload)
    # Claim the transition atomically so concurrent approval requests cannot both win.
    claimed = db.execute(update(Scar).where(Scar.id == scar.id, Scar.status == "validated")
                         .values(status="approved"))
    if claimed.rowcount != 1:  # type: ignore[attr-defined]
        raise ValueError("Candidate is no longer awaiting approval")
    revision.state = "approved"
    scar.status = ScarStatus.APPROVED.value
    scar.approved_by = payload.approver
    scar.approved_reason = payload.reason
    _audit(db, actor, "scar.approved", {**payload.model_dump(), "rule_id": revision.rule_id}, scar.id, organization_id=scar.organization_id)
    return scar


def activate_scar(db: Session, scar: Scar, actor: str) -> Scar:
    if scar.status != ScarStatus.APPROVED.value:
        raise ValueError("Only an approved scar can be activated")
    revision = assurance.latest(db, scar)
    if revision is None or revision.state != "approved":
        raise ValueError("The latest revision must be approved before activation")
    approvals.verify_approved(db, scar, revision)
    previous = assurance.active(db, scar)
    if previous is not None:
        previous.state = "superseded"
    revision.state = "active"
    scar.status = ScarStatus.ACTIVE.value
    scar.active = True
    _audit(db, actor, "scar.activated", {"approved_by": scar.approved_by, "revision_id": revision.id}, scar.id, organization_id=scar.organization_id)
    return scar


def activate_scar_break_glass(db: Session, scar: Scar, actor: str, authorized_by: str, reason: str) -> Scar:
    if scar.status != ScarStatus.APPROVED.value:
        raise ValueError("Only an approved scar can be activated")
    # Manual activation also requires the exact approved revision. The route's
    # AdminRequired dependency, mandatory reason, and break-glass audit remain.
    revision = assurance.latest(db, scar)
    if revision is None or revision.state != "approved":
        raise ValueError("The latest revision must be approved before activation")
    approvals.verify_approved(db, scar, revision)
    previous = assurance.active(db, scar)
    if previous is not None:
        previous.state = "superseded"
    revision.state = "active"
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
            "revision_id": revision.id,
        },
        scar.id,
        organization_id=scar.organization_id,
    )
    return scar


def challenge_scar(db: Session, scar: Scar, actor: str, payload: ChallengeRequest) -> ExceptionRecord:
    expires = datetime.now(UTC) + timedelta(days=payload.expires_in_days)
    record = ExceptionRecord(
        id=new_id("exc"),
        scar_id=scar.id,
        organization_id=scar.organization_id,
        requested_by=payload.requested_by,
        reason=payload.reason,
        path_pattern=payload.path_pattern,
        status="pending",
        expires_at=expires,
        approver=None,
    )
    db.add(record)
    detail = payload.model_dump(mode="json", exclude={"proposed_rule_yaml", "bad_examples", "good_examples"})
    if payload.proposed_rule_yaml:
        detail["proposed_rule_sha256"] = hashlib.sha256(payload.proposed_rule_yaml.encode()).hexdigest()
    _audit(db, actor, "scar.challenged", detail, scar.id, organization_id=scar.organization_id)
    return record


def _as_utc(dt: datetime | None) -> datetime | None:
    if dt is None:
        return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=UTC)
    return dt.astimezone(UTC)


def exception_response(exc: ExceptionRecord, scar: Scar | None = None) -> ExceptionResponse:
    now = datetime.now(UTC)
    exp = _as_utc(exc.expires_at)
    is_expired = exp is not None and exp <= now
    scar_num = scar.number if scar else getattr(exc.scar, "number", None)
    return ExceptionResponse(
        id=exc.id,
        scar_id=exc.scar_id,
        scar_number=scar_num,
        organization_id=exc.organization_id,
        requested_by=exc.requested_by,
        reason=exc.reason,
        path_pattern=exc.path_pattern,
        status=exc.status,
        expires_at=exc.expires_at,
        approver=exc.approver,
        approved_at=exc.approved_at,
        is_expired=is_expired,
    )


def approve_exception(db: Session, exception_id: str, approver: str, reason: str, actor: str) -> ExceptionRecord:
    exc = db.get(ExceptionRecord, exception_id)
    if exc is None:
        raise ValueError(f"Exception {exception_id} not found")
    if exc.status == "approved":
        return exc
    exc.status = "approved"
    exc.approver = approver
    exc.approved_at = datetime.now(UTC)
    scar = db.get(Scar, exc.scar_id)
    org_id = scar.organization_id if scar else exc.organization_id
    _audit(
        db,
        actor,
        "exception.approved",
        {"exception_id": exc.id, "approver": approver, "reason": reason, "scar_id": exc.scar_id},
        scar_id=exc.scar_id,
        organization_id=org_id,
    )
    return exc


def list_active_exceptions(
    db: Session,
    organization_id: str | None = None,
    repository: str | None = None,
    include_expired: bool = False,
) -> list[ExceptionRecord]:
    stmt = select(ExceptionRecord).join(Scar, ExceptionRecord.scar_id == Scar.id)
    if organization_id and organization_id != "*":
        stmt = stmt.where(ExceptionRecord.organization_id == organization_id)
    if repository:
        stmt = stmt.where(Scar.repository == repository)
    stmt = stmt.where(ExceptionRecord.status == "approved")
    if not include_expired:
        now = datetime.now(UTC)
        stmt = stmt.where((ExceptionRecord.expires_at.is_(None)) | (ExceptionRecord.expires_at > now))
    return list(db.scalars(stmt.order_by(ExceptionRecord.created_at.desc())).all())


def generate_active_rules_yaml(
    db: Session,
    organization_id: str | None = None,
    repository: str | None = None,
) -> str:
    stmt = select(Scar).where(Scar.active.is_(True), Scar.enforcement == Enforcement.SEMGREP.value)
    if organization_id and organization_id != "*":
        stmt = stmt.where(Scar.organization_id == organization_id)
    if repository:
        stmt = stmt.where(Scar.repository == repository)
    scars = list(db.scalars(stmt.order_by(Scar.number.asc())).all())
    merged_rules: list[dict[str, Any]] = []
    for scar in scars:
        revision = assurance.active(db, scar)
        if revision is None:
            raise ValueError(f"SCAR-{scar.number:03d} lacks revision evidence; revalidate, challenge, approve and activate it")
        latest_rule_version = db.get(RuleVersionModel, revision.rule_id)
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
                if not isinstance(metadata, dict):
                    metadata = {}
                    rule_copy["metadata"] = metadata
                base = f"/v1/scars/{scar.number}/revisions/{revision.id}"
                metadata.update({"scar": f"SCAR-{scar.number:03d}",
                                 "incident": scar.incident_url or f"/v1/scars/{scar.number}/provenance",
                                 "origin": scar.origin, "rule_sha256": latest_rule_version.sha256,
                                 "revision_id": revision.id, "approved_rule": base + "/rule",
                                 "tests": base + "/tests", "history": f"/v1/scars/{scar.number}/provenance",
                                 "remediation": scar.remediation})
                merged_rules.append(rule_copy)
    return yaml.safe_dump({"rules": merged_rules}, sort_keys=False)

