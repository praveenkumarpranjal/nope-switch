from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import time
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any, cast

from fastapi import FastAPI, HTTPException, Query, Request, Response
from fastapi.responses import HTMLResponse, JSONResponse
from nope_core import (
    approvals,
    assurance,
    metrics,
    scar_service,
    validation_jobs,
    validation_pipeline,
)
from nope_core.auth import (
    AdminRequired,
    AgentRequired,
    ApproverRequired,
    CiRequired,
    Role,
    issue_token,
)
from nope_core.config import settings
from nope_core.db import (
    AuditEvent,
    ExceptionRecord,
    RuleVersion,
    Scar,
    SessionLocal,
    ValidationJob,
    WebhookDelivery,
    engine,
    init_db,
    new_id,
)
from nope_core.gitops import GitHubUnavailable, verify_merged_rule
from nope_core.rule_lab import RuleLab, RuleLabError
from nope_core.schemas import (
    AdversarialRequest,
    ApprovalDecisionRequest,
    ApprovalProposalRequest,
    ApprovalRequest,
    ApproveExceptionRequest,
    BreakGlassActivationRequest,
    ChallengeRequest,
    CreateScarRequest,
    ExceptionResponse,
    IssueTokenRequest,
    ScarStatus,
    TokenResponse,
    ValidateScarRequest,
)
from pydantic import BaseModel, Field, ValidationError
from sqlalchemy import select
from sqlalchemy.orm import Session


@asynccontextmanager
async def lifespan(_: FastAPI) -> AsyncIterator[None]:
    init_db()
    try:
        yield
    finally:
        engine.dispose()


app = FastAPI(title="NOPE Never-Again Compiler", version="1.0.0", docs_url="/docs", redoc_url=None, lifespan=lifespan)
lab = RuleLab()


@app.middleware("http")
async def metrics_middleware(request: Request, call_next: Any) -> Response:
    start_time = time.perf_counter()
    response = cast(Response, await call_next(request))
    duration = time.perf_counter() - start_time
    endpoint = request.url.path
    metrics.NOPE_REQUEST_DURATION.observe(duration, labels={"method": request.method, "endpoint": endpoint})
    return response


def _collect_db_metrics() -> None:
    from datetime import UTC, datetime
    with SessionLocal() as db:
        # Scars by status and org
        scars = list(db.scalars(select(Scar)).all())
        counts: dict[tuple[str, str], int] = {}
        for s in scars:
            key = (s.status, s.organization_id)
            counts[key] = counts.get(key, 0) + 1
        for (st, org), c in counts.items():
            metrics.NOPE_SCARS_TOTAL.set(float(c), labels={"status": st, "organization_id": org})

        # Exceptions by status and org
        excs = list(db.scalars(select(ExceptionRecord)).all())
        now = datetime.now(UTC)
        exc_counts: dict[tuple[str, str], int] = {}
        for e in excs:
            st = "expired" if (e.status == "approved" and e.expires_at and e.expires_at <= now) else e.status
            k = (st, e.organization_id)
            exc_counts[k] = exc_counts.get(k, 0) + 1
        for (st, org), c in exc_counts.items():
            metrics.NOPE_EXCEPTIONS_TOTAL.set(float(c), labels={"status": st, "organization_id": org})

        # Active rules
        active_scars = [s for s in scars if s.active]
        active_by_org: dict[str, int] = {}
        for s in active_scars:
            active_by_org[s.organization_id] = active_by_org.get(s.organization_id, 0) + 1
        for org, c in active_by_org.items():
            metrics.NOPE_ACTIVE_RULES_TOTAL.set(float(c), labels={"organization_id": org})


metrics.REGISTRY.add_collector(_collect_db_metrics)


@app.get("/metrics", response_class=Response)
def get_metrics() -> Response:
    content = metrics.REGISTRY.generate_prometheus()
    return Response(content=content, media_type="text/plain; version=0.0.4; charset=utf-8")


@app.get("/health")
def health() -> dict[str, Any]:
    return {"status": "ok", "service": "nope-core", "version": "1.0.0", "env": settings.env}


@app.get("/v1/scars")
def list_scars(actor: AgentRequired, repository: str | None = None) -> list[dict[str, Any]]:
    with SessionLocal() as db:
        return [
            scar_service.scar_response(scar).model_dump(mode="json")
            for scar in scar_service.list_scars(db, organization_id=actor.organization, repository=repository)
        ]


@app.post("/v1/scars", status_code=201)
def create_scar(payload: CreateScarRequest, actor: AgentRequired) -> dict[str, Any]:
    with SessionLocal() as db:
        if actor.is_user_identity and payload.proposed_by and payload.proposed_by != actor.subject:
            raise HTTPException(
                status_code=403,
                detail=f"Identity impersonation forbidden: authenticated as '{actor.subject}', cannot propose as '{payload.proposed_by}'",
            )
        target_org = actor.organization if hasattr(actor, "organization") else "default"
        if payload.organization_id and payload.organization_id != target_org:
            if hasattr(actor, "role") and actor.role < Role.ADMIN and target_org != "*":
                raise HTTPException(
                    status_code=403,
                    detail=f"Identity forbidden: authenticated in organization '{target_org}', cannot create scar in '{payload.organization_id}'",
                )
            target_org = payload.organization_id
        scar = scar_service.create_scar(db, payload, actor, organization_id=target_org)
        db.commit()
        return scar_service.scar_response(scar).model_dump(mode="json")


def _load_scar(
    db: Session,
    scar_id_or_number: str,
    organization_id: str | None = None,
    *,
    for_update: bool = False,
) -> Scar | None:
    if for_update and db.get_bind().dialect.name == "sqlite":
        # SQLite ignores FOR UPDATE. Take its write lock before reading a
        # candidate so validation, challenge and approval cannot overwrite one another.
        db.connection().exec_driver_sql("BEGIN IMMEDIATE")
    if scar_id_or_number.startswith("scar-") or scar_id_or_number.startswith("scar_"):
        query = select(Scar).where(Scar.id == scar_id_or_number)
        if organization_id and organization_id != "*":
            query = query.where(Scar.organization_id == organization_id)
        if for_update:
            query = query.with_for_update()
        return db.scalar(query)
    if scar_id_or_number.isascii() and scar_id_or_number.isdigit() and len(scar_id_or_number) <= 10:
        query = select(Scar).where(Scar.number == int(scar_id_or_number))
        if organization_id and organization_id != "*":
            query = query.where(Scar.organization_id == organization_id)
        if for_update:
            query = query.with_for_update()
        return db.scalar(query)
    query = select(Scar).where(Scar.id == scar_id_or_number)
    if organization_id and organization_id != "*":
        query = query.where(Scar.organization_id == organization_id)
    if for_update:
        query = query.with_for_update()
    return db.scalar(query)


@app.get("/v1/scars/{scar_id_or_number}")
def get_scar(scar_id_or_number: str, actor: AgentRequired) -> dict[str, Any]:
    with SessionLocal() as db:
        scar = _load_scar(db, scar_id_or_number, organization_id=actor.organization)
        if not scar:
            raise HTTPException(status_code=404, detail="Scar not found")
        return scar_service.scar_response(scar).model_dump(mode="json")


@app.post("/v1/scars/{scar_id_or_number}/validate")
def validate_scar(scar_id_or_number: str, payload: ValidateScarRequest, actor: AgentRequired, sync: bool = Query(False)) -> Any:
    with SessionLocal() as db:
        scar = _load_scar(db, scar_id_or_number, organization_id=actor.organization, for_update=True)
        if not scar:
            raise HTTPException(status_code=404, detail="Scar not found")
        if sync:
            val_start = time.perf_counter()
            try:
                result = validation_pipeline.execute(db, scar, payload, actor, lab)
                metrics.NOPE_VALIDATION_DURATION.observe(
                    time.perf_counter() - val_start,
                    labels={"status": "passed" if result.get("passed") else "failed"},
                )
            except RuleLabError as exc:
                metrics.NOPE_VALIDATION_DURATION.observe(
                    time.perf_counter() - val_start,
                    labels={"status": "error"},
                )
                raise HTTPException(status_code=422, detail=str(exc)) from exc
            db.commit()
            return result

        job = validation_jobs.enqueue_validation(db, scar, payload, actor)
        db.commit()
        status_url = f"/v1/validations/{job.id}"
        return JSONResponse(
            status_code=202,
            content={"job_id": job.id, "status": job.status, "status_url": status_url},
            headers={"Location": status_url},
        )


@app.get("/v1/validations/{job_id}")
def get_validation(job_id: str, actor: AgentRequired) -> dict[str, Any]:
    with SessionLocal() as db:
        job = db.get(ValidationJob, job_id)
        if job is None or (actor.organization != "*" and job.organization_id != actor.organization):
            raise HTTPException(status_code=404, detail="Validation job not found")
        return validation_jobs.job_response(job)


def _safe_json_loads(data: str | None, default: Any = None) -> Any:
    if not data:
        return default
    try:
        return json.loads(data)
    except (json.JSONDecodeError, TypeError):
        return default if default is not None else {"raw": data}


@app.post("/v1/scars/{scar_id_or_number}/adversarial")
def adversarial_scar(scar_id_or_number: str, payload: AdversarialRequest, actor: AgentRequired) -> dict[str, Any]:
    with SessionLocal() as db:
        scar = _load_scar(db, scar_id_or_number, organization_id=actor.organization, for_update=True)
        if scar is None:
            raise HTTPException(404, "Scar not found")
        revision = assurance.latest(db, scar)
        if revision is None:
            raise HTTPException(409, "Validate a rule revision first")
        if revision.challenge is not None:
            raise HTTPException(409, "Challenge evidence is immutable; submit a new rule revision to retry")
        if revision.state not in {"draft", "validated"}:
            raise HTTPException(409, "Challenge a pending revision; approved evidence is immutable")
        try:
            metrics = assurance.adversarial(db, revision, actor, payload.model_dump(), lab)
        except (ValueError, RuleLabError) as exc:
            raise HTTPException(409, str(exc)) from exc
        scar_service._audit(db, actor, "scar.adversarial_completed", {"revision_id": revision.id, **metrics}, scar.id, organization_id=scar.organization_id)
        db.commit()
        return {"revision_id": revision.id, **metrics}


@app.post("/v1/scars/{scar_id_or_number}/reject")
def reject_scar(scar_id_or_number: str, payload: ApprovalRequest, actor: ApproverRequired) -> dict[str, Any]:
    with SessionLocal() as db:
        scar = _load_scar(db, scar_id_or_number, organization_id=actor.organization, for_update=True)
        if scar is None:
            raise HTTPException(404, "Scar not found")
        revision = assurance.latest(db, scar)
        if revision is None or revision.state not in {"draft", "validated"}:
            raise HTTPException(409, "Only a pending revision can be rejected")
        revision.state = "rejected"
        scar.status = "active" if scar.active else "proposed"
        scar_service._audit(db, actor, "scar.rejected", {"revision_id": revision.id, **payload.model_dump()}, scar.id, organization_id=scar.organization_id)
        db.commit()
        return {"revision_id": revision.id, "state": revision.state}


@app.get("/v1/scars/{scar_id_or_number}/provenance")
def scar_provenance(scar_id_or_number: str, actor: CiRequired) -> dict[str, Any]:
    with SessionLocal() as db:
        scar = _load_scar(db, scar_id_or_number, organization_id=actor.organization)
        if scar is None:
            raise HTTPException(404, "Scar not found")
        revisions = db.scalars(select(assurance.Revision).where(assurance.Revision.scar_id == scar.id)
                              .order_by(assurance.Revision.sequence)).all()
        events = db.scalars(select(AuditEvent).where(AuditEvent.scar_id == scar.id)
                           .order_by(AuditEvent.occurred_at, AuditEvent.id)).all()
        rule_shas = {rule.id: rule.sha256 for rule in db.scalars(select(RuleVersion).where(RuleVersion.scar_id == scar.id))}
        return {"scar": scar_service.scar_response(scar).model_dump(mode="json"),
                "revisions": [{"id": r.id, "sequence": r.sequence, "rule_id": r.rule_id, "rule_sha256": rule_shas.get(r.rule_id),
                               "state": r.state, "author": r.author, "adversary": r.adversary,
                               "evidence_sha256": approvals.evidence_hash(db, scar, r),
                               "report": _safe_json_loads(r.report, {}), "challenge": _safe_json_loads(r.challenge) if r.challenge else None}
                              for r in revisions],
                "decisions": [{"id": e.id, "actor": e.actor, "action": e.action,
                               "occurred_at": e.occurred_at.isoformat(), "detail": _safe_json_loads(e.detail, {})} for e in events]}


@app.get("/v1/scars/{scar_id_or_number}/revisions/{revision_id}/{artifact}")
def revision_artifact(scar_id_or_number: str, revision_id: str, artifact: str, actor: CiRequired) -> Any:
    with SessionLocal() as db:
        scar = _load_scar(db, scar_id_or_number, organization_id=actor.organization)
        revision = db.get(assurance.Revision, revision_id)
        if scar is None or revision is None or revision.scar_id != scar.id:
            raise HTTPException(404, "Revision not found")
        if artifact == "tests":
            return {"fixtures": _safe_json_loads(revision.fixtures, {}), "report": _safe_json_loads(revision.report, {}),
                    "challenge": _safe_json_loads(revision.challenge)}
        rule = db.get(RuleVersion, revision.rule_id)
        if artifact == "rule" and rule:
            return {"rule_id": rule.id, "sha256": rule.sha256, "rule_yaml": rule.rule_yaml}
        raise HTTPException(404, "Artifact not found")


@app.post("/v1/scars/{scar_id_or_number}/approval-request")
def request_approval(scar_id_or_number: str, payload: ApprovalProposalRequest, actor: AgentRequired) -> dict[str, Any]:
    with SessionLocal() as db:
        scar = _load_scar(db, scar_id_or_number, organization_id=actor.organization, for_update=True)
        if scar is None:
            raise HTTPException(404, "Scar not found")
        try:
            packet = approvals.request(db, scar, actor, payload.revision_id)
        except ValueError as exc:
            raise HTTPException(409, str(exc)) from exc
        db.commit()
        return packet


@app.post("/v1/scars/{scar_id_or_number}/approve")
def approve_scar(scar_id_or_number: str, payload: ApprovalDecisionRequest, actor: ApproverRequired) -> dict[str, Any]:
    with SessionLocal() as db:
        scar = _load_scar(db, scar_id_or_number, organization_id=actor.organization, for_update=True)
        if not scar:
            raise HTTPException(status_code=404, detail="Scar not found")
        if actor.is_user_identity and payload.approver and payload.approver != actor.subject:
            raise HTTPException(
                status_code=403,
                detail=f"Identity impersonation forbidden: authenticated as '{actor.subject}', cannot approve as '{payload.approver}'",
            )
        try:
            scar = scar_service.approve_scar(db, scar, actor, payload)
            db.commit()
        except ValueError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        return scar_service.scar_response(scar).model_dump(mode="json")


@app.post("/v1/scars/{scar_id_or_number}/activate")
def activate_scar(
    scar_id_or_number: str,
    payload: BreakGlassActivationRequest,
    actor: AdminRequired,
) -> dict[str, Any]:
    """BREAK-GLASS ONLY: Manually activates a scar, bypassing standard GitOps PR merge.

    Requires Admin permissions and an audited justification.
    """
    with SessionLocal() as db:
        scar = _load_scar(db, scar_id_or_number, organization_id=actor.organization, for_update=True)
        if not scar:
            raise HTTPException(status_code=404, detail="Scar not found")
        if actor.is_user_identity and payload.authorized_by and payload.authorized_by != actor.subject:
            raise HTTPException(
                status_code=403,
                detail=f"Identity impersonation forbidden: authenticated as '{actor.subject}', cannot activate as '{payload.authorized_by}'",
            )
        authorized_by = actor.subject if (actor.is_user_identity or not payload.authorized_by) else payload.authorized_by
        try:
            scar = scar_service.activate_scar_break_glass(
                db, scar, actor, authorized_by, payload.reason
            )
            db.commit()
        except ValueError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        return scar_service.scar_response(scar).model_dump(mode="json")


@app.post("/v1/scars/{scar_id_or_number}/challenge", status_code=202)
def challenge_scar(scar_id_or_number: str, payload: ChallengeRequest, actor: AgentRequired) -> dict[str, Any]:
    with SessionLocal() as db:
        scar = _load_scar(db, scar_id_or_number, organization_id=actor.organization)
        if not scar:
            raise HTTPException(status_code=404, detail="Scar not found")
        replacement = None
        replacement_job = None
        if payload.proposed_rule_yaml:
            previous = assurance.active(db, scar)
            if previous is None:
                raise HTTPException(409, "A replacement requires an active revision with preserved incident tests")
            suite = json.loads(previous.fixtures)
            replacement = ValidateScarRequest(rule_yaml=payload.proposed_rule_yaml,
                original=suite["original"], corrected=suite["corrected"],
                bad_examples=payload.bad_examples or suite["bad"], good_examples=payload.good_examples or suite["good"])
            replacement_job = validation_jobs.enqueue_validation(db, scar, replacement, actor)
        record = scar_service.challenge_scar(db, scar, actor, payload)
        db.commit()
        response = {
            "exception_id": record.id,
            "status": record.status,
            "expires_at": record.expires_at.isoformat() if record.expires_at else None,
            "replacement_validation": None,
        }
        if replacement_job is not None:
            status_url = f"/v1/validations/{replacement_job.id}"
            response["replacement_job_id"] = replacement_job.id
            response["replacement_status_url"] = status_url
    return response


@app.get("/v1/exceptions/active")
def list_active_exceptions(
    actor: CiRequired,
    repository: str | None = None,
    include_expired: bool = False,
) -> list[ExceptionResponse]:
    """Retrieve active and unexpired challenge exceptions for CI enforcement."""
    with SessionLocal() as db:
        records = scar_service.list_active_exceptions(
            db, organization_id=actor.organization, repository=repository, include_expired=include_expired
        )
        return [scar_service.exception_response(exc) for exc in records]


@app.post("/v1/exceptions/{exception_id}/approve")
def approve_exception(
    exception_id: str,
    payload: ApproveExceptionRequest,
    actor: ApproverRequired,
) -> ExceptionResponse:
    """Approve a temporary rule challenge exception."""
    with SessionLocal() as db:
        exc = db.get(ExceptionRecord, exception_id)
        if exc is None or (actor.organization != "*" and exc.organization_id != actor.organization):
            raise HTTPException(status_code=404, detail="Exception not found")
        approver = actor.subject if (actor.is_user_identity or not payload.approver) else payload.approver
        try:
            exc = scar_service.approve_exception(db, exception_id, approver, payload.reason, actor)
            db.commit()
            return scar_service.exception_response(exc)
        except ValueError as exc_err:
            raise HTTPException(status_code=409, detail=str(exc_err)) from exc_err


class CiFailure(BaseModel):
    repository: str = Field(min_length=3, max_length=200)
    sha: str = Field(pattern=r"^[0-9a-f]{7,40}$")
    scar_number: int = Field(ge=1)
    check_url: str = Field(min_length=8, max_length=2048)
    revision_id: str | None = Field(default=None, max_length=64)


@app.post("/v1/ci/failure")
def ci_failure(payload: CiFailure, actor: CiRequired) -> dict[str, Any]:
    with SessionLocal() as db:
        scar = scar_service.get_scar_by_number(
            db, payload.scar_number, organization_id=actor.organization, repository=payload.repository
        )
        if not scar:
            scar = scar_service.get_scar_by_number(db, payload.scar_number, organization_id=actor.organization)
        if not scar:
            raise HTTPException(status_code=404, detail="Scar not found")
        if scar.repository != payload.repository:
            raise HTTPException(409, "CI failure repository does not match the active Scar repository scope")
        revision = db.get(assurance.Revision, payload.revision_id) if payload.revision_id else assurance.active(db, scar)
        if revision is not None and (revision.scar_id != scar.id or revision.state not in {"active", "superseded"}):
            raise HTTPException(409, "CI failure must reference an activated revision of this Scar")
        if payload.revision_id and revision is None:
            raise HTTPException(404, "Revision not found")
        if revision is None:
            raise HTTPException(409, "CI provenance requires an activated revision with preserved rule and tests")
        provenance = f"/v1/scars/{scar.number}/provenance"
        base = f"/v1/scars/{scar.number}/revisions/{revision.id}" if revision else None
        detail = {**payload.model_dump(), "revision_id": revision.id if revision else None}
        db.add(AuditEvent(
            id=new_id("ci"),
            scar_id=scar.id,
            organization_id=scar.organization_id,
            actor=actor,
            action="ci.failure_observed",
            detail=json.dumps(detail),
        ))
        metrics.NOPE_CI_FAILURES_TOTAL.inc(
            labels={"scar_number": str(payload.scar_number), "repository": payload.repository}
        )
        db.commit()
        return {
            "scar_number": scar.number,
            "title": scar.title,
            "why": scar.rationale,
            "fix": scar.remediation,
            "incident": scar.incident_url or provenance,
            "origin": scar.origin,
            "revision_id": revision.id if revision else None,
            "approved_rule": base + "/rule" if base else None,
            "tests": base + "/tests" if base else None,
            "history": provenance,
        }


@app.get("/v1/audit")
def audit(actor: ApproverRequired, limit: int = 100) -> list[dict[str, Any]]:
    limit = max(1, min(limit, 500))
    with SessionLocal() as db:
        stmt = select(AuditEvent)
        if actor.organization and actor.organization != "*":
            stmt = stmt.where(AuditEvent.organization_id == actor.organization)
        rows = db.scalars(stmt.order_by(AuditEvent.occurred_at.desc()).limit(limit)).all()
        return [
            {
                "id": row.id,
                "scar_id": row.scar_id,
                "organization_id": row.organization_id,
                "actor": row.actor,
                "action": row.action,
                "occurred_at": row.occurred_at.isoformat(),
                "detail": _safe_json_loads(row.detail, {}),
            }
            for row in rows
        ]


@app.get("/v1/auth/me")
def auth_me(actor: CiRequired) -> dict[str, Any]:
    """Inspect the authenticated caller's identity, role, and organization."""
    return actor.to_dict()


@app.post("/v1/auth/tokens", status_code=201)
def create_token(payload: IssueTokenRequest, actor: AdminRequired) -> TokenResponse:
    """Issue a cryptographically signed HMAC-SHA256 bearer token (Admin only)."""
    from datetime import UTC, datetime, timedelta
    token = issue_token(
        subject=payload.subject,
        role=payload.role,
        expires_in_seconds=payload.expires_in_seconds,
        organization=payload.organization,
    )
    expires_at = (datetime.now(UTC) + timedelta(seconds=payload.expires_in_seconds)).isoformat()
    with SessionLocal() as db:
        scar_service._audit(
            db,
            actor,
            "auth.token_issued",
            {
                "subject": payload.subject,
                "role": payload.role.lower(),
                "organization": payload.organization,
                "expires_in_seconds": payload.expires_in_seconds,
            },
        )
        db.commit()
    return TokenResponse(
        token=token,
        token_type="Bearer",
        subject=payload.subject,
        role=payload.role.lower(),
        organization=payload.organization,
        expires_at=expires_at,
    )


def _verify_github_signature(raw_body: bytes, signature_header: str | None, secret: str) -> bool:
    if not secret:
        return True
    if not signature_header or not signature_header.startswith("sha256="):
        return False
    expected = "sha256=" + hmac.new(secret.encode("utf-8"), raw_body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(signature_header, expected)


class GitHubRepository(BaseModel):
    full_name: str = Field(pattern=r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$", max_length=200)


class GitHubBase(BaseModel):
    ref: str = Field(min_length=1, max_length=250)
    repo: GitHubRepository


class GitHubHead(BaseModel):
    ref: str = Field(min_length=1, max_length=250)


class GitHubUser(BaseModel):
    login: str = Field(min_length=1, max_length=200)


class MergePullRequest(BaseModel):
    number: int = Field(ge=1)
    merge_commit_sha: str = Field(pattern=r"^[a-f0-9]{40}$")
    base: GitHubBase
    head: GitHubHead
    merged_by: GitHubUser | None = None
    user: GitHubUser | None = None
    title: str | None = Field(default=None, max_length=256)
    body: str | None = Field(default=None, max_length=65536)
    html_url: str | None = None


def _extract_scar_number_from_pr(pr_data: dict[str, Any]) -> int | None:
    head_ref = str(pr_data.get("head", {}).get("ref") or "")
    match = re.search(r"(?:^|/)(?:nope/)?scar-(\d+)", head_ref, re.IGNORECASE)
    if match:
        return int(match.group(1)) if len(match.group(1)) <= 10 else None

    title = str(pr_data.get("title") or "")
    match = re.search(r"scar[-\s#]*(\d+)", title, re.IGNORECASE)
    if match:
        return int(match.group(1)) if len(match.group(1)) <= 10 else None

    body = str(pr_data.get("body") or "")
    match = re.search(r"scar[-\s#]*(\d+)", body, re.IGNORECASE)
    if match:
        return int(match.group(1)) if len(match.group(1)) <= 10 else None

    return None


@app.post("/v1/webhooks/github")
async def github_webhook(request: Request) -> dict[str, Any]:
    content_length = request.headers.get("content-length")
    if content_length:
        if not content_length.isascii() or not content_length.isdigit() or len(content_length) > 12:
            raise HTTPException(400, "Invalid Content-Length")
        if int(content_length) > 1_048_576:
            raise HTTPException(status_code=413, detail="Webhook payload exceeds 1MB limit")
    chunks = bytearray()
    async for chunk in request.stream():
        chunks.extend(chunk)
        if len(chunks) > 1_048_576:
            raise HTTPException(status_code=413, detail="Webhook payload exceeds 1MB limit")
    raw_body = bytes(chunks)

    secret = os.getenv("GITHUB_WEBHOOK_SECRET") or settings.github_webhook_secret
    if not secret:
        if not settings.is_development:
            raise HTTPException(status_code=503, detail="GitHub webhook secret is not configured")
    else:
        sig_header = request.headers.get("X-Hub-Signature-256")
        if not _verify_github_signature(raw_body, sig_header, secret):
            raise HTTPException(status_code=401, detail="Invalid or missing GitHub signature")

    delivery_id = request.headers.get("X-GitHub-Delivery")

    event = request.headers.get("X-GitHub-Event")
    if event == "ping":
        return {"status": "ok", "message": "PONG"}
    if event != "pull_request":
        return {"status": "ignored", "reason": f"Unhandled event '{event}'"}

    try:
        payload = json.loads(raw_body.decode("utf-8")) if raw_body else {}
        if not isinstance(payload, dict):
            raise ValueError("Webhook body must be an object")
    except Exception as exc:
        raise HTTPException(status_code=400, detail="Malformed JSON body") from exc

    action = payload.get("action")
    pr = payload.get("pull_request")
    if not isinstance(pr, dict):
        return {"status": "ignored", "reason": "Missing pull_request object in payload"}

    if action != "closed" or pr.get("merged") is not True:
        return {"status": "ignored", "reason": "Pull request is not closed and merged"}

    try:
        pr = MergePullRequest.model_validate(pr).model_dump()
    except ValidationError as exc:
        raise HTTPException(400, "Malformed merged pull request metadata") from exc

    # Guard: Ensure PR was merged into the protected base branch
    base_ref = pr.get("base", {}).get("ref")
    expected_base = settings.base_ref.split("/")[-1]
    if base_ref and base_ref != expected_base:
        return {
            "status": "ignored",
            "reason": f"PR target branch '{base_ref}' does not match expected base branch '{expected_base}'",
        }

    scar_number = _extract_scar_number_from_pr(pr)
    if scar_number is None:
        return {"status": "ignored", "reason": "No scar identifier found in PR metadata"}

    merged_by = (pr.get("merged_by") or {}).get("login") or (pr.get("user") or {}).get("login") or "unknown"
    merge_commit_sha = pr.get("merge_commit_sha") or "unknown"
    head_ref = pr.get("head", {}).get("ref") or ""

    with SessionLocal() as db:
        scar = _load_scar(db, str(scar_number), for_update=True)
        if delivery_id and db.get(WebhookDelivery, delivery_id):
            return {"status": "already_processed", "delivery_id": delivery_id}
        if delivery_id:
            db.add(WebhookDelivery(id=delivery_id, event=event or "pull_request", status="processed"))

        if not scar:
            db.commit()
            return {"status": "ignored", "reason": f"Scar #{scar_number} not found"}

        if pr["base"]["repo"]["full_name"] != scar.repository:
            raise HTTPException(409, "Merged pull request repository does not match the approved Scar scope")

        if scar.active and scar.status != ScarStatus.APPROVED.value:
            db.commit()
            return {"status": "already_active", "scar_number": scar.number}

        if scar.status != ScarStatus.APPROVED.value:
            db.add(
                AuditEvent(
                    id=new_id("audit"),
                    scar_id=scar.id,
                    organization_id=scar.organization_id,
                    actor=f"github:{merged_by}",
                    action="scar.merge_unapproved_warning",
                    detail=json.dumps({
                        "warning": "PR merged for unapproved scar",
                        "current_status": scar.status,
                        "merge_commit_sha": merge_commit_sha,
                        "merged_by": merged_by,
                        "pr_number": pr.get("number"),
                    }),
                )
            )
            db.commit()
            return {
                "status": "ignored",
                "scar_number": scar.number,
                "reason": f"Scar #{scar.number} is in status '{scar.status}', must be 'approved' before activation via merge",
            }

        try:
            revision = assurance.latest(db, scar)
            if revision is None:
                raise ValueError("The merged PR has no approved candidate")
            binding = re.search(r"<!-- nope-approval: (\{[^\n]*\}) -->", pr.get("body") or "")
            if not binding:
                raise ValueError("Merged PR must contain its exact nope-approval evidence binding")
            try:
                bound = json.loads(binding.group(1))
            except ValueError as exc:
                raise ValueError("Merged PR approval binding is malformed") from exc
            if (not isinstance(bound, dict) or bound.get("revision_id") != revision.id
                    or bound.get("evidence_sha256") != approvals.evidence_hash(db, scar, revision)):
                raise ValueError("Merged PR approval binding is stale or belongs to another candidate")
            rule = db.get(RuleVersion, revision.rule_id)
            if rule is None:
                raise ValueError("Approved rule is missing")
            verify_merged_rule(scar.repository, merge_commit_sha, rule.sha256)
            scar_service.activate_scar(db, scar, f"github:{merged_by}")
        except GitHubUnavailable as exc:
            raise HTTPException(503, str(exc)) from exc
        except ValueError as exc:
            raise HTTPException(409, str(exc)) from exc
        db.add(
            AuditEvent(
                id=new_id("audit"),
                scar_id=scar.id,
                organization_id=scar.organization_id,
                actor=f"github:{merged_by}",
                action="scar.activated_via_merge",
                detail=json.dumps({
                    "merge_commit_sha": merge_commit_sha,
                    "merged_by": merged_by,
                    "pr_number": pr.get("number"),
                    "pr_url": pr.get("html_url"),
                    "branch": head_ref,
                }),
            )
        )
        db.commit()
        return {
            "status": "activated",
            "scar_number": scar.number,
            "commit_sha": merge_commit_sha,
            "merged_by": merged_by,
        }


@app.get("/v1/rules/active.yml", response_class=Response)
@app.get("/v1/rules/active.yaml", response_class=Response, include_in_schema=False)
def get_active_rules(actor: CiRequired, repository: str | None = None) -> Response:
    with SessionLocal() as db:
        try:
            yaml_content = scar_service.generate_active_rules_yaml(
                db, organization_id=actor.organization, repository=repository
            )
        except ValueError as exc:
            raise HTTPException(409, str(exc)) from exc
        return Response(content=yaml_content, media_type="application/x-yaml")


@app.get("/", include_in_schema=False)
def dashboard() -> HTMLResponse:
    with SessionLocal() as db:
        scars = scar_service.list_scars(db)
        rows = []
        for scar in scars:
            flag = "ACTIVE" if scar.active else scar.status.upper()
            rows.append(
                f"<tr><td>#{scar.number:03d}</td><td>{_escape(scar.title)}</td>"
                f"<td>{_escape(flag)}</td><td>{_escape(scar.severity)}</td><td>{_escape(scar.repository)}</td></tr>"
            )
    return HTMLResponse(
        "<!doctype html><style>body{font:15px -apple-system,system-ui,color:#e8e5db;background:#08090d;padding:40px}h1{font:42px Georgia;margin:0}p,h2{color:#a9a593}code{color:#d8ff4a}table{border-collapse:collapse;min-width:900px}td,th{border-bottom:1px solid #262820;padding:14px;text-align:left}th{color:#d8ff4a}</style>"
        "<p>SWITCH / NEVER-AGAIN COMPILER</p><h1>NOPE Scar Ledger</h1>"
        "<p>Enforced memory, one repeated mistake at a time. All changes require review.</p>"
        "<table><thead><th>Scar</th><th>Lesson</th><th>Status</th><th>Risk</th><th>Repository</th></thead>"
        + "".join(rows)
        + "</table>"
    )


def _escape(value: str) -> str:
    import html

    return html.escape(str(value))
