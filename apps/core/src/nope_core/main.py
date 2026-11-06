from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any

from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.responses import HTMLResponse
from nope_core import assurance, scar_service
from nope_core.auth import AdminRequired, AgentRequired, ApproverRequired, CiRequired
from nope_core.config import settings
from nope_core.db import (
    AuditEvent,
    RuleVersion,
    Scar,
    SessionLocal,
    WebhookDelivery,
    init_db,
    new_id,
)
from nope_core.rule_lab import RuleLab, RuleLabError
from nope_core.schemas import (
    AdversarialRequest,
    ApprovalRequest,
    BreakGlassActivationRequest,
    ChallengeRequest,
    CreateScarRequest,
    ScarStatus,
    ValidateScarRequest,
)
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session


@asynccontextmanager
async def lifespan(_: FastAPI) -> AsyncIterator[None]:
    init_db()
    yield


app = FastAPI(title="NOPE Never-Again Compiler", version="1.0.0", docs_url="/docs", redoc_url=None, lifespan=lifespan)
lab = RuleLab()


@app.get("/health")
def health() -> dict[str, Any]:
    return {"status": "ok", "service": "nope-core", "version": "1.0.0", "env": settings.env}


@app.get("/v1/scars")
def list_scars(_: AgentRequired) -> list[dict[str, Any]]:
    with SessionLocal() as db:
        return [scar_service.scar_response(scar).model_dump(mode="json") for scar in scar_service.list_scars(db)]


@app.post("/v1/scars", status_code=201)
def create_scar(payload: CreateScarRequest, actor: AgentRequired) -> dict[str, Any]:
    with SessionLocal() as db:
        scar = scar_service.create_scar(db, payload, actor)
        db.commit()
        return scar_service.scar_response(scar).model_dump(mode="json")


def _load_scar(db: Session, scar_id_or_number: str) -> Scar | None:
    scar: Scar | None = db.get(Scar, scar_id_or_number)
    if scar is not None:
        return scar
    if scar_id_or_number.isdigit():
        scar = db.scalar(select(Scar).where(Scar.number == int(scar_id_or_number)))
        return scar
    return None


@app.get("/v1/scars/{scar_id_or_number}")
def get_scar(scar_id_or_number: str, _: AgentRequired) -> dict[str, Any]:
    with SessionLocal() as db:
        scar = _load_scar(db, scar_id_or_number)
        if not scar:
            raise HTTPException(status_code=404, detail="Scar not found")
        return scar_service.scar_response(scar).model_dump(mode="json")


@app.post("/v1/scars/{scar_id_or_number}/validate")
def validate_scar(scar_id_or_number: str, payload: ValidateScarRequest, actor: AgentRequired) -> dict[str, Any]:
    with SessionLocal() as db:
        scar = _load_scar(db, scar_id_or_number)
        if not scar:
            raise HTTPException(status_code=404, detail="Scar not found")
        try:
            rule = scar_service.add_rule_version(db, scar, payload.rule_yaml)
            db.flush()
            revision = assurance.build_revision(db, scar, rule, actor, {
                "original": payload.original.model_dump(), "corrected": payload.corrected.model_dump(),
                "bad": [e.model_dump() for e in payload.bad_examples],
                "good": [e.model_dump() for e in payload.good_examples], "target_path": payload.target_path,
            }, lab)
        except RuleLabError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        report = json.loads(revision.report)
        scar.status = "validated" if revision.state == "validated" else "proposed"
        scar.approved_by = None
        scar.approved_reason = None
        scar_service._audit(db, actor, "scar.validation_passed" if revision.state == "validated" else "scar.validation_failed",
                            {"revision_id": revision.id, "rule_id": rule.id, **report}, scar.id)
        db.commit()
        return {
            "passed": revision.state == "validated",
            "revision_id": revision.id,
            "replay": report["replay"], "regression": report["regression"],
            "quality_threshold": report["quality_threshold"],
            "bad_findings": report["candidate"]["bad_hits"],
            "good_findings": report["candidate"]["good_hits"],
            "target_findings": report["candidate"]["target_hits"],
            "rule_errors": report["candidate"]["rule_errors"],
            "total_bad_examples": len(payload.bad_examples),
            "total_good_examples": len(payload.good_examples),
            "scar": scar_service.scar_response(scar).model_dump(mode="json"),
        }


@app.post("/v1/scars/{scar_id_or_number}/adversarial")
def adversarial_scar(scar_id_or_number: str, payload: AdversarialRequest, actor: AgentRequired) -> dict[str, Any]:
    with SessionLocal() as db:
        scar = _load_scar(db, scar_id_or_number)
        if scar is None:
            raise HTTPException(404, "Scar not found")
        revision = assurance.latest(db, scar)
        if revision is None:
            raise HTTPException(409, "Validate a rule revision first")
        try:
            metrics = assurance.adversarial(db, revision, actor, payload.model_dump(), lab)
        except (ValueError, RuleLabError) as exc:
            raise HTTPException(409, str(exc)) from exc
        scar_service._audit(db, actor, "scar.adversarial_completed", {"revision_id": revision.id, **metrics}, scar.id)
        db.commit()
        return {"revision_id": revision.id, **metrics}


@app.post("/v1/scars/{scar_id_or_number}/reject")
def reject_scar(scar_id_or_number: str, payload: ApprovalRequest, actor: ApproverRequired) -> dict[str, Any]:
    with SessionLocal() as db:
        scar = _load_scar(db, scar_id_or_number)
        if scar is None:
            raise HTTPException(404, "Scar not found")
        revision = assurance.latest(db, scar)
        if revision is None or revision.state not in {"draft", "validated"}:
            raise HTTPException(409, "Only a pending revision can be rejected")
        revision.state = "rejected"
        scar.status = "active" if scar.active else "proposed"
        scar_service._audit(db, actor, "scar.rejected", {"revision_id": revision.id, **payload.model_dump()}, scar.id)
        db.commit()
        return {"revision_id": revision.id, "state": revision.state}


@app.get("/v1/scars/{scar_id_or_number}/provenance")
def scar_provenance(scar_id_or_number: str, _: CiRequired) -> dict[str, Any]:
    with SessionLocal() as db:
        scar = _load_scar(db, scar_id_or_number)
        if scar is None:
            raise HTTPException(404, "Scar not found")
        revisions = db.scalars(select(assurance.Revision).where(assurance.Revision.scar_id == scar.id)
                              .order_by(assurance.Revision.sequence)).all()
        events = db.scalars(select(AuditEvent).where(AuditEvent.scar_id == scar.id)
                           .order_by(AuditEvent.occurred_at, AuditEvent.id)).all()
        return {"scar": scar_service.scar_response(scar).model_dump(mode="json"),
                "revisions": [{"id": r.id, "sequence": r.sequence, "rule_id": r.rule_id,
                               "state": r.state, "author": r.author, "adversary": r.adversary,
                               "report": json.loads(r.report), "challenge": json.loads(r.challenge) if r.challenge else None}
                              for r in revisions],
                "decisions": [{"id": e.id, "actor": e.actor, "action": e.action,
                               "occurred_at": e.occurred_at.isoformat(), "detail": json.loads(e.detail)} for e in events]}


@app.get("/v1/scars/{scar_id_or_number}/revisions/{revision_id}/{artifact}")
def revision_artifact(scar_id_or_number: str, revision_id: str, artifact: str, _: CiRequired) -> Any:
    with SessionLocal() as db:
        scar = _load_scar(db, scar_id_or_number)
        revision = db.get(assurance.Revision, revision_id)
        if scar is None or revision is None or revision.scar_id != scar.id:
            raise HTTPException(404, "Revision not found")
        if artifact == "tests":
            return {"fixtures": json.loads(revision.fixtures), "report": json.loads(revision.report),
                    "challenge": json.loads(revision.challenge) if revision.challenge else None}
        rule = db.get(RuleVersion, revision.rule_id)
        if artifact == "rule" and rule:
            return {"rule_id": rule.id, "sha256": rule.sha256, "rule_yaml": rule.rule_yaml}
        raise HTTPException(404, "Artifact not found")


@app.post("/v1/scars/{scar_id_or_number}/approve")
def approve_scar(scar_id_or_number: str, payload: ApprovalRequest, actor: ApproverRequired) -> dict[str, Any]:
    with SessionLocal() as db:
        scar = _load_scar(db, scar_id_or_number)
        if not scar:
            raise HTTPException(status_code=404, detail="Scar not found")
        try:
            scar = scar_service.approve_scar(db, scar, actor, payload.approver, payload.reason)
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
        scar = _load_scar(db, scar_id_or_number)
        if not scar:
            raise HTTPException(status_code=404, detail="Scar not found")
        try:
            scar = scar_service.activate_scar_break_glass(
                db, scar, actor, payload.authorized_by, payload.reason
            )
            db.commit()
        except ValueError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        return scar_service.scar_response(scar).model_dump(mode="json")


@app.post("/v1/scars/{scar_id_or_number}/challenge", status_code=202)
def challenge_scar(scar_id_or_number: str, payload: ChallengeRequest, actor: AgentRequired) -> dict[str, Any]:
    with SessionLocal() as db:
        scar = _load_scar(db, scar_id_or_number)
        if not scar:
            raise HTTPException(status_code=404, detail="Scar not found")
        replacement = None
        if payload.proposed_rule_yaml:
            previous = assurance.active(db, scar)
            if previous is None:
                raise HTTPException(409, "A replacement requires an active revision with preserved incident tests")
            suite = json.loads(previous.fixtures)
            replacement = ValidateScarRequest(rule_yaml=payload.proposed_rule_yaml,
                original=suite["original"], corrected=suite["corrected"],
                bad_examples=payload.bad_examples or suite["bad"], good_examples=payload.good_examples or suite["good"])
        record = scar_service.challenge_scar(db, scar, actor, payload)
        db.commit()
        response = {
            "exception_id": record.id,
            "status": record.status,
            "expires_at": record.expires_at.isoformat() if record.expires_at else None,
            "replacement_validation": None,
        }
    if replacement:
        validation = validate_scar(scar_id_or_number, replacement, actor)
        response["replacement_validation"] = validation["passed"]
        response["revision_id"] = validation["revision_id"]
        response["regression"] = validation["regression"]
    return response


class CiFailure(BaseModel):
    repository: str = Field(min_length=3, max_length=200)
    sha: str = Field(pattern=r"^[0-9a-f]{7,40}$")
    scar_number: int = Field(ge=1)
    check_url: str = Field(min_length=8, max_length=2048)
    revision_id: str | None = Field(default=None, max_length=64)


@app.post("/v1/ci/failure")
def ci_failure(payload: CiFailure, actor: CiRequired) -> dict[str, Any]:
    with SessionLocal() as db:
        scar = scar_service.get_scar_by_number(db, payload.scar_number)
        if not scar:
            raise HTTPException(status_code=404, detail="Scar not found")
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
            actor=actor,
            action="ci.failure_observed",
            detail=json.dumps(detail),
        ))
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
def audit(_: ApproverRequired, limit: int = 100) -> list[dict[str, Any]]:
    limit = max(1, min(limit, 500))
    with SessionLocal() as db:
        rows = db.scalars(select(AuditEvent).order_by(AuditEvent.occurred_at.desc()).limit(limit)).all()
        return [
            {
                "id": row.id,
                "scar_id": row.scar_id,
                "actor": row.actor,
                "action": row.action,
                "occurred_at": row.occurred_at.isoformat(),
                "detail": json.loads(row.detail),
            }
            for row in rows
        ]


def _verify_github_signature(raw_body: bytes, signature_header: str | None, secret: str) -> bool:
    if not secret:
        return True
    if not signature_header or not signature_header.startswith("sha256="):
        return False
    expected = "sha256=" + hmac.new(secret.encode("utf-8"), raw_body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(signature_header, expected)


def _extract_scar_number_from_pr(pr_data: dict[str, Any]) -> int | None:
    head_ref = str(pr_data.get("head", {}).get("ref") or "")
    match = re.search(r"(?:^|/)(?:nope/)?scar-(\d+)", head_ref, re.IGNORECASE)
    if match:
        return int(match.group(1))

    title = str(pr_data.get("title") or "")
    match = re.search(r"scar[-\s#]*(\d+)", title, re.IGNORECASE)
    if match:
        return int(match.group(1))

    body = str(pr_data.get("body") or "")
    match = re.search(r"scar[-\s#]*(\d+)", body, re.IGNORECASE)
    if match:
        return int(match.group(1))

    return None


@app.post("/v1/webhooks/github")
async def github_webhook(request: Request) -> dict[str, Any]:
    content_length = request.headers.get("content-length")
    if content_length and int(content_length) > 1_048_576:
        raise HTTPException(status_code=413, detail="Webhook payload exceeds 1MB limit")

    raw_body = await request.body()
    if len(raw_body) > 1_048_576:
        raise HTTPException(status_code=413, detail="Webhook payload exceeds 1MB limit")

    secret = os.getenv("GITHUB_WEBHOOK_SECRET") or settings.github_webhook_secret
    if not secret:
        if not settings.is_development:
            raise HTTPException(status_code=503, detail="GitHub webhook secret is not configured")
    else:
        sig_header = request.headers.get("X-Hub-Signature-256")
        if not _verify_github_signature(raw_body, sig_header, secret):
            raise HTTPException(status_code=401, detail="Invalid or missing GitHub signature")

    delivery_id = request.headers.get("X-GitHub-Delivery")
    if delivery_id:
        with SessionLocal() as db:
            if db.get(WebhookDelivery, delivery_id):
                return {"status": "already_processed", "delivery_id": delivery_id}

    event = request.headers.get("X-GitHub-Event")
    if event == "ping":
        return {"status": "ok", "message": "PONG"}
    if event != "pull_request":
        return {"status": "ignored", "reason": f"Unhandled event '{event}'"}

    try:
        payload = json.loads(raw_body.decode("utf-8")) if raw_body else {}
    except Exception as exc:
        raise HTTPException(status_code=400, detail="Malformed JSON body") from exc

    action = payload.get("action")
    pr = payload.get("pull_request")
    if not isinstance(pr, dict):
        return {"status": "ignored", "reason": "Missing pull_request object in payload"}

    if action != "closed" or pr.get("merged") is not True:
        return {"status": "ignored", "reason": "Pull request is not closed and merged"}

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
        if delivery_id:
            db.add(WebhookDelivery(id=delivery_id, event=event or "pull_request", status="processed"))

        scar = scar_service.get_scar_by_number(db, scar_number)
        if not scar:
            db.commit()
            return {"status": "ignored", "reason": f"Scar #{scar_number} not found"}

        if scar.active and scar.status != ScarStatus.APPROVED.value:
            db.commit()
            return {"status": "already_active", "scar_number": scar.number}

        if scar.status != ScarStatus.APPROVED.value:
            db.add(
                AuditEvent(
                    id=new_id("audit"),
                    scar_id=scar.id,
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
            scar_service.activate_scar(db, scar, f"github:{merged_by}")
        except ValueError as exc:
            raise HTTPException(409, str(exc)) from exc
        db.add(
            AuditEvent(
                id=new_id("audit"),
                scar_id=scar.id,
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
def get_active_rules(_: CiRequired) -> Response:
    with SessionLocal() as db:
        try:
            yaml_content = scar_service.generate_active_rules_yaml(db)
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
