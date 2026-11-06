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
from nope_core import scar_service
from nope_core.auth import AgentRequired, ApproverRequired, CiRequired
from nope_core.config import settings
from nope_core.db import AuditEvent, Scar, SessionLocal, init_db, new_id
from nope_core.rule_lab import RuleLab, RuleLabError
from nope_core.schemas import (
    ApprovalRequest,
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
            result = lab.validate(
                payload.rule_yaml,
                [(example.name, example.content) for example in payload.bad_examples],
                [(example.name, example.content) for example in payload.good_examples],
                payload.target_path,
                settings.min_bad_fixture_hits,
                settings.max_good_fixture_hits,
            )
        except RuleLabError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        scar_service.add_rule_version(db, scar, payload.rule_yaml)
        scar_service.record_validation(db, scar, actor, result)
        db.commit()
        return {
            "passed": result.passed,
            "bad_findings": result.bad_hits,
            "good_findings": result.good_hits,
            "target_findings": result.target_hits,
            "rule_errors": result.rule_errors,
            "total_bad_examples": len(payload.bad_examples),
            "total_good_examples": len(payload.good_examples),
            "scar": scar_service.scar_response(scar).model_dump(mode="json"),
        }


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
def activate_scar(scar_id_or_number: str, actor: ApproverRequired) -> dict[str, Any]:
    with SessionLocal() as db:
        scar = _load_scar(db, scar_id_or_number)
        if not scar:
            raise HTTPException(status_code=404, detail="Scar not found")
        try:
            scar = scar_service.activate_scar(db, scar, actor)
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
        validation = None
        if payload.proposed_rule_yaml:
            try:
                validation = lab.validate(
                    payload.proposed_rule_yaml,
                    [(example.name, example.content) for example in payload.bad_examples],
                    [(example.name, example.content) for example in payload.good_examples],
                    None,
                    settings.min_bad_fixture_hits,
                    settings.max_good_fixture_hits,
                )
            except RuleLabError as exc:
                raise HTTPException(status_code=422, detail=str(exc)) from exc
            scar_service.add_rule_version(db, scar, payload.proposed_rule_yaml)
        record = scar_service.challenge_scar(db, scar, actor, payload)
        if validation:
            scar_service.record_validation(db, scar, actor, validation)
        db.commit()
        return {
            "exception_id": record.id,
            "status": record.status,
            "expires_at": record.expires_at.isoformat() if record.expires_at else None,
            "replacement_validation": getattr(validation, "passed", None),
        }


class CiFailure(BaseModel):
    repository: str = Field(min_length=3, max_length=200)
    sha: str = Field(pattern=r"^[0-9a-f]{7,40}$")
    scar_number: int = Field(ge=1)
    check_url: str = Field(min_length=8, max_length=2048)


@app.post("/v1/ci/failure")
def ci_failure(payload: CiFailure, actor: CiRequired) -> dict[str, Any]:
    with SessionLocal() as db:
        scar = scar_service.get_scar_by_number(db, payload.scar_number)
        if not scar:
            raise HTTPException(status_code=404, detail="Scar not found")
        db.add(AuditEvent(
            id=new_id("ci"),
            scar_id=scar.id,
            actor=actor,
            action="ci.failure_observed",
            detail=payload.model_dump_json(),
        ))
        db.commit()
        return {
            "scar_number": scar.number,
            "title": scar.title,
            "why": scar.rationale,
            "fix": scar.remediation,
            "incident": scar.incident_url,
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
    raw_body = await request.body()
    secret = os.getenv("GITHUB_WEBHOOK_SECRET") or settings.github_webhook_secret
    if not secret:
        if not settings.is_development:
            raise HTTPException(status_code=503, detail="GitHub webhook secret is not configured")
    else:
        sig_header = request.headers.get("X-Hub-Signature-256")
        if not _verify_github_signature(raw_body, sig_header, secret):
            raise HTTPException(status_code=401, detail="Invalid or missing GitHub signature")

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

    scar_number = _extract_scar_number_from_pr(pr)
    if scar_number is None:
        return {"status": "ignored", "reason": "No scar identifier found in PR metadata"}

    merged_by = (pr.get("merged_by") or {}).get("login") or (pr.get("user") or {}).get("login") or "unknown"
    merge_commit_sha = pr.get("merge_commit_sha") or "unknown"
    head_ref = pr.get("head", {}).get("ref") or ""

    with SessionLocal() as db:
        scar = scar_service.get_scar_by_number(db, scar_number)
        if not scar:
            return {"status": "ignored", "reason": f"Scar #{scar_number} not found"}

        if scar.active:
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

        scar.status = ScarStatus.ACTIVE.value
        scar.active = True
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
        yaml_content = scar_service.generate_active_rules_yaml(db)
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
