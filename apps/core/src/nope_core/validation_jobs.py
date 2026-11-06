from __future__ import annotations

import json
import os
import time
from datetime import UTC, datetime, timedelta
from typing import Any

from nope_core.db import Scar, SessionLocal, ValidationJob, new_id
from nope_core.rule_lab import RuleLab, RuleLabError
from nope_core.schemas import ValidateScarRequest
from nope_core.validation_pipeline import execute
from sqlalchemy import select, update
from sqlalchemy.orm import Session

MAX_ERROR = 4000
MAX_ATTEMPTS = 3
STALE_SECONDS = int(os.getenv("NOPE_VALIDATION_STALE_SECONDS", "900"))


def enqueue_validation(db: Session, scar: Scar, payload: ValidateScarRequest, actor: str) -> ValidationJob:
    job = ValidationJob(
        id=new_id("val"),
        scar_id=scar.id,
        actor=actor,
        status="pending",
        payload=payload.model_dump_json(),
        attempts=0,
    )
    db.add(job)
    return job


def _claim_next(db: Session) -> str | None:
    cutoff = datetime.now(UTC) - timedelta(seconds=STALE_SECONDS)
    db.execute(
        update(ValidationJob)
        .where(ValidationJob.status == "running", ValidationJob.started_at < cutoff, ValidationJob.attempts >= MAX_ATTEMPTS)
        .values(status="failed", error=f"Job exceeded maximum retry attempts ({MAX_ATTEMPTS})", finished_at=datetime.now(UTC))
    )
    db.execute(
        update(ValidationJob)
        .where(ValidationJob.status == "running", ValidationJob.started_at < cutoff, ValidationJob.attempts < MAX_ATTEMPTS)
        .values(status="pending", error="Recovered stale worker execution")
    )
    candidate = (
        select(ValidationJob.id)
        .where(ValidationJob.status == "pending")
        .order_by(ValidationJob.created_at, ValidationJob.id)
        .limit(1)
        .scalar_subquery()
    )
    claimed = db.execute(
        update(ValidationJob)
        .where(ValidationJob.id == candidate, ValidationJob.status == "pending")
        .values(
            status="running",
            started_at=datetime.now(UTC),
            finished_at=None,
            attempts=ValidationJob.attempts + 1,
            error=None,
        )
        .returning(ValidationJob.id)
    ).scalar_one_or_none()
    if claimed is None:
        db.commit()
        return None
    db.commit()
    return str(claimed) if claimed is not None else None


def run_job(job_id: str) -> None:
    lab = RuleLab()
    with SessionLocal() as db:
        job = db.get(ValidationJob, job_id)
        if job is None or job.status != "running":
            return
        try:
            payload = ValidateScarRequest.model_validate_json(job.payload)
            scar = db.get(Scar, job.scar_id) if job.scar_id else None
            if scar is None:
                raise ValueError("Scar for validation job was deleted")
            result = execute(db, scar, payload, job.actor, lab)
            job.status = "completed"
            job.result = json.dumps(result, default=str)
            job.error = None
            job.finished_at = datetime.now(UTC)
            db.commit()
        except RuleLabError as exc:
            db.rollback()
            _mark_failed(job_id, f"Rule validation error: {exc}")
        except Exception as exc:
            db.rollback()
            _mark_failed(job_id, f"{exc.__class__.__name__}: {exc}")


def _mark_failed(job_id: str, message: str) -> None:
    with SessionLocal() as db:
        job = db.get(ValidationJob, job_id)
        if job is None:
            return
        job.status = "failed"
        job.error = (message or "Unknown validation failure")[:MAX_ERROR]
        job.finished_at = datetime.now(UTC)
        db.commit()


def run_once() -> int:
    with SessionLocal() as db:
        job_id = _claim_next(db)
    if job_id is None:
        return 0
    run_job(job_id)
    return 1


def run_worker(poll_interval: float, max_jobs: int | None = None) -> int:
    processed = 0
    while True:
        did_work = run_once()
        if did_work:
            processed += 1
            if max_jobs is not None and processed >= max_jobs:
                return processed
            continue
        time.sleep(poll_interval)


def job_response(job: ValidationJob) -> dict[str, Any]:
    result: Any = None
    if job.result:
        try:
            result = json.loads(job.result)
        except json.JSONDecodeError:
            result = {"parse_error": "Validation result payload is invalid JSON"}
    return {
        "job_id": job.id,
        "status": job.status,
        "scar_id": job.scar_id,
        "actor": job.actor,
        "attempts": job.attempts,
        "created_at": job.created_at.isoformat(),
        "started_at": job.started_at.isoformat() if job.started_at else None,
        "finished_at": job.finished_at.isoformat() if job.finished_at else None,
        "result": result,
        "error": job.error,
    }
