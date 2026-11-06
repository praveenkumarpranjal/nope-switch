from __future__ import annotations

import json
from typing import Any

from nope_core import assurance, scar_service
from nope_core.db import Scar
from nope_core.rule_lab import RuleLab, RuleLabError
from nope_core.schemas import ScarStatus, ValidateScarRequest
from sqlalchemy.orm import Session


def execute(db: Session, scar: Scar, payload: ValidateScarRequest, actor: str, lab: RuleLab) -> dict[str, Any]:
    """Execute the deterministic validation pipeline without committing.

    Callers own the transaction boundary so HTTP handlers and background workers
    can persist their job state atomically with the rule, revision and audit rows.
    """
    try:
        rule = scar_service.add_rule_version(db, scar, payload.rule_yaml)
        db.flush()
        revision = assurance.build_revision(
            db,
            scar,
            rule,
            actor,
            {
                "original": payload.original.model_dump(),
                "corrected": payload.corrected.model_dump(),
                "bad": [example.model_dump() for example in payload.bad_examples],
                "good": [example.model_dump() for example in payload.good_examples],
                "target_path": payload.target_path,
            },
            lab,
        )
    except RuleLabError:
        raise

    report = json.loads(revision.report)
    scar.status = ScarStatus.VALIDATED.value if revision.state == "validated" else ScarStatus.PROPOSED.value
    scar.approved_by = None
    scar.approved_reason = None
    scar_service._audit(
        db,
        actor,
        "scar.validation_passed" if revision.state == "validated" else "scar.validation_failed",
        {"revision_id": revision.id, "rule_id": rule.id, **report},
        scar.id,
    )
    return {
        "passed": revision.state == "validated",
        "revision_id": revision.id,
        "replay": report["replay"],
        "regression": report["regression"],
        "quality_threshold": report["quality_threshold"],
        "bad_findings": report["candidate"]["bad_hits"],
        "good_findings": report["candidate"]["good_hits"],
        "target_findings": report["candidate"]["target_hits"],
        "rule_errors": report["candidate"]["rule_errors"],
        "total_bad_examples": len(payload.bad_examples),
        "total_good_examples": len(payload.good_examples),
        "scar": scar_service.scar_response(scar).model_dump(mode="json"),
    }
