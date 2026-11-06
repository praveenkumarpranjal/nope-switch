"""Immutable test evidence and approval gates for a Scar rule revision."""

from __future__ import annotations

import json
from typing import Any

from nope_core.db import Base, RuleVersion, Scar, new_id
from nope_core.rule_lab import RuleLab
from sqlalchemy import ForeignKey, Integer, String, Text, select
from sqlalchemy.orm import Mapped, Session, mapped_column


class Revision(Base):
    __tablename__ = "scar_revisions"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    scar_id: Mapped[str] = mapped_column(ForeignKey("scars.id"), index=True)
    rule_id: Mapped[str] = mapped_column(ForeignKey("rule_versions.id"))
    sequence: Mapped[int] = mapped_column(Integer)
    author: Mapped[str] = mapped_column(String(200))
    state: Mapped[str] = mapped_column(String(24), default="draft")
    fixtures: Mapped[str] = mapped_column(Text)
    report: Mapped[str] = mapped_column(Text)
    adversary: Mapped[str | None] = mapped_column(String(200), nullable=True)
    challenge: Mapped[str | None] = mapped_column(Text, nullable=True)


QUALITY = {
    "min_bad_examples": 6,
    "min_good_examples": 4,
    "min_detection_rate": 1.0,
    "max_false_positive_rate": 0.0,
}


def latest(db: Session, scar: Scar) -> Revision | None:
    return db.scalar(
        select(Revision)
        .where(Revision.scar_id == scar.id)
        .order_by(Revision.sequence.desc())
        .limit(1)
    )


def active(db: Session, scar: Scar) -> Revision | None:
    return db.scalar(
        select(Revision).where(Revision.scar_id == scar.id, Revision.state == "active")
    )


def pairs(examples: list[dict[str, str]]) -> list[tuple[str, str]]:
    return [(e["name"], e["content"]) for e in examples]


def build_revision(
    db: Session, scar: Scar, rule: RuleVersion, actor: str, fixtures: dict[str, Any], lab: RuleLab
) -> Revision:
    # Include every previously accepted suite, including independent challenges.
    historical: dict[str, list[dict[str, str]]] = {"bad": [], "good": []}
    for previous in db.scalars(
        select(Revision).where(Revision.scar_id == scar.id).order_by(Revision.sequence)
    ):
        if previous.state not in {"approved", "active", "superseded"}:
            continue
        suite = json.loads(previous.fixtures)
        historical["bad"].extend([suite["original"], *suite["bad"]])
        historical["good"].extend([suite["corrected"], *suite["good"]])
        if previous.challenge:
            challenge = json.loads(previous.challenge)
            historical["bad"].extend(challenge["bad_examples"])
            historical["good"].extend(challenge["good_examples"])

    # Stable generated names prevent collisions across historical suites.
    def renamed(items: list[dict[str, str]]) -> list[tuple[str, str]]:
        return [
            (f"regression-{i}{lab._example_extension(e['name'])}", e["content"])
            for i, e in enumerate(items)
        ]

    replay = lab.validate(
        rule.rule_yaml, pairs([fixtures["original"]]), pairs([fixtures["corrected"]])
    )
    candidate = lab.validate(
        rule.rule_yaml, pairs(fixtures["bad"]), pairs(fixtures["good"]), fixtures.get("target_path")
    )
    regression = (
        lab.validate(rule.rule_yaml, renamed(historical["bad"]), renamed(historical["good"]))
        if historical["bad"]
        else None
    )
    report = {
        "replay": {
            "passed": replay.passed,
            "original_detected": bool(replay.bad_hits) and all(replay.bad_hits.values()),
            "corrected_passes": bool(replay.good_hits) and not any(replay.good_hits.values()),
            "errors": replay.rule_errors,
        },
        "candidate": candidate.__dict__,
        "regression": {
            "passed": regression.passed if regression else True,
            "bad_examples": len(historical["bad"]),
            "good_examples": len(historical["good"]),
            "result": regression.__dict__ if regression else None,
        },
        "quality_threshold": dict(QUALITY),
    }
    passed = replay.passed and candidate.passed and (regression is None or regression.passed)
    revision = Revision(
        id=new_id("rev"),
        scar_id=scar.id,
        rule_id=rule.id,
        sequence=rule.version,
        author=actor,
        state="validated" if passed else "draft",
        fixtures=json.dumps(fixtures),
        report=json.dumps(report),
    )
    db.add(revision)
    return revision


def adversarial(
    db: Session, revision: Revision, actor: str, payload: dict[str, Any], lab: RuleLab
) -> dict[str, Any]:
    if actor == revision.author:
        raise ValueError(
            "The adversarial agent must use a different authenticated identity from the rule author"
        )
    if revision.state not in {"draft", "validated"}:
        raise ValueError("Challenge a pending revision; approved evidence is immutable")
    if revision.challenge is not None:
        raise ValueError("Challenge evidence is immutable; submit a new rule revision to retry")
    author_suite = json.loads(revision.fixtures)
    author_content = {
        e["content"].strip()
        for e in [
            author_suite["original"],
            author_suite["corrected"],
            *author_suite["bad"],
            *author_suite["good"],
        ]
    }
    examples = payload["bad_examples"] + payload["good_examples"]
    if any(e["content"].strip() in author_content for e in examples):
        raise ValueError("Independent examples must differ from the author's fixtures")
    rule = db.get(RuleVersion, revision.rule_id)
    if rule is None:
        raise ValueError("Revision rule is missing")
    result = lab.validate(
        rule.rule_yaml, pairs(payload["bad_examples"]), pairs(payload["good_examples"])
    )
    detections = sum(h > 0 for h in result.bad_hits.values())
    total_bad, total_good = len(payload["bad_examples"]), len(payload["good_examples"])
    false_positives = sum(h > 0 for h in result.good_hits.values())
    metrics = {
        "detections": detections,
        "misses": total_bad - detections,
        "false_positives": false_positives,
        "true_negatives": total_good - false_positives,
        "detection_rate": detections / total_bad,
        "false_positive_rate": false_positives / total_good,
        "bad_findings": result.bad_hits,
        "good_findings": result.good_hits,
        "errors": result.rule_errors,
    }
    threshold = json.loads(revision.report)["quality_threshold"]
    metrics["passed"] = (
        not result.rule_errors
        and len(result.bad_hits) == total_bad
        and len(result.good_hits) == total_good
        and total_bad >= threshold["min_bad_examples"]
        and total_good >= threshold["min_good_examples"]
        and metrics["detection_rate"] >= threshold["min_detection_rate"]
        and metrics["false_positive_rate"] <= threshold["max_false_positive_rate"]
    )
    revision.adversary = actor
    revision.challenge = json.dumps({**payload, "metrics": metrics})
    return metrics


def require_quality(revision: Revision | None) -> Revision:
    if revision is None or revision.state != "validated":
        raise ValueError(
            "A pending revision must pass replay, validation, and all historical regressions"
        )
    if not revision.challenge or not json.loads(revision.challenge)["metrics"]["passed"]:
        raise ValueError(
            "Independent adversarial challenge must meet the predefined quality threshold"
        )
    return revision
