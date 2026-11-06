"""Immutable test evidence and approval gates for a Scar rule revision."""

from __future__ import annotations

import hashlib
import json
from typing import Any

from nope_core.db import Revision, RuleVersion, Scar, new_id
from nope_core.rule_lab import RuleLab
from sqlalchemy import select
from sqlalchemy.orm import Session

# Re-export Revision for backwards compatibility
__all__ = ["QUALITY", "Revision", "active", "adversarial", "build_revision", "latest", "pairs", "require_quality"]

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

    # Deduplicate historical fixtures by content hash to prevent quadratic growth and file limit exhaustion
    seen_bad: set[str] = set()
    deduped_bad: list[dict[str, str]] = []
    for e in historical["bad"]:
        content_hash = hashlib.sha256(e["content"].strip().encode()).hexdigest()
        if content_hash not in seen_bad:
            seen_bad.add(content_hash)
            deduped_bad.append(e)

    seen_good: set[str] = set()
    deduped_good: list[dict[str, str]] = []
    for e in historical["good"]:
        content_hash = hashlib.sha256(e["content"].strip().encode()).hexdigest()
        if content_hash not in seen_good:
            seen_good.add(content_hash)
            deduped_good.append(e)

    # Bound historical regression suites to prevent runaway resource exhaustion
    MAX_HISTORICAL = 100
    deduped_bad = deduped_bad[-MAX_HISTORICAL:]
    deduped_good = deduped_good[-MAX_HISTORICAL:]

    replay = lab.validate(
        rule.rule_yaml, pairs([fixtures["original"]]), pairs([fixtures["corrected"]])
    )
    candidate = lab.validate(
        rule.rule_yaml, pairs(fixtures["bad"]), pairs(fixtures["good"]), fixtures.get("target_path")
    )
    regression = (
        lab.validate(rule.rule_yaml, renamed(deduped_bad), renamed(deduped_good))
        if deduped_bad
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
            "bad_examples": len(deduped_bad),
            "good_examples": len(deduped_good),
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
    author_suite = json.loads(revision.fixtures or "{}")
    all_author_examples: list[dict[str, Any]] = []
    if isinstance(author_suite.get("original"), dict):
        all_author_examples.append(author_suite["original"])
    if isinstance(author_suite.get("corrected"), dict):
        all_author_examples.append(author_suite["corrected"])
    if isinstance(author_suite.get("bad"), list):
        all_author_examples.extend(e for e in author_suite["bad"] if isinstance(e, dict))
    if isinstance(author_suite.get("good"), list):
        all_author_examples.extend(e for e in author_suite["good"] if isinstance(e, dict))

    author_content = {
        str(e["content"]).strip()
        for e in all_author_examples
        if "content" in e and e["content"] is not None
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
    detection_rate = (detections / total_bad) if total_bad > 0 else 0.0
    false_positive_rate = (false_positives / total_good) if total_good > 0 else 0.0
    metrics = {
        "detections": detections,
        "misses": max(0, total_bad - detections),
        "false_positives": false_positives,
        "true_negatives": max(0, total_good - false_positives),
        "detection_rate": detection_rate,
        "false_positive_rate": false_positive_rate,
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
