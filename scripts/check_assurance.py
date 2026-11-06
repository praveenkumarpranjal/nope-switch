"""Run the shipped policy against the original incident and independent challenge."""

import json
from pathlib import Path

from nope_core.rule_lab import RuleLab

ROOT = Path(__file__).resolve().parents[1]


def main() -> None:
    lab = RuleLab()
    fixtures = ROOT / "demo-app" / "fixtures"
    rule = (ROOT / "config" / ".semgrep" / "nope-active.yml").read_text(encoding="utf-8")
    replay = lab.validate(
        rule,
        [
            ("original.ts", (fixtures / "bad-authorization-log.ts").read_text(encoding="utf-8")),
            (
                "credential-object.ts",
                "declare const secret: string; console.log({authorization: secret});",
            ),
        ],
        [("corrected.ts", (fixtures / "good-redacted-log.ts").read_text(encoding="utf-8"))],
    )
    bundle = json.loads((fixtures / "adversarial-challenge.json").read_text(encoding="utf-8"))
    challenge = lab.validate(
        rule,
        [(e["name"], e["content"]) for e in bundle["bad_examples"]],
        [(e["name"], e["content"]) for e in bundle["good_examples"]],
    )
    detections = sum(h > 0 for h in challenge.bad_hits.values())
    report = {
        "replay": replay.__dict__,
        "adversarial": challenge.__dict__,
        "detections": detections,
        "misses": len(bundle["bad_examples"]) - detections,
        "false_positives": sum(h > 0 for h in challenge.good_hits.values()),
    }
    output = ROOT / ".data" / "assurance-report.json"
    output.parent.mkdir(exist_ok=True)
    output.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(json.dumps(report, indent=2))
    if not replay.passed or not challenge.passed:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
