from __future__ import annotations

from pathlib import Path

from nope_core.rule_lab import RuleLab

RULE = """rules:
  - id: test.credentials-in-logs
    message: credentials must not reach logs
    severity: ERROR
    languages: [typescript]
    patterns:
      - pattern-inside: logger.$METHOD(...)
      - pattern-either:
          - pattern: "authorization: $VALUE"
          - pattern: $REQ.headers.authorization
"""

BAD = "logger.info({ authorization: req.headers.authorization }, 'headers');\n"
GOOD = "logger.info({ userId: req.headers['x-user-id'] }, 'headers');\n"


def test_rejects_rule_without_rules() -> None:
    try:
        RuleLab().ensure_rule_shape("not-yaml: [")
    except Exception as exc:
        assert "Rule YAML is invalid" in str(exc)
    else:
        raise AssertionError("invalid YAML escaped RuleLab")


def test_rule_lab_accepts_target_rule() -> None:
    result = RuleLab(timeout_seconds=90).validate(RULE, [("bad", BAD)], [("good", GOOD)], None)
    assert result.rule_errors == []
    assert result.bad_hits["bad"] >= 1
    assert result.good_hits["good"] == 0
    assert result.passed
