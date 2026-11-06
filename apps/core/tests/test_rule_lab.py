from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import Any

import pytest
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


def test_skipped_safe_fixture_is_not_evidence_of_a_pass(monkeypatch: pytest.MonkeyPatch) -> None:
    def scan(command: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        bad_path = next(Path(command[-2]).glob("*.ts"))
        # Simulate a rule's path exclusions hiding the safe fixture from Semgrep.
        payload = {"results": [{"path": str(bad_path)}], "errors": [], "paths": {"scanned": [str(bad_path)]}}
        return subprocess.CompletedProcess(command, 0, json.dumps(payload), "")
    monkeypatch.setattr("nope_core.rule_lab.shutil.which", lambda _: "semgrep")
    monkeypatch.setattr("nope_core.rule_lab.subprocess.run", scan)
    result = RuleLab().validate(RULE, [("bad.ts", BAD)], [("good.ts", GOOD)])
    assert result.bad_hits["bad.ts"] == 1
    assert result.good_hits["good.ts"] == 0
    assert result.passed is False
    assert "not scanned: good/good.ts" in result.rule_errors[0]
