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


def test_rule_lab_rejects_redos_patterns() -> None:
    redos_rule = """rules:
  - id: test.redos
    message: Potentially explosive regex
    severity: ERROR
    languages: [typescript]
    pattern-regex: "([a-zA-Z]+)*"
"""
    with pytest.raises(Exception, match="suspected ReDoS"):
        RuleLab().ensure_rule_shape(redos_rule)

    nested_redos = """rules:
  - id: test.redos.nested
    message: Nested quantifier
    severity: ERROR
    languages: [typescript]
    patterns:
      - pattern-regex: "(a+)+"
"""
    with pytest.raises(Exception, match="suspected ReDoS"):
        RuleLab().ensure_rule_shape(nested_redos)


def test_rule_lab_rejects_excessive_patterns() -> None:
    patterns = "\n".join(f"      - pattern: dangerous_call_{i}(...)" for i in range(55))
    huge_rule = f"""rules:
  - id: test.excessive
    message: Too many patterns
    severity: ERROR
    languages: [typescript]
    patterns:
{patterns}
"""
    with pytest.raises(Exception, match="exceeds maximum pattern limit"):
        RuleLab().ensure_rule_shape(huge_rule)


def test_rule_lab_taint_mode_shape_validation() -> None:
    # 1. Missing pattern-sources
    missing_sources = """rules:
  - id: test.taint.no-sources
    mode: taint
    message: Missing sources
    severity: ERROR
    languages: [typescript]
    pattern-sinks:
      - pattern: sink(...)
"""
    with pytest.raises(Exception, match="requires a non-empty 'pattern-sources' list"):
        RuleLab().ensure_rule_shape(missing_sources)

    # 2. Missing pattern-sinks
    missing_sinks = """rules:
  - id: test.taint.no-sinks
    mode: taint
    message: Missing sinks
    severity: ERROR
    languages: [typescript]
    pattern-sources:
      - pattern: source(...)
"""
    with pytest.raises(Exception, match="requires a non-empty 'pattern-sinks' list"):
        RuleLab().ensure_rule_shape(missing_sinks)

    # 3. Invalid mode
    invalid_mode = """rules:
  - id: test.taint.invalid
    mode: unknown_mode
    message: Bad mode
    severity: ERROR
    languages: [typescript]
    pattern: foo()
"""
    with pytest.raises(Exception, match="unsupported mode 'unknown_mode'"):
        RuleLab().ensure_rule_shape(invalid_mode)


def test_rule_lab_taint_mode_end_to_end_dataflow() -> None:
    taint_rule = """rules:
  - id: test.taint.dataflow
    mode: taint
    message: Credential token reached log sink
    severity: ERROR
    languages: [typescript, javascript]
    pattern-sources:
      - pattern: req.headers.authorization
      - pattern: req.headers['authorization']
    pattern-sinks:
      - pattern: logger.info(...)
"""
    # Bad fixture: variable propagation across assignments
    bad_code = """
const authHeader = req.headers.authorization;
const sensitivePayload = authHeader;
logger.info({ token: sensitivePayload });
"""
    # Good fixture: user ID is logged, not authorization header
    good_code = """
const userId = req.user.id;
logger.info({ user: userId });
"""
    lab = RuleLab(timeout_seconds=90)
    result = lab.validate(taint_rule, [("bad_flow.ts", bad_code)], [("good_flow.ts", good_code)])
    assert result.rule_errors == []
    assert result.bad_hits["bad_flow.ts"] >= 1
    assert result.good_hits["good_flow.ts"] == 0
    assert result.passed is True


def test_rule_lab_fixture_size_limit() -> None:
    oversized = "a" * 250_001
    lab = RuleLab()
    result = lab.validate(RULE, [("big.ts", oversized)], [("good.ts", GOOD)])
    assert result.passed is False
    assert any("exceeds maximum allowed size" in err for err in result.rule_errors)


def test_rule_lab_resource_limit_signal_handling(monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_subprocess_run(command: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        # Simulate SIGXCPU (returncode -24)
        return subprocess.CompletedProcess(command, -24, "", "CPU time limit exceeded")

    monkeypatch.setattr("nope_core.rule_lab.shutil.which", lambda _: "semgrep")
    monkeypatch.setattr("nope_core.rule_lab.subprocess.run", fake_subprocess_run)

    lab = RuleLab()
    result = lab.validate(RULE, [("bad.ts", BAD)], [("good.ts", GOOD)])
    assert result.passed is False
    assert any("sandbox resource limits" in err for err in result.rule_errors)
