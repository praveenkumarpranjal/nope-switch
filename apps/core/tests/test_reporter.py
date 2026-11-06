from __future__ import annotations

import json
import socket
import threading
import time
from collections.abc import Generator
from pathlib import Path
from unittest.mock import patch

import pytest
import uvicorn
from nope_core import assurance, scar_service
from nope_core.db import AuditEvent, Scar, SessionLocal
from nope_core.main import app
from nope_core.reporter import (
    escape_data,
    escape_property,
    get_check_url,
    get_git_info,
    parse_scar_number,
    process_scan_file,
    report_failure_to_api,
    write_github_step_summary,
)
from nope_core.schemas import CreateScarRequest
from sqlalchemy import select


def test_parse_scar_number() -> None:
    assert parse_scar_number("SCAR-001") == 1
    assert parse_scar_number("scar-42") == 42
    assert parse_scar_number("no-numbers") is None


def test_workflow_command_escaping() -> None:
    # Property values must escape %, \r, \n, :, and ,
    raw_prop = "path/to:file,v1%2.ts\n"
    assert escape_property(raw_prop) == "path/to%3Afile%2Cv1%252.ts%0A"

    # Message body must escape %, \r, and \n
    raw_msg = "Critical:\nDo not log tokens, secret%100"
    assert escape_data(raw_msg) == "Critical:%0ADo not log tokens, secret%25100"


def test_workflow_command_output_captured(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("GITHUB_ACTIONS", "true")
    scan_file = tmp_path / "findings.json"
    scan_file.write_text(
        json.dumps({
            "results": [
                {
                    "check_id": "nope.rules.test",
                    "path": "src/bad,file:test.ts",
                    "start": {"line": 10, "col": 4},
                    "extra": {
                        "message": "Auth: token%leak\nin logs",
                        "metadata": {"scar": "SCAR-005"},
                    },
                }
            ],
            "errors": [],
        })
    )

    with patch("nope_core.reporter.report_failure_to_api", return_value=None):
        exit_code = process_scan_file(scan_file, fail_closed=True)

    assert exit_code == 1
    captured = capsys.readouterr()
    expected_command = (
        "::error file=src/bad%2Cfile%3Atest.ts,line=10,col=4,title=NOPE Scar #005::Auth: token%25leak%0Ain logs"
    )
    assert expected_command in captured.out


def test_get_git_info_and_check_url(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("GITHUB_REPOSITORY", "org/test-repo")
    monkeypatch.setenv("GITHUB_SHA", "abcdef1234567")
    monkeypatch.setenv("GITHUB_RUN_ID", "998877")

    repo, sha = get_git_info()
    assert repo == "org/test-repo"
    assert sha == "abcdef1234567"

    url = get_check_url(repo, sha)
    assert url == "https://github.com/org/test-repo/actions/runs/998877"


def test_process_scan_file_clean(tmp_path: Path) -> None:
    scan_file = tmp_path / "clean.json"
    scan_file.write_text(json.dumps({"results": [], "errors": []}))

    assert process_scan_file(scan_file) == 0


def test_process_scan_file_missing_file(tmp_path: Path) -> None:
    assert process_scan_file(tmp_path / "nonexistent.json") == 1


def test_process_scan_file_invalid_json(tmp_path: Path) -> None:
    scan_file = tmp_path / "invalid.json"
    scan_file.write_text("not json content {")

    assert process_scan_file(scan_file) == 1


def test_process_scan_file_semgrep_errors_fail_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    scan_file = tmp_path / "semgrep_errors.json"
    scan_file.write_text(
        json.dumps({
            "results": [],
            "errors": [
                {
                    "message": "Syntax error in rule yaml at line 14",
                    "path": "config/.semgrep/bad-rule.yml",
                }
            ],
        })
    )

    # When results are empty but Semgrep reported errors, fail_closed=True must exit 1
    exit_code = process_scan_file(scan_file, fail_closed=True)
    assert exit_code == 1

    captured = capsys.readouterr()
    assert "SEMGREP SCAN ERRORS DETECTED" in captured.out
    assert "Syntax error in rule yaml" in captured.out


def test_process_scan_file_semgrep_errors_fail_open(tmp_path: Path) -> None:
    scan_file = tmp_path / "semgrep_errors.json"
    scan_file.write_text(
        json.dumps({
            "results": [],
            "errors": [{"message": "Unrecoverable parser failure"}],
        })
    )

    # When fail_closed=False, permit the build
    exit_code = process_scan_file(scan_file, fail_closed=False)
    assert exit_code == 0


def test_process_scan_file_both_results_and_errors(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    scan_file = tmp_path / "mixed.json"
    scan_file.write_text(
        json.dumps({
            "results": [
                {
                    "check_id": "rule.test",
                    "path": "src/index.ts",
                    "start": {"line": 1, "col": 1},
                    "extra": {
                        "message": "Dangerous call",
                        "metadata": {"scar": "SCAR-001"},
                    },
                }
            ],
            "errors": [{"message": "Failed to parse src/corrupt.ts"}],
        })
    )

    with patch("nope_core.reporter.report_failure_to_api", return_value=None):
        exit_code = process_scan_file(scan_file, fail_closed=True)

    assert exit_code == 1
    captured = capsys.readouterr()
    assert "🚨 NOPE POLICY VIOLATIONS DETECTED" in captured.out
    assert "Additional Semgrep Scan Errors:" in captured.out
    assert "Failed to parse src/corrupt.ts" in captured.out


def test_process_scan_file_offline_fallback(tmp_path: Path) -> None:
    scan_file = tmp_path / "findings.json"
    scan_file.write_text(
        json.dumps({
            "results": [
                {
                    "check_id": "nope.credentials-in-logs",
                    "path": "src/auth.ts",
                    "start": {"line": 5, "col": 1},
                    "extra": {
                        "message": "Never log tokens directly.",
                        "metadata": {
                            "scar": "SCAR-002",
                            "incident": "INC-022",
                            "remediation": "Delete log call.",
                        },
                    },
                }
            ],
            "errors": [],
        })
    )

    # Policy violations must ALWAYS fail (exit 1), regardless of fail_closed setting
    with patch("nope_core.reporter.report_failure_to_api", return_value=None):
        assert process_scan_file(scan_file, fail_closed=True) == 1
        assert process_scan_file(scan_file, fail_closed=False) == 1


@pytest.fixture(scope="module")
def live_server() -> Generator[str, None, None]:
    """Start an ephemeral in-process uvicorn server on a free port for real HTTP tests."""
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]

    config = uvicorn.Config(app=app, host="127.0.0.1", port=port, log_level="error")
    server = uvicorn.Server(config=config)
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()

    start_wait = time.time()
    while not server.started:
        if time.time() - start_wait > 5.0:
            raise TimeoutError("Live test server failed to start within 5s")
        time.sleep(0.05)

    yield f"http://127.0.0.1:{port}"

    server.should_exit = True
    thread.join(timeout=3.0)


def test_step_summary_table_escaping(tmp_path: Path) -> None:
    summary_file = tmp_path / "escaped_summary.md"
    scar_data = {
        1: {
            "title": "Never log tokens | keys",
            "why": "Line1\nLine2",
            "fix": "Fix|with|pipes",
            "incident": "INC-01",
        }
    }
    findings = {
        1: [
            {
                "path": "src/path|with|pipe.ts",
                "start": {"line": 15, "col": 2},
                "check_id": "rule|pipe",
                "extra": {"message": "Msg|with|pipes\nand newlines"},
            }
        ]
    }
    errors = [{"message": "Parser|error\nmultiline", "path": "bad|file.ts"}]

    write_github_step_summary(summary_file, scar_data, findings, errors=errors)
    content = summary_file.read_text(encoding="utf-8")

    # Table cells must escape pipes to \| and newlines to <br>
    assert "`src/path\\|with\\|pipe.ts`" in content
    assert "`rule\\|pipe`" in content
    assert "Parser\\|error<br>multiline" in content
    assert "`bad\\|file.ts`" in content


def test_live_server_integration_records_failure_and_returns_remediation(
    live_server: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Real HTTP socket integration test:

    1. Verify clean, hermetic initial database state.
    2. Seed a Scar in the database.
    3. Make direct real TCP HTTP call to /v1/ci/failure and assert 200 OK and fields.
    4. Make duplicate retry call to verify idempotency and non-colliding audit IDs.
    5. Run process_scan_file against the live uvicorn server over TCP.
    6. Verify audit event persistence and step summary rendering.
    """
    # 1. Assert initial isolated DB state has 0 scars and 0 audit events
    with SessionLocal() as db:
        assert len(db.scalars(select(Scar)).all()) == 0
        assert len(db.scalars(select(AuditEvent)).all()) == 0

    # 2. Seed a Scar in the database
    with SessionLocal() as db:
        scar = scar_service.create_scar(
            db,
            CreateScarRequest(
                title="Never log customer credentials",
                incident_summary="INC-999: Auth credentials logged during login flow",
                invariant="Credentials must never reach logs",
                rationale="Wide monitoring ingestion leaks credentials",
                remediation="Log opaque user ID instead",
                incident_url="https://github.com/example/inc-999",  # type: ignore[arg-type]
                repository="acme/payments-api",
                scope="src/",
                origin="INC-999",
                proposed_by="live-integration-test",
            ),
            actor="test-setup",
        )
        db.commit()
        scar_number = scar.number
        # Seed an activated revision so the HTTP reporter can link exact artifacts.
        rule = scar_service.add_rule_version(db, scar, "rules: []")
        db.flush()
        db.add(assurance.Revision(id="rev_reporter_test", scar_id=scar.id, rule_id=rule.id,
                                 sequence=rule.version, author="test-author", state="active",
                                 fixtures=json.dumps({"original": {"name": "original.ts", "content": "danger();"},
                                                      "corrected": {"name": "safe.ts", "content": "safe();"}}),
                                 report=json.dumps({"replay": {"passed": True}})))
        scar.active = True
        scar.status = "active"
        db.commit()

    # 3. Direct HTTP call over TCP socket to /v1/ci/failure
    api_resp = report_failure_to_api(
        base_url=live_server,
        ci_key="ci",
        repo="acme/payments-api",
        sha="b296edf2a9f1554d3faee4f468f529cc8db2e119",
        scar_number=scar_number,
        check_url="https://github.com/acme/payments-api/actions/runs/123",
    )
    assert api_resp is not None
    assert api_resp["scar_number"] == scar_number
    assert api_resp["title"] == "Never log customer credentials"
    assert api_resp["why"] == "Wide monitoring ingestion leaks credentials"
    assert api_resp["fix"] == "Log opaque user ID instead"
    assert api_resp["incident"] == "https://github.com/example/inc-999"
    assert api_resp["revision_id"] == "rev_reporter_test"
    assert api_resp["approved_rule"].endswith("/revisions/rev_reporter_test/rule")
    assert api_resp["tests"].endswith("/revisions/rev_reporter_test/tests")
    assert api_resp["history"].endswith("/provenance")

    # 4. Duplicate retry call on same commit to verify retry idempotency and unique IDs
    retry_resp = report_failure_to_api(
        base_url=live_server,
        ci_key="ci",
        repo="acme/payments-api",
        sha="b296edf2a9f1554d3faee4f468f529cc8db2e119",
        scar_number=scar_number,
        check_url="https://github.com/acme/payments-api/actions/runs/123",
    )
    assert retry_resp == api_resp

    with SessionLocal() as db:
        events = db.scalars(
            select(AuditEvent)
            .where(AuditEvent.action == "ci.failure_observed")
        ).all()
        assert len(events) == 2
        # IDs must be unique and non-colliding
        assert events[0].id != events[1].id
        assert events[0].id.startswith("ci_")

    # 5. Run process_scan_file targeting the real HTTP live server
    scan_file = tmp_path / "live_scan.json"
    summary_file = tmp_path / "live_summary.md"
    monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(summary_file))
    monkeypatch.setenv("GITHUB_ACTIONS", "true")
    monkeypatch.setenv("NOPE_CI_KEY", "ci")

    scan_file.write_text(
        json.dumps({
            "results": [
                {
                    "check_id": "nope.credentials-in-logs",
                    "path": "src/payment.ts",
                    "start": {"line": 42, "col": 8},
                    "extra": {
                        "message": "Credential logged",
                        "metadata": {"scar": f"SCAR-{scar_number:03d}"},
                    },
                }
            ],
            "errors": [],
        })
    )

    exit_code = process_scan_file(
        scan_json_path=scan_file,
        base_url=live_server,
        ci_key="ci",
        fail_closed=True,
    )
    assert exit_code == 1

    # 6. Verify the step summary Markdown rendered with real DB data
    assert summary_file.exists()
    summary_md = summary_file.read_text(encoding="utf-8")
    assert f"Scar #{scar_number:03d} — Never log customer credentials" in summary_md
    assert "Log opaque user ID instead" in summary_md
    assert "https://github.com/example/inc-999" in summary_md
    assert "[Approved rule]" in summary_md
    assert "[Tests and replay]" in summary_md
    assert "[Decision history]" in summary_md


def test_offline_provenance_links_pin_repository_commit(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("GITHUB_REPOSITORY", "acme/service")
    monkeypatch.setenv("GITHUB_SHA", "abcdef123")
    summary = tmp_path / "summary.md"
    monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(summary))
    scan = tmp_path / "scan.json"
    scan.write_text(json.dumps({"results": [{"path": "src/auth.ts", "check_id": "credential-rule",
        "extra": {"metadata": {"scar": "SCAR-001", "revision_id": "rev_original",
                                "incident": "demo-app/fixtures/teach.json", "approved_rule": "config/.semgrep/nope-active.yml",
                                "tests": "demo-app/fixtures/adversarial-challenge.json", "history": "docs/scar-assurance.md"}}}], "errors": []}))
    with patch("nope_core.reporter.report_failure_to_api", return_value=None) as report:
        assert process_scan_file(scan) == 1
        assert report.call_args.args[-1] == "rev_original"
    content = summary.read_text(encoding="utf-8")
    for path in ("demo-app/fixtures/teach.json", "config/.semgrep/nope-active.yml",
                 "demo-app/fixtures/adversarial-challenge.json", "docs/scar-assurance.md"):
        assert f"https://github.com/acme/service/blob/abcdef123/{path}" in content
