from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml


class RuleLabError(RuntimeError):
    pass


@dataclass(frozen=True)
class CandidateResult:
    passed: bool
    bad_hits: dict[str, int]
    good_hits: dict[str, int]
    target_hits: list[str]
    rule_errors: list[str]


def _scan_root() -> Path:
    return Path(os.getenv("NOPE_SCAN_ROOT", os.getcwd())).resolve()


def checked_target_path(target_path: str | None) -> Path | None:
    if not target_path:
        return None
    candidate = Path(target_path)
    if not candidate.is_absolute():
        candidate = _scan_root() / candidate
    resolved = candidate.resolve()
    root = _scan_root()
    if root not in resolved.parents and resolved != root:
        raise RuleLabError("target_path is outside NOPE_SCAN_ROOT")
    if not resolved.is_dir():
        raise RuleLabError("target_path must be an existing directory")
    return resolved


class RuleLab:
    def __init__(self, timeout_seconds: int = 120) -> None:
        self.timeout_seconds = timeout_seconds

    def ensure_rule_shape(self, rule_yaml: str) -> bytes:
        try:
            document = yaml.safe_load(rule_yaml)
        except yaml.YAMLError as exc:
            raise RuleLabError(f"Rule YAML is invalid: {exc}") from exc
        if not isinstance(document, dict) or not isinstance(document.get("rules"), list) or not document["rules"]:
            raise RuleLabError("Rule YAML must contain a non-empty 'rules' list")
        for index, rule in enumerate(document["rules"], start=1):
            if not isinstance(rule, dict):
                raise RuleLabError(f"Rule {index} must be a mapping")
            if not {"id", "message", "severity", "languages"}.issubset(rule):
                raise RuleLabError(f"Rule {index} requires id, message, severity and languages")
        return rule_yaml.encode("utf-8")

    @staticmethod
    def _example_extension(name: str) -> str:
        suffix = Path(name).suffix.lower()
        return suffix if suffix in {".ts", ".tsx", ".js", ".jsx", ".py", ".java", ".go"} else ".ts"

    def validate(
        self,
        rule_yaml: str,
        bad_examples: list[tuple[str, str]],
        good_examples: list[tuple[str, str]],
        target_path: str | None = None,
        min_bad_fixture_hits: int = 1,
        max_good_fixture_hits: int = 0,
    ) -> CandidateResult:
        rule_bytes = self.ensure_rule_shape(rule_yaml)
        semgrep = shutil.which("semgrep")
        if not semgrep:
            return CandidateResult(False, {}, {}, [], ["semgrep is not installed on PATH"])

        with tempfile.TemporaryDirectory(prefix="nope-rule-lab-") as tmp:
            workdir = Path(tmp)
            rule_path = workdir / "candidate.yml"
            rule_path.write_bytes(rule_bytes)
            bad_dir = workdir / "fixtures" / "bad"
            good_dir = workdir / "fixtures" / "good"
            bad_dir.mkdir(parents=True)
            good_dir.mkdir(parents=True)

            bad_paths = self._write_examples(bad_dir, bad_examples)
            good_paths = self._write_examples(good_dir, good_examples)

            scanned = [bad_dir, good_dir]
            checked_target = checked_target_path(target_path) if target_path else None
            if checked_target:
                scanned.append(checked_target)

            command = [
                semgrep,
                "scan",
                "--config",
                str(rule_path),
                "--json",
                "--quiet",
                "--metrics=off",
                "--no-error",
                *(str(path) for path in scanned),
            ]
            try:
                completed = subprocess.run(command, capture_output=True, text=True, timeout=self.timeout_seconds, check=False)
            except subprocess.TimeoutExpired:
                return CandidateResult(False, {}, {}, [], [f"semgrep exceeded {self.timeout_seconds} seconds"])
            except OSError as exc:
                return CandidateResult(False, {}, {}, [], [f"semgrep could not start: {exc}"])

            try:
                payload = json.loads(completed.stdout or "{}")
            except json.JSONDecodeError:
                detail = (completed.stderr or completed.stdout).strip()[:800]
                return CandidateResult(False, {}, {}, [], [f"semgrep returned invalid JSON: {detail}"])

            if completed.returncode not in (0, 1):
                return CandidateResult(False, {}, {}, [], [f"semgrep exited with status {completed.returncode}"])
            if not isinstance(payload, dict) or not isinstance(payload.get("results"), list):
                return CandidateResult(False, {}, {}, [], ["semgrep returned an incomplete scan report"])

            hits_by_path: dict[str, int] = {}
            for finding in payload.get("results", []):
                location = finding.get("path")
                if isinstance(location, str):
                    hits_by_path[str(Path(location).resolve())] = hits_by_path.get(str(Path(location).resolve()), 0) + 1

            bad_hits = {name: hits_by_path.get(str(path), 0) for name, path in bad_paths.items()}
            good_hits = {name: hits_by_path.get(str(path), 0) for name, path in good_paths.items()}
            target_hits = self._target_hits(hits_by_path, checked_target)
            errors = payload.get("errors", [])
            error_messages = [self._error_message(error) for error in errors if isinstance(error, dict)][:20]
            scanned_paths = {os.path.normcase(str(Path(path).resolve()))
                             for path in payload.get("paths", {}).get("scanned", []) if isinstance(path, str)}
            skipped = [name for name, path in {**{f"bad/{k}": v for k, v in bad_paths.items()},
                                               **{f"good/{k}": v for k, v in good_paths.items()}}.items()
                       if os.path.normcase(str(path)) not in scanned_paths]
            if skipped:
                error_messages.append(f"Fixture coverage incomplete; not scanned: {', '.join(skipped)}")

            bad_ok = all(hits >= min_bad_fixture_hits for hits in bad_hits.values())
            good_ok = all(hits <= max_good_fixture_hits for hits in good_hits.values())
            return CandidateResult(bad_ok and good_ok and not error_messages, bad_hits, good_hits, target_hits, error_messages)

    def _write_examples(self, directory: Path, examples: list[tuple[str, str]]) -> dict[str, Path]:
        written: dict[str, Path] = {}
        for index, (name, content) in enumerate(examples):
            path = directory / f"{index}-{Path(name).stem}{self._example_extension(name)}"
            path.write_text(content, encoding="utf-8")
            written[name] = path.resolve()
        return written

    @staticmethod
    def _error_message(error: dict[str, Any]) -> str:
        detail = (
            error.get("long_msg")
            or error.get("short_msg")
            or error.get("message")
            or error.get("reason")
            or str(error)
        )
        return " ".join(str(detail).split())[:1000]

    @staticmethod
    def _target_hits(hits_by_path: dict[str, int], target: Path | None) -> list[str]:
        if target is None:
            return []
        hits: list[str] = []
        for path, count in hits_by_path.items():
            resolved = Path(path).resolve()
            if target == resolved or target in resolved.parents:
                hits.append(f"{resolved} ({count} finding{'s' if count != 1 else ''})")
        return sorted(hits)

    @property
    def semgrep_fingerprint(self) -> str:
        return hashlib.sha256(__file__.encode()).hexdigest()
