"""Scan a real repository fixture; a prohibited behavior fails this command."""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
from pathlib import Path

from nope_core.paths import data_root
from nope_core.scan_report import checked_report

ROOT = Path(__file__).resolve().parents[1]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", type=Path, default=ROOT / "demo-app/regression/credential-log.ts")
    parser.add_argument("--rule", type=Path, default=ROOT / "config/.semgrep/nope-active.yml")
    parser.add_argument("--output", type=Path, default=data_root() / "regression-scan.json")
    args = parser.parse_args()
    scanner = shutil.which("semgrep")
    if not scanner or not args.target.is_file() or not args.rule.is_file():
        print("NOPE: scanner, rule and regression target must all exist")
        return 2
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.unlink(missing_ok=True)
    completed = subprocess.run([
        scanner, "scan", "--config", str(args.rule), "--error", "--strict",
        "--no-git-ignore", "--json", "--output", str(args.output), str(args.target),
    ], check=False, cwd=ROOT)
    if completed.returncode:
        return completed.returncode
    if not args.output.is_file():
        print("NOPE: scanner produced no evidence")
        return 2
    try:
        report = checked_report(json.loads(args.output.read_text(encoding="utf-8")))
    except (OSError, ValueError) as exc:
        print(f"NOPE: invalid scanner evidence: {exc}")
        return 2
    if report.get("errors") or report.get("results") or not report.get("paths", {}).get("scanned"):
        print("NOPE: findings, scanner errors or an unscanned regression target")
        return 1
    print("NOPE: regression target scanned; no prohibited credential logging")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
