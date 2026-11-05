#!/bin/sh
set -eu

BASE_SHA="${NOPE_BASE_SHA:-${GITHUB_BASE_SHA:-origin/main}}"
RULE_FILE="${NOPE_ACTIVE_RULES:-config/.semgrep/nope-active.yml}"
EXCLUDES="--exclude demo-app/fixtures/** --exclude apps/core/tests/** --exclude config/.semgrep/**"

if command -v semgrep >/dev/null; then
  run_semgrep() { semgrep "$@"; }
elif command -v uv >/dev/null && uv run semgrep --version >/dev/null 2>&1; then
  run_semgrep() { uv run semgrep "$@"; }
else
  echo "semgrep is required for NOPE enforcement (install with 'uv sync --extra semgrep')" >&2
  exit 3
fi

if command -v git >/dev/null && git rev-parse --is-inside-work-tree >/dev/null && git cat-file -e "$BASE_SHA" 2>/dev/null; then
  echo "NOPE: scanning changes against $BASE_SHA"
  run_semgrep scan --config "$RULE_FILE" --baseline-commit "$BASE_SHA" --error --quiet $EXCLUDES .
  printf '%s\n' 'NOPE: no new Scar policy violations.'
else
  echo "NOPE: base commit unavailable; scanning source tree." >&2
  run_semgrep scan --config "$RULE_FILE" --error --quiet $EXCLUDES .
  printf '%s\n' 'NOPE: no Scar policy violations.'
fi
