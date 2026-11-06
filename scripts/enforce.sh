#!/bin/sh
set -eu

BASE_SHA="${NOPE_BASE_SHA:-${GITHUB_BASE_SHA:-origin/main}}"
RULE_FILE="${NOPE_ACTIVE_RULES:-config/.semgrep/nope-active.yml}"
SCAN_OUTPUT="${NOPE_SCAN_OUTPUT:-.data/semgrep-scan.json}"
EXCLUDES="--exclude demo-app/fixtures/** --exclude apps/core/tests/** --exclude config/.semgrep/**"

# Remove any stale scan output from previous runs to prevent stale file reuse
rm -f "$SCAN_OUTPUT"
mkdir -p "$(dirname "$SCAN_OUTPUT")"

if [ ! -f "$RULE_FILE" ]; then
  echo "NOPE: active rule configuration file not found at '$RULE_FILE'" >&2
  exit 2
fi

# Verify rules sync against nope-core ledger if service URL is provided or explicitly requested
if [ "${NOPE_VERIFY_SYNC:-false}" = "true" ] || [ -n "${NOPE_BASE_URL:-}" ]; then
  echo "NOPE: verifying rules sync against active ledger..."
  if command -v uv >/dev/null; then
    uv run nope verify-sync --rule-file "$RULE_FILE"
  elif command -v nope >/dev/null; then
    nope verify-sync --rule-file "$RULE_FILE"
  fi
fi

if command -v semgrep >/dev/null; then
  run_semgrep() { semgrep "$@"; }
elif command -v uv >/dev/null && uv run semgrep --version >/dev/null 2>&1; then
  run_semgrep() { uv run semgrep "$@"; }
else
  echo "semgrep is required for NOPE enforcement (install with 'uv sync --extra semgrep')" >&2
  exit 3
fi

SEMGREP_EXIT=0
if command -v git >/dev/null && git rev-parse --is-inside-work-tree >/dev/null && git cat-file -e "$BASE_SHA" 2>/dev/null; then
  echo "NOPE: scanning changes against $BASE_SHA"
  run_semgrep scan --config "$RULE_FILE" --baseline-commit "$BASE_SHA" --json --output "$SCAN_OUTPUT" --quiet $EXCLUDES . || SEMGREP_EXIT=$?
else
  echo "NOPE: base commit unavailable; scanning source tree." >&2
  run_semgrep scan --config "$RULE_FILE" --json --output "$SCAN_OUTPUT" --quiet $EXCLUDES . || SEMGREP_EXIT=$?
fi

# If Semgrep crashed or suffered a fatal exit (> 1), fail closed unconditionally!
if [ "$SEMGREP_EXIT" -gt 1 ]; then
  echo "NOPE: Semgrep scan command exited with fatal error status $SEMGREP_EXIT" >&2
  if [ -s "$SCAN_OUTPUT" ]; then
    if command -v uv >/dev/null; then
      uv run python -m nope_core.reporter "$SCAN_OUTPUT" || true
    elif command -v python3 >/dev/null; then
      python3 -m nope_core.reporter "$SCAN_OUTPUT" || true
    fi
  fi
  exit "$SEMGREP_EXIT"
fi

if command -v uv >/dev/null; then
  uv run python -m nope_core.reporter "$SCAN_OUTPUT"
elif command -v python3 >/dev/null; then
  python3 -m nope_core.reporter "$SCAN_OUTPUT"
elif command -v nope-report >/dev/null; then
  nope-report "$SCAN_OUTPUT"
else
  echo "python is required for NOPE reporting" >&2
  exit 1
fi
