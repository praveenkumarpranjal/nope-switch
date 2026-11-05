#!/bin/sh
set -eu

uv sync --extra dev --extra semgrep
uv run pytest
npm --prefix demo-app ci
npm --prefix demo-app run test
npm --prefix demo-app run typecheck
sh scripts/enforce.sh
