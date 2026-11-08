# Backend verification

Run the repeatable checks from the repository root:

```sh
uv sync --frozen --extra dev --extra semgrep
uv run ruff check .
uv run mypy -p nope_core
uv run mypy apps/switch/src/nope_switch
uv run mypy apps/core/tests
uv run pytest
uv run python scripts/smoke_backend.py
```

The smoke check starts a real HTTP server with fresh restricted credentials and
an isolated SQLite ledger. It exercises proposal, original/corrected replay,
the independent challenge, evidence-bound approval, manual test activation,
exported rule replay and CI provenance. Unauthorized and altered approvals must
be rejected. Its approvals are **automated test fixtures**, not human sign-off,
and it leaves the developer's ledger untouched. Results go to
`.data/backend-smoke-sqlite.json`, or `NOPE_WORKDIR` when configured.

To run the same HTTP workflow against a disposable PostgreSQL database, set
`NOPE_SMOKE_DATABASE_URL` to its SQLAlchemy PostgreSQL URL. The Docker CI job
creates its own database and removes it afterward; it runs the production
image as its normal non-root user.

The production image uses the committed `uv.lock`, includes the CLI's demo and
rule assets, and writes ledger/evidence files under `/var/lib/nope`. Set
`NOPE_PROJECT_ROOT` when an installed CLI must use another checkout's assets.
Shell files have enforced LF endings so a Windows checkout builds a working
Linux image. Offline reset removes only the selected SQLite ledger, preserving
room messages, reports and other evidence.

Backend regression coverage includes malformed webhooks/scanner reports,
development-only anonymous access without approval/admin privileges,
concurrent revision updates, corrupt active evidence, invalid rule-sync
responses, unpublished PR heads and stale/cross-repository merge approvals.
The webhook reads the actual merged rule from GitHub before activation; see
[GitHub configuration](github-enforcement.md#backend-verification-of-a-merged-safeguard).
Expected authorization and validation rejections return client errors rather
than unhandled server exceptions.

For the TypeScript target, run `npm --prefix demo-app ci`,
`npm --prefix demo-app test` and `npm --prefix demo-app run typecheck` using
Node 22, matching CI. Logger regressions include circular metadata, bigint IDs,
shared references and nested credential redaction.

Local tests currently emit one upstream Starlette deprecation warning about
its httpx test adapter. It does not fail the suite and is not suppressed.
Passing these checks establishes the tested behavior; it does not certify that
every possible input or external-service configuration is error-free.
