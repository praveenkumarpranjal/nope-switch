# NOPE — Never-Again Compiler

**Every mistake should leave something stronger than a message in chat: an executable safeguard.**

NOPE is an engineering workflow for teams that run agents with [Switch](https://github.com/sandbox-quantum/switch). When someone reports a painful lesson in a team room, NOPE turns it into a tested, auditable policy in the department’s CI:

1. A developer reports a lesson in a Switch-connected team room (`@nope teach …`).
2. The NOPE coding agent investigates the repository and drafts a rule (Semgrep or tests at first).
3. nope-core validates the rule against deliberate bad examples, known-good examples and the existing repository.
4. The team approves the change in the room, and the agent opens a pull request.
5. After merge, CI enforces the rule and links any failure back to the original incident, the reason for the rule and the exact correction.
6. `@nope challenge 001` lets a teammate question the rule; NOPE can narrow it or issue an expiring, reviewed exception.

This repository is **the product, not just a hack**: it contains the workflow platform, the validation lab, a seeded TypeScript target service, CI enforcement and the Switch onboarding kit.

> Hackathon: Flip the Switch (Nov 4–7 2026) | Track: Best Business Workflow | Sponsor license applies to submitted artefacts. The source remains MIT licensed for this project.

## What you get

- **`@nope` Switch agent brief** — a reviewable brief that makes the coding agent use the workbench instead of improvising against production.
- **nope-core** — FastAPI backend with an append-only Scar Ledger, PostgreSQL support, SQLite for local development, API-key RBAC and OpenAPI.
- **Async validation queue** — `POST /v1/scars/{id}/validate` returns `202 Accepted`; a dedicated `nope-worker` process executes Semgrep jobs and updates `GET /v1/validations/{job_id}`.
- **Rule Lab** — validates generated rules against:
  - adversarial fixtures the rule **must** flag,
  - known-good examples the rule **must not** flag,
  - the existing repository, using a baseline so legacy violations are warned about rather than silently made blocking.
- **The demo target service** — a small, strict TypeScript API with auth middleware, a logger and tests. The safe version passes CI.
- **CI enforcement** — fails only on newly introduced violations; existing findings become a baseline report.
- **Audit trail** — every proposal, validation, approval, activation, challenge and exception is tied to the original room message and incident.
- **Production packaging** — Docker, Compose/Postgres, API-key authentication, environment-driven configuration, migrations and an offline fallback demo.

## Fastest path to the "oh damn" moment

Requirements: Python 3.12+, Node 20+, Semgrep, Git, Switch and one supported coding agent.

```sh
git clone <url-for-this-repository>
cd nope-switch
cp .env.example .env  # replace demo keys for production
uv sync --extra dev --extra semgrep
npm --prefix demo-app ci
uv run pytest
uv run nope-demo reset
uv run nope-demo teach
uv run nope-demo validate
uv run nope-demo adversarial
uv run nope-demo approve 1
uv run nope-demo activate 1
```

Then in the room that has the Switch GitHub reference and safe auth/MCP permissions for the NOPE agent:

```text
@nope teach "We had another security incident because someone logged the Authorization header. Never log credentials or tokens anywhere in this repository."
```

NOPE answers with:

```text
I need two decisions before I create Scar 001:
1. Should the scope be this repository or all services in the workspace?
2. Should existing incidents be warned, or blocked on future pull requests only?
```

When you approve, it opens a PR containing the rule, fixtures and provenance. The deterministic enforcement demo makes the same lesson unbreachable:

```sh
uv run nope-demo reset
uv run nope-demo teach
uv run nope-demo validate
uv run nope-demo adversarial
uv run nope-demo approve 1
uv run nope-demo activate 1
uv run nope-demo scan-bad
```

`scan-bad` exits with `42` and prints the Scar reference, reason and remediation.

### Demo with no network or no agent

```sh
uv run nope-demo reset
uv run nope-demo teach
uv run nope-demo validate
uv run nope-demo adversarial
uv run nope-demo approve 1
uv run nope-demo activate 1
uv run nope-demo scan-good
uv run nope-demo scan-bad
```

The offline script uses the checked-in bad fixture, so no external model or chat is needed to see the full enforce/fail path. The Docker/Postgres path is in `docker-compose.yml`; replace all demo keys for any shared deployment.

## Architecture

Scars now require [counterfactual replay, an independent adversarial challenge,
and preserved provenance with regression gates](docs/scar-assurance.md). Approval
requires detection of the original incident, a passing correction, at least six
independent unsafe variants and four safe controls, 100% detection, and zero false
positives. Replacement rules must also pass every previously approved test suite.

```text
Slack / Discord / Teams / Telegram / Mattermost
              │ room: #incidents
              ▼
        Switch server ────── @nope agent
              │                 │
              │                 ├─ investigates repo and CI
              │                 ├─ drafts rule + fixtures
              │                 └─ uses nope CLI/HTTP only
              ▼                 ▼
        nope-core (FastAPI) ── validation queue (HTTP 202)
              │                 └─ durable validation jobs
              ▼                 ▼
       Scar Ledger (PostgreSQL; SQLite local) ◄── nope-worker
              │                 (Semgrep in a separate process)
              │
              ▼
gh API / PR merge webhook → scar active → CI enforcement
```

The critical boundary is intentional: **the agent does the judgment; nope-core does the deterministic work**. The agent cannot activate a rule from prompt text alone. Activation requires a passing Rule Lab result and an authorized human confirmation.

## Layout

```text
apps/core/                 production FastAPI service and CLI
apps/core/tests/           API, auth, RBAC, validation and scar-lifecycle tests
apps/core/src/nope_core/   domain logic (no LLM code in the safety path)
config/.semgrep/           active rule pack checked into target repos
demo-app/                  strict TypeScript service and fixtures
switch/nope-agent/         Switch brief, permissions, setup and operator notes
docs/                      demo, security, Switch setup, architecture and roadmap
scripts/                   offline demo and production release helpers
.github/workflows/         test and enforce workflows
```

## Security defaults

- `NOPE_API_KEYS` is required in production; health is the only public route.
- Roles are `admin`, `approver`, `agent`, and `ci`; key files are never logged or stored in the database.
- Rules and exceptions are immutable history rows; status changes are appended, not overwritten.
- Existing legacy violations are report-only by default (`NOPE_BASELINE_ENFORCE=false`).
- `@nope challenge` cannot bypass a rule — it creates an expiring, reviewed exception or a narrowed, tested replacement.
- Docker packaging includes PostgreSQL and a dedicated `nope-worker`; deployments that scale horizontally must run the same worker for every replica.
- Semgrep receives no network access and runs in a separate process; nope-core never executes model output directly.
- Production uses parameterized SQL via SQLAlchemy and no `shell=True` for user input.

## Repository hygiene and submission

CI runs unit tests, the demo target test suite, checks the shipped Semgrep pack and verifies the Formatter. The GitHub Actions workflow fails only on new dangerous findings, not on the intentionally bad checked-in fixture under `demo-app/fixtures/` and `.semgrep/` test cases.

## What is intentionally not in this release

- A bespoke coding agent. Switch brings Claude Code, Codex, OpenCode or another harness.
- Automatic merging. Humans always approve scars and exceptions.
- Cross-repo automatic rollout. Jobs may propose the same scar in another service, but they may not install it without a room approval.
- Guarantees for arbitrary, unseen languages. The MVP supports TypeScript/JavaScript well and Python as a secondary target; other languages need a rule pack with real fixtures and a human review.
