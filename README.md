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

## How Switch is used

NOPE is designed natively around Switch rooms and multi-agent coordination. Instead of relying on a single agent trying to review its own work, NOPE introduces a **Three-Agent Courtroom** inside Switch rooms where competing agents debate, attack, and verify safety rules before any human approves them.

### 1. The Connected Agents

| Agent | Role & Brief | Responsibility in Switch Room |
|---|---|---|
| **`@nope`** | **Rule Synthesizer**<br>([`switch/nope-agent/brief.md`](switch/nope-agent/brief.md)) | Monitors the incident channel. When an engineer posts `@nope teach <incident>`, it investigates the target repository, synthesizes invariant rules (Semgrep patterns), creates test fixtures, and submits candidate rules to the Rule Lab. |
| **`@red-team`** | **Independent Adversary**<br>([`switch/red-team/brief.md`](switch/red-team/brief.md)) | Operates with a distinct agent key. It receives candidate rules and attempts to bypass them using 8 real-world mutation vectors (nested logging, re-aliased credentials, string interpolation, custom formatters). It actively tries to prove the rule is too naive. |
| **`@nope-reviewer`** | **Courtroom Judge**<br>([`switch/nope-reviewer/brief.md`](switch/nope-reviewer/brief.md)) | Evaluates both agents' evidence. It enforces strict acceptance criteria: 100% detection of adversarial variants, 0 false positives against safe controls, and zero scanner errors. If satisfied, it signs the cryptographic `evidence_sha256` manifest. |
| **Human SRE** | **Cryptographic Approver**<br>(Role: `approver`) | Reviews the courtroom transcript in the room and authorizes the rule (`@nope approve <rationale>`). **Agents are strictly forbidden from self-signing human approvals**; nope-core enforces HMAC token role verification. |

### 2. Channel Setup

1. **Room Creation**: Create a Switch room named `#incidents` (or `nope-never-again`) via Switch Console or bridged to your team's chat platform (Mattermost / Slack).
2. **Attach Context**: Attach this target repository (`praveenkumarpranjal/nope-switch`) as context so agents can read `.github/workflows`, source code, and existing test fixtures.
3. **Register Agents**: Register `@nope`, `@red-team`, and `@nope-reviewer` in Switch Console using the exact instructions in [`docs/switch-setup.md`](docs/switch-setup.md) and [`docs/switch-live-demo.md`](docs/switch-live-demo.md).
4. **Agent Protocol**: The `nope_switch` adapter communicates via the native Switch Agent Protocol (WebSockets and dynamic `/ops` HTTP schema discovery).
5. **CI Results Posted to Room**: When CI detects a violation on any future developer Pull Request, the CI gate (`nope-room` / `scripts/enforce.sh`) posts the structured evidence bundle directly back to the Switch room, linking the exact failing code line back to the original postmortem message and remediation.

> **Note on Rule Synthesis**: The built-in dispatcher simulator uses a deterministic reference rule (`pattern: leakCredential($X)`) for automated testing and reproducible demos; in production deployments, the coding agent following [`switch/nope-agent/brief.md`](switch/nope-agent/brief.md) investigates the target repository and writes bespoke Semgrep rules and test fixtures.

## What you get

- **Three-Agent Courtroom (`apps/switch`)** — Connected Switch room runtime, agent briefs (`@nope`, `@red-team`, `@nope-reviewer`), adversarial mutation engine, and the `nope-room` CLI.
- **nope-core** — Production FastAPI backend with an append-only Scar Ledger, PostgreSQL support, SQLite for local development, API-key RBAC and OpenAPI docs.
- **Async validation queue** — `POST /v1/scars/{id}/validate` returns `202 Accepted`; a dedicated `nope-worker` process executes Semgrep jobs and updates `GET /v1/validations/{job_id}`.
- **Rule Lab** — Validates generated rules against adversarial fixtures (must flag), known-good examples (must not flag), and existing repository baselines.
- **Demo target service (`demo-app`)** — Strict TypeScript service with auth middleware, logger, and full test suite.
- **CI enforcement (`scripts/enforce.sh`)** — Fails only on newly introduced violations; existing findings become a baseline report.
- **Audit trail** — Every proposal, validation, approval, activation, challenge and exception is tied to the original room message and incident.
- **Production packaging** — Docker container, Compose/PostgreSQL stack, API-key authentication, and an offline fallback demo.

## Quickstart: How to Run It (Judge Evaluation in < 2 Minutes)

NOPE is fully reproducible with local commands. Judges can evaluate the entire multi-agent loop, backend ledger, and CI gate in four quick steps:

### Prerequisites

```sh
git clone https://github.com/praveenkumarpranjal/nope-switch.git
cd nope-switch
cp .env.example .env
uv sync --extra dev --extra semgrep
npm --prefix demo-app ci
```

### 1. Test the Multi-Agent Courtroom

Demonstrates `@nope` proposing a naive rule, `@red-team` attacking and rejecting it, followed by a taint-tracking rule achieving 100% detection and 0 false positives:

```sh
uv run nope-room courtroom
```

*Expected output*: Naive candidate `REJECT` (0 detected, 8 missed); Taint candidate `PASS` (8 detected, 0 missed, 0 false positives).

### 2. Test the Real HTTP Backend, Ledger & Async Queue

Boots an isolated FastAPI instance, exercises HMAC authentication, Scar lifecycle (#1 proposal → validation → human approval → activation), and verifies the ledger:

```sh
uv run python scripts/smoke_backend.py
```

*Expected output*: `smoke test passed` with green test report against SQLite or PostgreSQL.

### 3. Test Developer Pull Request CI Gate (Exit Code 42)

Simulates the end-to-end developer experience: an incident is taught, validated, approved, activated, and then a developer attempts to commit code re-introducing the vulnerability:

```sh
uv run nope-demo reset
uv run nope-demo teach
uv run nope-demo validate
uv run nope-demo adversarial
uv run nope-demo approve 1
uv run nope-demo activate 1
uv run nope-demo scan-bad
```

*Expected output*: `scan-bad` exits with code `42`, blocking the pull request and printing the exact Scar reference, invariant rationale, and remediation.

### 4. Run the Full Test Suite

Verifies backend invariants, cryptographic role boundaries, and the TypeScript target service:

```sh
uv run pytest
npm --prefix demo-app test
```

*Expected output*: 152 Python tests passing, 4 TypeScript tests passing.

---

## Live Room Interaction

When running in a live Switch room with connected agents:

1. **Report Incident**:
   ```text
   @nope teach "We had INC-014: someone logged the Authorization header. Never log credentials or tokens anywhere in this repository."
   ```
2. **Scope Decision**:
   NOPE queries in-thread:
   ```text
   I need two decisions before I create Scar 001:
   1. Should the scope be this repository or all services in the workspace?
   2. Should existing incidents be warned, or blocked on future pull requests only?
   ```
3. **Courtroom Challenge**:
   `@red-team` challenges the candidate rule with adversarial variants. `@nope-reviewer` tallies detection score.
4. **Human Approval**:
   The human SRE confirms the cryptographic approval ticket:
   ```text
   @nope approve "Verified taint coverage catches re-aliased credentials. Approved for main."
   ```
5. **Automated PR & CI Gate**:
   NOPE opens the Pull Request with the Semgrep rule and fixtures. Upon merge, CI enforces the rule on all future code.

## Architecture

Repeatable backend, real HTTP, Docker/PostgreSQL and TypeScript checks are in
[backend verification](docs/backend-verification.md).

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
apps/switch/               Switch Console client, room listener, evidence generator, and nope-room CLI
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

## Backup: Offline Demo (No Network or Agent Required)

If evaluating offline without an active Switch room or external LLM connections, you can run the deterministic local demo:

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

The offline script uses the checked-in bad fixture (`demo-app/fixtures/`), demonstrating the complete Rule Lab validation, independent adversarial challenge, evidence-bound approval, and CI gate rejection (`exit 42`) without external dependencies. The full Docker/PostgreSQL multi-process stack is configured in `docker-compose.yml`.
