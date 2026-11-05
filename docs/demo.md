# 6-minute demo script

This is the path to show a judge or stakeholder. It requires no external model or internet access until the Switch conversation portion.

## Setup (pre-record if room is unstable)

```sh
cd nope-switch
uv sync --extra dev --extra semgrep
npm --prefix demo-app ci
uv run pytest
```

Keep a terminal in this repository. Set local demo keys if running the HTTP service:

```sh
export NOPE_BASE_URL=http://localhost:8010
export NOPE_AGENT_KEY=agent-change-me
export NOPE_APPROVER_KEY=approver-change-me
export NOPE_CI_KEY=ci-change-me
```

## 1. Name the cost, not the prompt (0:00–0:35)

Say: “The best-reviewed codebase still repeats INC-001, because the lesson lives in Slack and in one engineer’s head. NOPE makes the next occurrence structurally impossible, and it keeps the reason attached.”

Open `config/.semgrep/nope-active.yml`. Point at `INC-014`, `remediation` and the Scar policy.

## 2. Show the product is deliberately closed-loop (0:35–1:15)

Open `docs/switch-setup.md`. Point out:

- the agent cannot create active rules from a chat message;
- validation and human approval are mandatory;
- all actions are appended to the audit ledger;
- target repo receives the config only after merge.

## 3. Run the deterministic loop (1:15–3:45)

```sh
uv run nope-demo reset
uv run nope-demo teach
uv run nope-demo validate
uv run nope-demo approve 1
uv run nope-demo activate 1
uv run nope-demo scan-good
```

Highlight `passed: true`, `bad_hits.bad = 1`, `good_hits.good = 0`, then status `active`.

## 4. Prove the safeguard blocks the incident again (3:45–4:45)

```sh
uv run nope-demo scan-bad
```

Expected exit code `42` and output:

```text
NOPE Scar 001 — Never expose authentication credentials in logs
Reason: INC-014; credentials reached customer support through monitoring.
Fix: delete the credential from the log or log user.id instead.
```

Also show the safe CI baseline:

```sh
npm --prefix demo-app test
npm --prefix demo-app run typecheck
sh scripts/enforce.sh
```

## 5. The challenge flow (4:45–5:30)

Inside the room, send:

```text
@nope challenge 001
The payment gateway uses a proprietary header. Is the rule still valid?
```

NOPE should ask for evidence, retrieve the active scar and propose either:
- a narrower replacement rule with passing fixtures, or
- a 14-day exception requiring a written reason and approver.

It must not loosen the rule silently.

## 6. Close with the business rule (5:30–6:00)

> “The diff is not the product. The ledger is. Every active Scar is incident-linked, test-backed, reviewable and reversible. You’re not buying faster code; you’re buying institutional memory your CI enforces by default.”

## Fallback script (if Switch or model is unavailable)

Use only the commands in steps 3–4. If nope-core needs to be shown over HTTP, start it with `uvicorn nope_core.main:app --port 8010` and inspect `http://127.0.0.1:8010/docs`; list the ledger with `uv run nope scars`.

Recording the fallback outputs before the presentation is legitimate redundancy, not deception. Do not edit them. If the live path works, use the live path.

## Judge Q&A

**Is this production-ready today?** The local demo path is verified, with Docker packaging for a single-purpose Node/Uvicorn/FastAPI service and PostgreSQL-backed schema creation on startup. Unpatched production use still needs hosted secrets, a GitHub App, branch protection, log retention and incident retrospectives.

**Why not just write Semgrep rules by hand?** Because hand-written policies don’t carry the provenance, rationale, review or challenge lifecycle, and they don’t turn chat lessons into enforcement.

**What if the AI generates a bad rule?** It doesn’t become active. The validation lab and approver are independent gates.
