# Hackathon submission summary

**Project:** NOPE — Never-Again Compiler  
**Track:** Best Business Workflow  
**Tagline:** Your codebase remembers the mistake your team already paid for.  
**Why now:** Engineering teams do not lack postmortems. They lack a path from postmortem to permanent, reviewable prevention.

## One-line story

> We stop the next developer from repeating the same security incident, not by reminding them in chat, but because their CI refuses the pattern and tells them why.

## What is real in this repository

```sh
uv sync --extra dev --extra semgrep
uv run pytest
npm --prefix demo-app ci
npm --prefix demo-app test
uv run nope-demo reset && uv run nope-demo teach && uv run nope-demo validate && uv run nope-demo activate 1
uv run nope-demo scan-bad
```

## Files that demonstrate the workflow

- `switch/nope-agent/brief.md` — how `@nope` behaves in the room.
- `apps/core/src/nope_core/rule_lab.py` — the proof gate.
- `apps/core/src/nope_core/db.py` — append-only ledger model.
- `config/.semgrep/nope-active.yml` — active, approved Scar SCAR-001.
- `.github/workflows/ci.yml` — enforcement on pull requests.
- `docs/demo.md` — exact judge/demo script.
- `demo-app/` — seeded strict TypeScript target with tests.

## Judging criteria mapping

| Criterion | Evidence |
|---|---|
| Use of Switch | The workflow cannot activate through a CLI alone; a room reports, confirms, approves and challenges. Switch carries GitHub reference, team context and routing. |
| Technical execution | Clone, install and reproduce in one command; Python tests, Node tests, enforcement workflow and seeded bad fixture. |
| Creativity / impact | Prevents repeat incidents rather than generating more code; direct measurable KPI is reach of production safeguards. |
| Presentation | 6-minute demo; deterministic offline fallback; no fake model output. |

## Ethical boundaries

NOPE is designed for fail-closed privileged actions. It does not execute agent output, merge code, weaken CI, or create approval. The riskiest team mistake in this domain is an automation that becomes policy without evidence. That is exactly what this architecture forbids.
