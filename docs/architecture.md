# Architecture and boundaries

## System context

```text
                          target repository
                          ┌────────────────┐
                          │ source + tests │
                          │ .github/ci     │
                          └─────┬──────────┘
                                │ semgrep / checkout
Slack/Discord/Teams/Telegram   │
       │                        ▼
       ▼                 ┌───────────────┐      ┌────────────────────┐
   Switch room ────────► │ NOPE agent    │ ───► │ nope-core          │
  (approve in text)      │ (case by case)│      │  FastAPI + SQL     │
                         └──┬───────┬────┘      │  Scar Ledger        │
                            │ CLI/  │ HTTP       │  Rule Lab (Semgrep) │
                            ▼       ▼             └─────────┬──────────┘
                       target repo changes        PostgreSQL / SQLite
```

## Boundary: judgement vs proof

| Concern | Owner | Notes |
|---|---|---|
| Reads natural language, extracts the invariant | NOPE agent | Cannot write activation state |
| Applies domain judgement to codebase | NOPE agent | Reads repo through Switch reference |
| Creates fixtures/rule candidate | NOPE agent | Outputs YAML and examples |
| Verifies fixtures/rule match | Rule Lab | Deterministic Semgrep process |
| Approves enforcement | Named human | API role `approver`/`admin` |
| Enforces on CI | Workflow | Committed config, not live model output |
| Stores evidence | nope-core | Append-only where practical |

## Scar lifecycle

```text
PROPOSED ─validate→ VALIDATED ─approve→ APPROVED ─activate→ ACTIVE
   │                                     │                    │
   │                                     └─ challenge         └─ CI reads
   └──── validation rejected (stored evidence) ─→ back to agent

ACTIVE ─challenge→ pending exception ─expiry/reject→ ACTIVE  (never silent)
```

## Request flows

### API authentication

Every non-health route requires `X-NOPE-Key`. Key format: `key:role` entries in `NOPE_API_KEYS`. Roles: `ci < agent < approver < admin`.

### Validation

1. Rule YAML is parsed; it must have a non-empty `rules` list with required keys.
2. Examples are written to an isolated temporary directory.
3. Semgrep runs with a fixed time budget and `--metrics=off`.
4. Results are mapped to fixture names using immutable resolved paths.
5. Bad-hit and good-hit thresholds are applied from configuration.
6. The result is stored even if rejected.

### CI

`scripts/enforce.sh` scans only added changes using `--baseline-commit`. Fallback scans the repository but is labelled as blocking only for safety-critical config. Test fixtures and rules are excluded from enforcement.

## Data model

- `scars`: immutable origin, invariant and remediation; mutable status is transitioned by actions.
- `rule_versions`: sha256 and version for each validated or proposed candidate.
- `validation_runs`: bad/good hit evidence.
- `exceptions`: expiry-limited, review-mediated bypasses.
- `audit_events`: append-only operational trail.

## Why this is not just "ChatGPT writes a Semgrep rule"

- The target policy is reviewed and tested like code.
- The **reason** travels with it.
- The exception path is explicit, short-lived and audited.
- The rest of the team's normal CI is still the final gate.
