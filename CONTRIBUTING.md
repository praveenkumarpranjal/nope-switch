# Contributing

NOPE favours small, reviewable contributions that strengthen the evidence chain.

## Ground rules

- Every behavior change that touches approval, activation, exceptions or audit needs a test.
- Every rule pack addition ships with at least one bad and one good fixture.
- Preserve history; never delete or rewrite ledger events to make a demo look clean.
- Do not weaken Semgrep, CI or authentication to make tests pass; fix the fixture instead.
- Never commit real provider keys, incident data or customer data.

## Development loop

```sh
uv sync --extra dev --extra semgrep
npm --prefix demo-app ci
uv run pytest
npm --prefix demo-app test
sh scripts/enforce.sh
```

Open a branch matching `nope/*` or `feat/*`; in production, branch protection requires a human review.

## Adding a new rule pack

1. Identify a concrete incident class.
2. Add `docs/rule-packs/<slug>.md` with provenance and remediation.
3. Add `.semgrep/rule-pack-<slug>.yml` and fixtures under `apps/core/tests/fixtures/<slug>/`.
4. Add tests for both sides of the boundary (`bad` must match, `good` must not).
5. Request review from this repository's security owner.
6. Activate only after a human approval event in the Scar Ledger and merged CI.
