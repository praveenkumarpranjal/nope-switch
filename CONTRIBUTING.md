# Contributing

NOPE favours small, reviewable contributions that strengthen the evidence chain.

## Ground rules

- **Direct pushes to `main` are strictly forbidden.** All contributions from collaborators must be developed on a dedicated branch and submitted through a GitHub Pull Request.
- **Mandatory Review:** Merges to `main` require explicit review and approval by repository maintainer (@praveenkumarpranjal).
- Every behavior change that touches approval, activation, exceptions or audit needs a test.
- Every rule pack addition ships with at least one bad and one good fixture.
- Preserve history; never delete or rewrite ledger events to make a demo look clean.
- Do not weaken Semgrep, CI or authentication to make tests pass; fix the fixture instead.
- Never commit real provider keys, incident data or customer data.

## Branching & Pull Request Workflow

1. Create a dedicated branch off `main`:
   ```sh
   git checkout -b feature/<descriptive-name>
   # or
   git checkout -b scar/<scar-number>-<slug>
   ```
2. Run local verification before pushing:
   ```sh
   uv sync --extra dev --extra semgrep
   uv run ruff check .
   uv run mypy -p nope_core
   uv run mypy apps/core/tests
   uv run pytest
   npm --prefix demo-app ci && npm --prefix demo-app test
   sh scripts/ci.sh
   ```
3. Push your branch to GitHub:
   ```sh
   git push -u origin feature/<descriptive-name>
   ```
4. Open a Pull Request targeting `main` via GitHub CLI or web UI:
   ```sh
   gh pr create --base main --head feature/<descriptive-name> --title "[Feature] ..." --body "..."
   ```
5. CI will run all Python, Semgrep, and TypeScript checks against the PR.
6. The maintainer will review code quality, test coverage, and assurance invariants before merging. Do not merge without review approval.

## Adding a new rule pack

1. Identify a concrete incident class.
2. Add `docs/rule-packs/<slug>.md` with provenance and remediation.
3. Add `.semgrep/rule-pack-<slug>.yml` and fixtures under `apps/core/tests/fixtures/<slug>/`.
4. Add tests for both sides of the boundary (`bad` must match, `good` must not).
5. Request review from this repository's security owner.
6. Activate only after a human approval event in the Scar Ledger and merged CI.
