# Replay, independent challenge, and evolution

Every candidate revision preserves its rule hash, original vulnerable incident code,
corrected incident code, author fixtures, test reports, authenticated author identity,
independent challenger identity, and fixed quality threshold in the Scar Ledger.
Evidence is stored in the additive `scar_revisions` table; existing tables need no
destructive migration. Run `python -m nope_core.migrate` when upgrading.
Legacy active Scars must be revalidated, independently challenged, approved and
activated to acquire revision evidence before exporting a new active rule pack.

## Counterfactual replay

```sh
nope validate 1 --rule config/.semgrep/nope-active.yml \
  --original demo-app/fixtures/bad-authorization-log.ts \
  --corrected demo-app/fixtures/good-redacted-log.ts \
  --bad original.ts=demo-app/fixtures/bad-authorization-log.ts \
  --good corrected.ts=demo-app/fixtures/good-redacted-log.ts
```

The original must produce a finding and the corrected version must produce none.
Scanner failures fail validation. The response includes separate `replay`,
`regression`, and author-suite results. This is required for every candidate.

## Independent adversarial challenge

Start a separate agent with the incident, invariant, and repository code context.
Do not give it the rule author's test fixtures. Have it generate a JSON bundle
like `demo-app/fixtures/adversarial-challenge.json`, including unsafe variations
and safe negative controls. The checked-in bundle was authored by a separate agent.
The core runs the submitted examples deterministically; Switch's agent harness
is responsible for launching the independent authoring process.

Configure a separate `challenger-key:agent` entry in `NOPE_API_KEYS` and supply it
through `NOPE_AGENT_KEY` for the challenger CLI process:

```sh
nope adversarial 1 --data demo-app/fixtures/adversarial-challenge.json
nope provenance 1
```

The API rejects the author's authenticated identity, repeated fixture contents,
author-fixture reuse, and attempts to overwrite a challenge. A display name alone
does not establish independence. Each revision fixes these thresholds before the
challenge runs: at least six unsafe examples, at least four safe examples,
100% detection, and 0% false positives. Metrics count examples rather than the
number of findings in each example. Misses, false positives, scan errors, or too
few examples prevent approval. API keys establish separate submitted identities;
operators must keep challenger credentials separate and supervise agent isolation.

```sh
nope reject 1 --approver reviewer --reason "Independent variations expose misses"
```

Rejection appends a decision. Submit a new candidate revision to improve a rule;
the failed report remains available. The offline path is:

```sh
uv run nope-demo reset
uv run nope-demo teach
uv run nope-demo validate
uv run nope-demo adversarial
uv run nope-demo approve 1
uv run nope-demo activate 1
```

The offline command replays the independently authored checked-in examples using
distinct recorded demo identities; it does not call a model or claim to generate
fresh challenges. `uv run python scripts/check_assurance.py` runs actual Semgrep
and writes `.data/assurance-report.json`. CI runs this check and uploads its report.

## Provenance and replacement rules

Active rule exports include the incident, approved revision and rule hash, test
artifact link, and decision history link. The CI reporter carries these into
console output and GitHub step summaries, including offline fallback output.
API links require an authorized CI or agent key. The bundled offline policy
uses repository-relative paths so evidence remains available without a server.

Use `nope challenge 1 --requester developer --reason "..." --proposed-rule replacement.yml`
to propose an evolution. The server recovers the incident pair itself and tests
the proposed rule against every previously approved incident, author suite, and
independent challenge. Tests are accumulated across revisions. The replacement
also needs fresh independent challenge evidence and human approval.

Normal activation follows the reviewed GitOps PR merge. Manual HTTP activation
requires an administrator key and an audited justification:
`nope activate 1 --authorized-by administrator --reason "Reviewed emergency activation"`.
This manual path enforces the same approved-revision gate. The offline demo
uses a separate local ledger and invokes the service directly.

Proposals and rejected rules never change the active exported rule. Activation
switches the approved revision; the old revision becomes superseded and keeps
its evidence. CI submits the revision ID embedded in the scanned rule, preserving
the exact provenance of older failures even after a replacement is activated.

The initial policy caught the original incident but detected only 2 of 8
independent unsafe variants, missed 6, and falsely flagged 1 of 5 safe controls.
The checked-in policy was revised against that unchanged challenge and detects
all 8 unsafe variations with 0 misses and 0 false positives across the 5 controls. Fixture
coverage is evidence for these cases, not a guarantee for every possible program.
