# Demonstrate a real GitHub merge gate

The workflow `.github/workflows/nope-enforce.yml` publishes the unique check
`NOPE / policy`. It replays INC-014, checks the independent corpus, scans the
actual `demo-app/regression/credential-log.ts` file with Semgrep `--error
--strict`, and enforces changed source. Missing targets, scanner errors and
findings fail the job. Scan JSON is retained as a workflow artifact.

The regression target is outside the intentionally unsafe fixture exclusions.
The clean version logs a request identifier. On a separate bad-variant branch,
replace it with this known incident variant:

```typescript
declare const logger: { info: (value: unknown) => void };
declare const authorization: string;
const forwardedCredential = authorization;
logger.info({ forwardedCredential });
export {};
```

Run `uv run python scripts/check_regression.py` in each checkout. The clean
case must exit zero and the unsafe variant must exit nonzero. This local
result proves detection; it does not establish GitHub merge protection.

## Owner setup

An administrator must apply the reviewed additive ruleset after the check has
run. This does not replace other repository rules. The GitHub Actions app ID
15368 was retrieved from this repository's actual check runs, not guessed.

```powershell
gh api --method POST repos/praveenkumarpranjal/nope-switch/rulesets --input .github/nope-ruleset.json
gh api repos/praveenkumarpranjal/nope-switch/rules/branches/main
```

Review the returned active rules: main must require `NOPE / policy` from
GitHub Actions, with no bypass actors. Also restrict changes to the workflow,
rule and regression files through your repository's normal review controls.
Required status checks alone do not prevent a privileged author from changing
the check implementation.

During implementation, the authenticated account `kaushikkr-dev092005` had
push access but no admin access. The private repository's ruleset API returned
HTTP 403 with a plan restriction. Nothing was made public and no protection
was claimed to be installed. GitHub documents both the [plan and permission
requirements](https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-protected-branches/managing-a-branch-protection-rule).

## Capture the actual demonstration

1. Validate the exact taint candidate and independent challenge through the
   workbench. Request approval in the original Switch room; the authorized
   human submits that exact approval request using their own approver key.
2. Commit the approved rule, this workflow and clean target on the Scar branch.
   Prepare the PR with `nope-room prepare-pr` after canonical approval. Save
   the real passing run and PR URLs.
3. Create a separate bad-variant branch and PR carrying the same safeguard and
   the unsafe target above. Save the real failing run and scan artifact.
4. Read the effective main rules and both PRs' check/merge state. Record the
   required check configuration together with the failing check on the same
   PR head. Do not attempt a merge merely to test it.

```powershell
gh pr checks $badPr --repo praveenkumarpranjal/nope-switch
gh pr view $badPr --repo praveenkumarpranjal/nope-switch --json url,headRefOid,baseRefName,mergeStateStatus,statusCheckRollup
gh api repos/praveenkumarpranjal/nope-switch/rules/branches/main
```

Only report a merge blocker when an active, applicable required-check rule and
the failing required check are both verified. Missing admin rights, unavailable
rulesets, or an inaccessible merge state remain **BLOCKED / unverified**.
