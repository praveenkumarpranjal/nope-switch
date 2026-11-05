# Roadmap: from hackathon workflow to resilient platform

## Current release — enforcement loop, not a demo shell

- [x] `@nope teach` workflow and documented Switch onboarding.
- [x] Scar Ledger API with status lifecycle and audit trail.
- [x] Rule Lab validation against bad/good fixtures and target repo.
- [x] TypeScript target service with tests and safe logger.
- [x] CI enforcement on new violations, not the intentionally bad fixture.
- [x] Explicit human approval; no silent rule activation.
- [x] Expiring exception concept; starter implementation only.

## 14 days — production pilot one team

1. Replace demo incident with redacted export from one real postmortem.
2. Add a GitHub App to report PR-merged and check-run events.
3. Make `@nope challenge` a room thread with:
   - evidence query,
   - narrowing proposal,
   - 14-day rollback,
   - approver decision.
4. Create `.nopeignore` decision log; every exclusion has an expiry.
5. Export ledger diff as Markdown PR notes; this proves adoption in Slack.
6. Add SLO dashboard: rule proposal latency, FP rate, challenge resolution time.

## 30–45 days — platform reliability

- Run nope-core behind SSO/reverse proxy with mTLS for CI calls.
- PostgreSQL HA; database backup/restore drill monthly.
- OpenTelemetry traces across room message → agent run → API call → check result.
- Rule packs for TypeScript, Python, Terraform; each with a signed fixture suite.
- Weekly automated replay of all active rules against each repo's scar corpus.
- Device authorization and short-lived tokens instead of env-var keys.

## 60–90 days — organizational memory

- Cross-repo discovery of the same incident class; suggestions only, never auto-applied.
- Duplicate/similarity matching between proposed scar and corpus.
- New-engineer onboarding room: "here are the ten scars that protect this codebase now".
- Rule sunset notification: inactive for 180 days or contradicted by architecture decision.
- Blameless KPI: repeated incident rate, not engineer scorecards.

## 90+ days — policy engineering discipline

- Rule simulation in staging: apply candidate to last six months of commits; emit predicted false positives.
- Exception SLA escalation; all expired exceptions cause CI fail until closed.
- SARIF export to code scanning; security dashboard integration.
- Compliance export (SOC 2/ISO) mapping control C-SC-01 to active scars.
- Multi-tenant control plane with workspace-scoped references and per-room packages.
- Public protocol documentation for "how to challenge a rule with evidence".

## Out of scope until the above works

- General natural language → arbitrary secure code generation.
- Auto-merge or auto-revert bots.
- Inventing incidents or approving policy autonomously.
- A standalone product that excludes humans from decisions.
