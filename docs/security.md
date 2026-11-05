# Security and threat model

## Assets that matter

1. Source code, CI diffs and configuration in the target repository.
2. Incident provenance and the reason a rule exists.
3. Approval identities, CI status and exception records.
4. Credential material accidentally placed in logs or fixtures.
5. Integrity of the active rule file committed to the repository.

## Threats and controls

| Threat | Control in this project |
|---|---|
| A message in a public room creates a CI block | `@nope teach` requires explicit scope/enforcement confirmation; a rule activates only after tests and authorized approval. |
| A generated rule is subtly wrong | Rule Lab requires positive and negative fixtures. Failing results are stored; no automated merge. |
| An exception becomes an invisible bypass | Exceptions are separate ledger rows with requester, reason, approver and `expires_at`; defaults expire in 14 days. |
| An existing code base gets permanently blocked | Initial rollout uses baseline reporting; `NOPE_BASELINE_ENFORCE=false`. Blocking is reserved for new diffs. |
| Agent edits are silently merged | Agents may create branches and PRs but not approve/merge. Branch protection and CODEOWNERS are required. |
| Rules are removed as architecture changes | Deprecation and replacement are new audited events; history is never deleted. |
| Repository secrets enter ledger | nope-core accepts only the request fields; validation output stores paths/counts, not raw file contents. Incident record must be redacted by the requester. |
| Forged CI status or approval API | Production requires `X-NOPE-Key` for everything except `/health`; roles separate CI, agent and approver capabilities. HMAC verifies webhooks (placeholder pending GitHub App integration). |
| Log-spoofing blocker | Missing redaction/policy cannot block release. The least-privilege path fails closed for privileged actions, never for user traffic. |
| Dependency compromise | `uv.lock` and `package-lock.json` pin exact packages; CI builds from lockfiles and `.dockerignore`; SBOM can be generated with Dockerfile. |

## Deployment hardening checklist

- [ ] Put nope-core behind your SSO/reverse proxy or VPN; do not make the dashboard public.
- [ ] Use one API key per actor and rotate them quarterly.
- [ ] Set `NOPE_ENV=production`, `NOPE_ALLOW_ANONYMOUS=false`.
- [ ] Use PostgreSQL; do not share the SQLite file.
- [ ] Use a dedicated GitHub App; restrict access to named repositories.
- [ ] Enable branch protection: required review + `NOPE policy smoke test`.
- [ ] Store secrets in your cloud secret manager; never `.env` on disk.
- [ ] Redact production logs before sending incident text to nope-core.
- [ ] Set request body size limits at the proxy.
- [ ] Alert on approvals and exception creation, not only on CI failures.
- [ ] Review all active exceptions weekly.
- [ ] Remove a scar only through a reviewed deprecation; never edit history.

## What is deliberately out of scope

- Vulnerability severity scoring (use your existing SCA stack).
- Autonomous incident response and production deploys.
- Proving that a generated model understood the invariant.
- Legal/compliance advice. NOPE records evidence; it does not decide who is liable.
