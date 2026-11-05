# Business case and measurement

## The problem no linter can own alone

Most teams have every ingredient: incidents, postmortems, linters and strong engineers. The missing ingredient is an **approval path that binds them together**. Incident notes name what broke; code review catches some things; CI enforces only what someone remembered to configure. The remainder is repeated at 3am by a new hire.

NOPE supplies that bond through a room where engineers, SREs, security and the responsible agent can decide together.

## Who buys

- **Engineering leadership:** fewer repeat incidents, shorter onboarding, evidence for audit and board review.
- **Security / AppSec:** rules carry incident context and can focus on the precise class of control that failed.
- **Platform teams:** one place to ask for a prevention rule instead of filing a linter PR.
- **Delivery teams:** visible, reversible safety; not an opaque "the bot said no".

## Measurable outcomes

| Metric | Baseline question | NOPE measurement |
|---|---|---|
| Time-to-safeguard | How long from "we fixed it" to enforceable prevention? | Minutes to propose, one review to activate; stored as ledger timestamps. |
| Repeat-trigger rate | Did the same class re-enter review/CI? | Count CI findings linked to scar IDs; zero means the safeguard held. |
| False-positive rate | Did a reviewer dispute the scanner or disarm it? | Good-fixture misses and `@nope challenge` requests per active scar. |
| Rule adoption | Are proposed scars reviewed or ignored? | Proposed → approved conversion, days to first merge. |
| Audit readiness | Can you produce the reason behind every CI policy? | `/v1/audit` shows origin, reviewer and expiry. |

## Pricing hypothesis (if this becomes a company)

- **Team:** fixed monthly for one ledger and one target repo family.
- **Org:** per repo/group plus hosted control plane, custom rule packs and GitHub App.
- **Regulated:** private deployment, SBOM, SSO, immutable ledger export and incident SLA.

Do not sell "AI". Sell the result: **fewer repeated incidents with evidence**.

## Where it fails

- If senior engineers never use the room, nothing changes. Introduce it after a real incident review.
- If every event creates a permanent rule, CI becomes noise. Keep scope tight and use expiry.
- If the dashboard matters more than the prevention loop, adoption collapses.
- If the agent can approve or merge, trust is lost permanently. Never ship that.
