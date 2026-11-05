# Switch setup — NOPE room

**The rule:** Switch is the operating surface. nope-core is the deterministic control plane. The coding agent is the builder, never the approver.

## 1. Register the agent

In `Switch Console → Your Agents → New agent`, use:

| Field | Value |
|---|---|
| Name | `nope` |
| Description | Converts a reported engineering lesson into a tested CI rule in this repository. |
| Run location | This computer (or managed worker for production) |
| Directory | The checkout of this repository |
| Provider | OpenCode, Claude Code or Codex — whichever the team owns |
| Instructions | Paste `switch/nope-agent/brief.md` unedited |

Production setting: run it on a managed worker with read access to the Switch reference, not an administrator's laptop. The worker should have GitHub write access only to branches matching `nope/*` and should not merge PRs.

## 2. Make the room real

Create `#incidents` as a Switch room. Attach a GitHub reference for this target repository with instructions such as:

> This repository is the target of Switch's NOPE workflow. Read its `.github/workflows`, tests and existing logging code before proposing changes. Do not push to protected branches.

Add participants:

- the team responsible for the repository;
- a code owner / SRE as approver;
- `@nope`;
- any coding agent the team wants to pair with it.

Set `@nope` to answer its owner and owner's agents only, or use custom room permissions. Never give it unrestricted `anyone` access in a production room without access review.

## 3. Give it the right capacity

The agent needs:

- read access to the repository reference;
- permission to create a branch or PR through `gh`, a GitHub App or the team's existing CI bot;
- `nope` on `PATH`, signed with an agent key;
- Semgrep available in that environment;
- no access to production logs containing customer data unless redacted.

Set the keys:

```sh
export NOPE_BASE_URL=http://localhost:8010
export NOPE_AGENT_KEY=agent-change-me
export NOPE_APPROVER_KEY=approver-change-me
export NOPE_CI_KEY=ci-change-me
```

## 4. Run the full loop

In the room:

```text
@nope teach "We had INC-014: someone logged the Authorization header. Never log credentials in this repository."
```

NOPE asks scope and rollout questions. Answer them in thread. It should:

1. inspect auth/logger/CI;
2. create a proposed scar with `nope create --data`;
3. generate the smallest rule and two fixtures;
4. call `nope validate`;
5. ask you to approve;
6. open a pull request marked `(DO NOT MERGE — needs approval)`.

After review in the room, merge it. The merge webhook or approved operator updates the scar to active.

## 5. Proof sequence for demo / judging

1. Show `config/.semgrep/nope-active.yml`.
2. Run the target service test.
3. Run the baseline scan and show clean.
4. Run the deterministic bad scan and show exit code 42 plus Scar 001.
5. Show `GET /v1/audit` with proposal → validation → approval → activation.
6. Ask `@nope challenge 001` and demonstrate that editing cannot bypass CI.

## 6. Permissions checklist

- [ ] Agent key is scoped to `agent`, not `approver` or `admin`.
- [ ] Approvers have separate keys and hardware-backed identities where possible.
- [ ] CI can write check results but cannot approve scars.
- [ ] The target repository branch protection requires a review and status check.
- [ ] The webhook secret is set, never committed.
- [ ] Exception expiry is short by default (14 days).
- [ ] Every approval links PR and room message in the scar rationale.
