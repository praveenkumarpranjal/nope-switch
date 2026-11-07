# NOPE in the real Switch room

Use the room **nope-never-again**, the actual local Mattermost connection, and
`@nope` running in this checkout. Codex is supported alongside Claude Code.
Console owns the incoming connection and agent sessions. The adapter in
`apps/switch` makes outbound HTTP calls and reads room context; nope-core never
imports it and exposes no Switch event listener.

The [current agent protocol](https://docs.switchagents.ai/switch-rooms/internals/agent-protocol)
uses WebSocket events and HTTP operations; older SSE clients are deprecated.
The old `docs.flintai.dev/mcp` address did not work during verification. The
[official repository](https://github.com/sandbox-quantum/switch#docs) now links
`https://docs.switchagents.ai/mcp`. This implementation also discovers operation
schemas from the actual running server before using them.

## Connection status and credentials

`LIVE` requires an observed real room request and an observed persisted agent
reply. `MOCK` means local deterministic testing without Switch. `BLOCKED` means
the required room, bridge, identity, credentials, or round trip is missing.
An HTTP health response or a locally passing test alone does not establish LIVE.

The six `NOPE_SWITCH_*` settings in `.env.example` are NOPE application settings,
not official Switch variable names. Do not put real tokens in that example.
Console's existing runtime uses `SWITCH_API_ENDPOINT`, `SWITCH_API_TOKEN`, and
`SWITCH_AGENT_ID`. Reuse its process environment. Alternatively, explicitly
select that agent's existing `credentials.json` with the global
`--console-credentials` option: only the required environment fields are loaded
in memory, without rewriting the file or copying its key into the repository.
Selecting that file explicitly enables Switch for the command.

From a Console agent session with its runtime credentials available:

```powershell
$env:NOPE_SWITCH_ENABLED = 'true'
uv run nope-room discover
```

Outside that session, select the **nope agent's** real credential file, not the
bootstrap buddy's file:

```powershell
uv run nope-room --console-credentials $consoleCredentials discover
```

`$consoleCredentials` must be the actual path supplied by Console. Discovery
reads the agent's real room membership, agent registry, and bridge list. It never
creates a substitute internal room or guesses a Mattermost URL. Set the observed
ID in `NOPE_SWITCH_ROOM_ID`; copy the real channel URL into
`NOPE_SWITCH_ROOM_URL`. Use the actual bridge display name for
`NOPE_SWITCH_BRIDGE_NAME`. Keep `.env` and runtime credentials outside Git.

## Teach, challenge, and prove the round trip

In Console, add `@nope` to the real room and attach this checkout as context. Use
`switch/nope-agent/brief.md` for its instructions. The owner and the other agents
must be permitted by the installed agent's actual addressing policy; defaults
vary between agent types and older installations. Do not broaden it to everyone
to hide a routing problem.

Post an actual request in Mattermost:

```text
@nope teach INC-014: never log authentication credentials in this repository.
```

Capture its real identifier and author, then prove the response:

```powershell
uv run nope-room receive
uv run nope-room roundtrip --source-message-id $actualMessageId
```

The first command saves source IDs, author IDs/names, original text, and room ID
to `.data/switch-requests.json`. It records `teach` and `challenge`; it does not
execute chat approvals. The second checks the real bridge and identity, posts an
acknowledgment as `@nope`, and reads it back before recording LIVE in
`.data/switch-status.json`.

For `nope create --data`, preserve `source_message` with `room_id`, `message_id`,
`author_id`, and `author_name`, plus `teach_message_url`, `incident_url`, and the
existing Scar fields. The proposal audit event stores those together, without
adding Switch transport to the domain. A challenge can include `source_message`
too. A reported author is provenance, not approval authorization.

`@nope` must invoke `nope validate` and ask the independent agent to invoke
`nope adversarial` with a different agent key. Post the exact returned replay,
detection, miss, false-positive, and scanner-error counts to the same room using
Console's normal messaging tool. Missing evidence must stay marked unverified.

## Three-agent courtroom

Add `red-team` and `nope-reviewer` as separate Console agents using the briefs in
`switch/red-team` and `switch/nope-reviewer`. Use the installed provider and the
actual machine. Run the addressing test before relying on handoffs:

```powershell
uv run nope-room probe --target red-team --target-id $redTeamSenderId --output .data/red-preflight.json
uv run nope-room probe --target nope-reviewer --target-id $reviewerSenderId --output .data/reviewer-preflight.json
```

These operations need the existing session's `SWITCH_CONNECTION_ID`. They do not
claim a new room or evict Console's connection. A fresh nonce must be returned by
the expected agent; an HTTP acknowledgment or someone else's reply is not proof.

Have red-team write fresh unsafe variations and safe controls **before reading
the author's candidate and fixtures**. Preserve its actual submission message
link. For the naive candidate, run the existing workbench:

```powershell
uv run nope validate $scar --rule switch/courtroom/naive.yml --original demo-app/fixtures/bad-authorization-log.ts --corrected demo-app/fixtures/good-redacted-log.ts --bad original.ts=demo-app/fixtures/bad-authorization-log.ts --good corrected.ts=demo-app/fixtures/good-redacted-log.ts
```

Red-team submits `nope adversarial $scar --data $freshChallenge` under its own
nope-core agent credential. Save the actual revision ID and result. Then repeat
validation with `config/.semgrep/nope-active.yml` and challenge the new revision
against the **unchanged** corpus. Do not activate the naive demonstration rule.

Publish both canonical results as `@nope`, then ask the reviewer for its verdict:

```powershell
uv run nope-room courtroom --scar $scar --naive-revision $naiveRevision --taint-revision $taintRevision --challenge-response-url $redTeamMessageUrl --preflight .data/red-preflight.json .data/reviewer-preflight.json --post
```

Live publication reads immutable evidence from nope-core HTTP; it does not
rerun validation outside the workbench. It checks independent challenger
identities, identical corpora, and the destination room against the original
Scar source. Human approval remains a separate step.

For a local-only comparison, `uv run nope-room courtroom` runs real Semgrep on
the two shipped candidates and the checked-in independent corpus. Its output is
explicitly MOCK with respect to Switch. The observed local result is: original
incident detected by both; naive rule misses 8/8 variants; taint rule detects
8/8, with zero false positives on five controls. This does not claim a live
three-agent conversation occurred.

## Scar documents and repeated developer trials

After the approved rule is activated:

```powershell
uv run nope-room document $scar --attach --post
```

The adapter discovers `create_room_document` and uses the existing Console
session. `--post` also posts a summary message; it does not claim to pin it.
For manual attachment, omit both flags and use `.data/scar-room.md` in Console.
The [room document mechanism](https://docs.switchagents.ai/switch-rooms/administer/shared-material)
shares context with agents; it is advisory and grants no CI exemption.

Use `switch/dev-agent/brief.md` and copy the manifest template from
`switch/room-experiment`. Collect at least five paired trials with the same
prompt, model, and agent. Use a fresh room/session per trial, counterbalance the
order, attach the Scar only in the treatment, and preserve every first response.
Replace every placeholder with actual room IDs, document IDs, message links,
and code file paths. A human reviewer must set `task_completed` true or false;
a harmless no-op is not a completed task. Do not silently discard failed trials.

```powershell
uv run nope-room compliance --manifest .data/experiment/manifest.json
```

This scores those actual code files with Semgrep, reports both compliance rates,
counts incomplete tasks, and leaves the rate unknown if scanner errors prevent
evaluation. Trial metadata is operator-supplied evidence. No live compliance
percentage is claimed until real responses exist. CI remains authoritative.

## Authorized human approval, PR, and activation

After validation and independent challenge, publish an exact approval request:

```powershell
uv run nope-room request-approval $scar --revision $taintRevision
```

This records the candidate ID, rule hash, evidence hash, repository, scope,
results and 24-hour expiry in the append-only ledger, then posts those exact
values in the original room. A delivery failure does not constitute approval.
Without a Switch room, `nope request-approval $scar --revision $taintRevision`
can prepare the same packet for local API review; it is not a live-room claim.

The human approver uses their own nope-core `approver` credential to run:

```powershell
uv run nope approve $scar --request .data/approval-request.json --approver $humanName --reason $reviewReason
```

The agent never receives that key. Chat text saying approved
cannot substitute for RBAC. The API records the credential identity separately
from the human-readable approver name. Unauthorized roles, missing bindings,
expired requests, changed candidates, mismatched scopes and evidence hashes,
and repeated approvals are rejected. Activation rechecks the approved hash.
Existing approvals without these bindings need a fresh validation and review.

```powershell
uv run nope-room prepare-pr $scar
```

This reads canonical HTTP provenance and refuses unless the latest revision is
approved by an authenticated approver/admin, with passing replay, regressions,
and independent challenge. It writes `.data/scar-pr.md` for review.

On the existing committed `nope/scar-NNN` branch containing the actual rule and
fixtures, add `--head $branch --create` to create the GitHub PR with `gh`. It
rechecks canonical approval and requires a clean matching branch, the exact
committed approved rule hash, the actual matching GitHub repository and the
named workflow plus regression target. It never
pushes main, merges the PR, or activates a Scar. Activation continues through the
existing authorized GitOps merge path; manual activation retains admin-only
authorization and an audited justification.

## CI-to-room ping

```powershell
uv run nope-room scan-bad --scar $scar --post
```

The adapter runs the real demo scan, reads its real finding file, and posts only
after exit 42. The message includes Scar ID, original teach link, matching
revision approver, failing file/line, and remediation. Rule hashes or embedded
revision IDs must match the approved evidence. Delivery failure leaves exit 42
intact and is recorded separately. No automatic fix is attempted.

`.github/workflows/nope-room-demo.yml` provides an explicit manual GitHub Actions
demonstration. Configure the actual reachable service URLs, room ID and agent ID
as repository variables, with keys in GitHub Secrets. A GitHub-hosted runner
cannot reach a server that exists only at your laptop's localhost. The demo job
intentionally fails with 42 and uploads scan/delivery evidence. Normal CI stays
includes the required-check workflow described in
[GitHub enforcement](github-enforcement.md). Installing a workflow does not
configure branch protection. The owner must apply and verify the required-check
rule before claiming that GitHub prevents the failing PR from merging.

The ledger records append-only events and content hashes. It does not provide
cryptographic signatures. API, operation-schema, peer-nonce, provenance, and
failure-isolation tests run locally without pretending to contact Switch.
