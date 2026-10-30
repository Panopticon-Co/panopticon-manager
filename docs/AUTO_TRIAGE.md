# Automated investigation triage

Migration 32 adds collection-only workflows to the existing detection transaction,
request/approval queue and tamper-evident response audit. No new endpoint action,
script, shell or isolation behavior is introduced. Unconfigured rules keep their
existing response behavior; a configured triage rule owns its collection
recommendations even while disabled, preventing fallback to legacy AUTO_SAFE.
Disruptive recommendations retain their existing independent analyst path.

## Operation

Provision `triage_admin` through `PANOPTICON_TRIAGE_ADMIN_ENROLLMENT_TOKEN`, which
must differ from ordinary analyst and artifact-administrator enrollment secrets.
Access policy version 3 grants only `triage:manage` to this role: it cannot approve
responses, pull evidence or grant evidence scope. Ordinary roles retain their
existing permissions and cannot configure automatic collection. Existing
privileged identities cannot be overwritten through another enrollment role.

Sign in using the Console's individual identity form and open Automated
investigation triage. Administrators configure a rule's standard-endpoint action
decisions, exact Windows/Linux file paths and budgets. Critical and unclassified
endpoints cannot auto-execute. Unknown classification is the default; changing a
classification requires the dedicated administrator and an audited reason.
Policy edits use immutable revisions, optimistic version checks and per-actor
retry identity. Saving an older editor returns conflict. Policies default off.

Operators refresh triage to see rule/policy revision, endpoint, deadline, initial
decisions, recorded skip reasons, live blockers, reserved bytes and linked response
cases. Case evidence continues through individual credential/case/endpoint grants.
Approvers can stop remaining collections through the existing queued-command
cancellation writer. Pending approval items use the existing rejection writer.
Cancellation retries are no-ops; already-delivered work may have started and is
not claimed recalled. Late results/evidence are retained under existing rules.

## Collection and budgets

Only COLLECT_PROCESS_INFO, COLLECT_NETWORK_CONNECTIONS and COLLECT_FILE are eligible.
File collection is JSON metadata/hash, never binary acquisition. Automatic file
collection additionally requires an exact platform/path allowlist. Process targets
come from retained verified native alert identity, with boot/PID/start-time binding.
Ambiguous file sources, stale or unsupported capability, off/dry-run mode, absent
signed-artifact delivery, a missing acceptance gate or inactive signing key skip
collection with a recorded reason. No platform support is inferred from its name.

The default collection budget reserves 1 MiB per accepted plan item, up to three
items/3 MiB per alert, 12 items/12 MiB per endpoint per 900 seconds, three active
items per endpoint, a hard global cap of 128 active items and a 300-second deadline.
Pending approvals count conservatively as active reservations. Limits may be
tightened within the central schema's hard bounds. Counters are shared across
rules on the same endpoint and reserved atomically under BEGIN IMMEDIATE; replayed
alerts cannot reserve twice. Window reservations are not refunded by cancellation,
small results or completion. Expiration permits the next window, not retroactive
budget reuse. Rechecks exclude the candidate's own prior reservation.

At most one collection per alert is delivered at once. Native durable replay uses
the same command identity, without recollection. Policy revision, enabled state,
classification revision, enrollment, capability, signing-key availability, target
and deadline are checked at authorization, poll and endpoint acceptance. Windows
and Linux collection executors require an exact affirmative live Manager ACK.
Queued work made permanently invalid by a revision/classification/deadline change
is reconciled through existing rejection/cancellation; transient capability
blockers remain visible and may clear before the deadline.

## Audit and interfaces

The existing signed-checkpoint/hash-chain writer covers rule edits, classifications,
created/skipped plans, authorization, dispatch, acceptance, results, final audit and
cancellation. Automated lifecycle facts use `system/auto-triage`, an immutable
policy-version reference and original actor provenance. Query via response-audit
request_id (response ID, or alert ID for a skip/run event), actor, asset_id and time.
No event commits without its audit fact; audit failure rolls back response work
while preserving the originating detection.

Manager exposes bounded `/api/v1/triage/policies`, `/assets`, `/runs`, and
`/runs/{alert_id}/cancel`. Console forwards only these allowlisted paths through
`/api/evidence/triage`, with individual credentials, same-origin checks and identity
version binding. There is no shared-token fallback. Case evidence uses the existing
signed manifest/hash verification and custody path.

Tests cover both reported platforms, the real detection sink, concurrent budget
reservation, replay, approval/critical assets, capability and key denial, policy/
classification/boot rechecks, cancellation, deadlines, audit rollback and filtered
chain queries. Full manual/native system E2E remains deferred; CI and focused
component/API/Console qualification are required before merge. Rollout requires
deployment/restart of the qualified releases and explicit operator provisioning;
merging code does not modify the running lab services.
