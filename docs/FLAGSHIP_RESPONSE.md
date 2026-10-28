# Response authority, readiness and campaigns

29 October 2026 implementation sprint. Manual/native E2E testing is deferred at
the user's request. Unit, contract and API regressions remain required; existing
CI remains the merge gate. The shared domain `docs/FLAGSHIP_RESPONSE_PLAN.md`
records delivery order and following milestones.

## Command authority

The organization's `feat/linux-command-signing` work is integrated without its
unrelated ingestion changes. Canonical bytes live in response-engine; negotiated
schemas and native reference vectors live in contracts.

Set `PANOPTICON_COMMAND_SIGNING_KEY` to an unencrypted P-256 PEM private-key file.
`python -m manager.command_signing generate PATH` creates a new file exclusively
and prints the public keyring line; `keyring-line PATH` prints that public line.
No key is created implicitly. Provision the public key into each Linux sensor's
keyring through the trusted deployment workflow. Private-key custody remains in
Manager's process. Key loading bounds file size, validates the same regular-file
handle, checks POSIX private permissions and rereads at each authorization for
rotation. Windows key ACLs remain a deployment responsibility.

A configured unusable key returns 503. Signed command lifetimes must be positive
and at most 900 seconds. Manager signs at authorization, retains the signature,
and never re-signs a stored command at polling. Audit records the public key ID.

Polls requesting `command_auth=ES256` never receive unsigned queued commands:
such a queue returns 409 without dispatch, requiring cancellation/new approval.
The authenticated signing demand is retained, and subsequent authorization for
that endpoint requires a signer. Legacy polls do not clear the observed demand.
Windows's strict decoder receives its original envelope with no authorization
extension; native Windows signature verification remains separate future work.

## Readiness and advisory review

`GET /api/v1/agents/{id}/response-readiness` reports enrollment, last authenticated
command poll, delivery/auth mode, contact age and current authority readiness.
Contact is recent within five minutes, stale afterward and unknown before a poll.
Contact is an observation, not proof of current connectivity, native capabilities
or enforcement mode. Native mode stays unknown. Retained Linux health snapshots may report policy
capabilities with unverified freshness; see `LINUX_RESPONSE.md`.

`GET /api/v1/response-actions/{id}/preflight` checks permission, pending state,
retained target/enrollment, separate approval and authority, with contact warnings.
It is advisory and read-only. Actual authorization independently rechecks identity
and signing availability. Catalog metadata exposes authority status/public key ID
and feature limits. These routes require analyst authentication.

## Bounded staging campaigns

`POST /api/v1/response-campaigns` accepts `{campaign_id, items}` with 1–25 manual
request bodies. Items omit `request_id`; Manager derives retry identities from
actor, campaign ID and index. Every item uses single-request permission/validation
and stays pending for individual approval. No campaign auto-authorizes commands.

Each item reports its response ID or specific error. Expected refusals roll back
that item's savepoint; unexpected server/storage errors roll back the whole batch.
The report persists atomically. Same actor/ID/normalized body returns the original
report/IDs, while changed intent returns 409. New staged items gain a
`campaign_linked` decision event. `GET /api/v1/response-campaigns` lists the current
analyst's recent reports. Reports describe staging; use the queue for current
execution state. Mutation still requires the request permission.

Migration 21 preserves existing evidence and adds observed channels/reports.
Restart Manager and Console after dependency upgrades. This release does not
implement automatic key distribution, external key custody, per-browser analyst
sessions, native capability reporting, artifact transfer/custody, automatic
multi-step playbooks or OS fault reconciliation. Those remain in the shared plan.
Static vectors and API tests establish no live native execution or product-parity
claim.

For a synthetic local UI preview without running response workflow qualification:
`.venv/Scripts/python.exe tools/verify_response_console.py --preview-only --console-port 60580`.
It creates an isolated temporary lab, does not connect to real endpoints and
does not execute the smoke/E2E workflow. Stop the process to close the preview.
