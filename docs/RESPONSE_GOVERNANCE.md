# Analyst governance and case evidence

Migration 20 adds closed analyst roles, persistent manual-request retry keys and
append-only response decision history. Existing analyst credentials migrate to
`analyst`, preserving existing behavior. Bootstrap-authorized analyst enrollment
accepts `role`: `viewer`, `responder`, `approver`, or `analyst`.

| Role | Read/export evidence | Stage response | Approve/reject/cancel | Update incidents |
| --- | --- | --- | --- | --- |
| viewer | Yes | No | No | No |
| responder | Yes | Yes | No | Yes |
| approver | Yes | No | Yes | Yes |
| analyst (legacy default) | Yes | Yes | Yes | Yes |

`GET /api/v1/analysts/me` and response catalog `analyst` metadata report the
authenticated identity and permissions. Role changes require the existing
privileged enrollment bootstrap credential, rotate the analyst credential, and
invalidate its previous token. There is no unauthenticated role-update route.
These roles do not implement tenant or host authorization scopes or SSO.

Set `PANOPTICON_REQUIRE_SEPARATE_APPROVER=true` to require a different analyst
to authorize manually staged requests. Accepted values are `true`, `false`, `1`,
`0` (case-insensitive); an invalid configured value refuses approvals/catalog
with 503. Default is false for existing single-analyst workflows. Detection policy
still controls automatic collection; destructive actions still require approval.
Rejection and queued cancellation remain possible for authorized approvers.

Manual POST accepts optional `request_id`, 1–128 characters from
`[A-Za-z0-9._:-]`. The authenticated analyst and ID identify the original request
persistently. Replaying the same normalized body returns that request and current
recommendation state (`replayed: true`), even after rejection/expiry/completion.
A changed body with that ID returns 409. Missing IDs retain legacy behavior.
The ID prevents request duplication; it never authorizes a second OS execution.

`decision_audit` records new staging, authorization, rejection, expiry and queued
cancellation facts in the same database transaction as their state changes.
Database triggers reject event updates/deletion. Existing events are not invented
on upgrade. Database administrators remain outside this application guarantee.

The queue supports `command_state` independently of recommendation `state`, so
operators can isolate INDETERMINATE, FAILED, CANCELLED, EXPIRED or in-flight
commands. Polling includes at most 100 command audit events, 100 decision events
and 20 V2 receipts per action and sets `evidence_truncated` when more exist.
`GET /api/v1/response-actions/{id}/export` returns the full case in a consistent
read snapshot: exact target/command, request and approver identities, decision and
execution histories, results and immutable receipts. It contains no analyst
credential. Export is complete for retained rows, not a tamper-proof forensic
signature. Retention policy and archive storage are separate deployment concerns.

The Console proxies identity/export with credentials kept server-side. Each
Console deployment uses its configured analyst identity; roles are enforced by
Manager even if a browser bypasses hidden/disabled controls. Separate analyst
sessions or an identity gateway are needed to operate a multi-user deployment.

Validation includes role denial, separate-approver policy, retry conflicts after
decisions, immutable audit, bounded queue/full export, contract parity and the
real HTTP Console/Manager smoke. Receipts in automated smoke are simulated;
privileged Windows/Linux execution still requires the endpoint E2E runbook.

Run `.venv/Scripts/python.exe tools/verify_response_console.py --governance`
against a sibling governance Console checkout to qualify the full flow over real
loopback HTTP. `--serve --console-port 8787` keeps an isolated synthetic lab open
on a stable local address for browser inspection. These flags do not connect to
real enrolled endpoints or execute native actions. The standard smoke mode remains
available for older compatible Console revisions.
