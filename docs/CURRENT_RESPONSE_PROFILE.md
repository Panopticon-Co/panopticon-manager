# Current response capabilities and policy

Agents send bounded Base64 UTF-8 JSON on `X-Panopticon-Response-Profile` with each
command poll. The central schema and delivery semantics are in contracts
`schema/response-profile-v1.schema.json` and `docs/RESPONSE_PROFILE.md`.

Migration 25 adds the profile, receive time and bound host to the authenticated
response channel. Poll validates the strict closed shape, unique allowed/support
lists, subset relationship, UTF-8/Base64 bounds and host enrollment. Credentials
are rechecked inside the transaction. Omitted reports clear previous freshness;
reports expire after 300 seconds or become invalid after a host rebind.

Readiness and preflight distinguish current endpoint-reported mode and permitted
actions from delayed health snapshots. Missing or stale reports remain explicit
unknowns for older agents. Recent policy blocks unsupported/disallowed/off-mode
work, changing actions in dry-run mode and process targets from another boot.
Actual authorization rechecks policy. Dispatch filters blocked commands before
its batch limit, so blocked containment cannot starve permitted investigation.
Withheld commands stay queued and cancellable; a report never establishes OS
execution. Case views show delivery blockers alongside command state.

A signature-requiring report retains ES256 demand even across a later missing
report, and cannot receive stripped delivery without ES256 negotiation. Native
verification and local safety controls remain authoritative. Windows currently
reports its signature-verification limitation explicitly; it does not claim
Linux signing parity. Off-mode agents do not poll; their old report becomes stale.

Upgrade Manager before deploying reporting clients. Older Managers ignore the
additional header and retain native endpoint safety behavior. Console readiness
shows platform, current/stale report, mode, configured actions, boot/signature
requirements, capture/receive facts and blocked-operation reasons without CLI.
Manual/native/full-system E2E remains deferred; focused native unit, API,
contract and existing CI checks qualify this implementation slice.
