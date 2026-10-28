# Analyst response operations

29 October 2026 increment. The response engine remains a domain package consumed
in-process by Manager. The closed seven native actions and existing wire formats
are preserved. Requires response-engine commit `e9e15f6` (or its merge descendant).

## Analyst API

All routes use the existing enrolled analyst bearer credential. Agent credentials
and the shared command-creation credential do not grant analyst access.

- `GET /api/v1/response-actions/catalog`: action labels, target kinds, policy tiers
  and disruptive-action metadata. This is not endpoint capability negotiation.
- `POST /api/v1/response-actions`: `{alert_id, action, reason, target?}`. Requires
  an existing alert attached to a live enrolled agent; creates a PENDING action.
  Even collection requests require explicit approval. File actions require exact
  `{path}`. Host actions require `{}`. Process actions derive their exact identity
  from retained alert context/recommendation; omitted target means use that
  identity, not guess a PID. Canonical Windows targets retain decimal uint64 ticks
  and boot binding, and unresolved identities fail closed.
- `POST /api/v1/response-actions/{id}/authorize`: existing approval path. Returns
  actual `authorized` and `lifecycle_state`; a rejected provenance check is never
  described as successful authorization.
- `POST /api/v1/response-actions/{id}/reject`: nonblank `{reason}`.
- `POST /api/v1/response-actions/{id}/cancel`: nonblank `{reason}`; atomically
  cancels an AUTHORIZED command before dispatch. Same-command retries are
  idempotent, with one cancellation audit event. DISPATCHED/ACCEPTED/terminal
  commands return 409. Reject a PENDING recommendation using `/reject` instead.
- `GET /api/v1/response-actions`: supports `state` (recommendation state),
  `host_id`, `alert_id`, `limit` (1–200) and `offset`. Returns `next_offset` when
  another page exists. Ordering is deterministic; live inserts can move pages.

Queue and alert/incident response records include agent/host, manual request
provenance, the exact queued command, command expiry/state, terminal result rows,
immutable V2 receipts (including execution facts) and command audit. The staging
row stays AUTHORIZED after command cancellation/completion; consult
`command_lifecycle_state` for execution progress.

Manual provenance is retained in migration 19 separately from the approver.
Authorization rechecks the endpoint binding and process evidence. Open equivalent
actions are refused with 409 rather than stacking duplicate endpoint operations.
There is no separate four-eyes approver role in this increment: an enrolled analyst
may stage and approve. Console credentials remain server-side and attribute actions
to the configured analyst identity; deploy separate sessions for separate analysts.

## E2E acceptance

1. Start Manager using a **test database** and enroll test Windows/Linux agents
   and an analyst using the existing enrollment mechanism. Run the Console with
   `--manager-url` and server-side `PANOPTICON_MANAGER_TOKEN`.
2. Generate a real detection on an enrolled test endpoint. Open the alert, choose
   **Respond to this alert**, stage collection and approve it. Verify endpoint
   polling, result detail and recorded analyst/agent audit identities.
3. Stage and approve isolation on a disposable test endpoint; cancel before the
   next poll. Both single and durable polling must omit the command. Cancel after
   dispatch must return 409. Release real isolation with the explicit recovery
   action after the test.
4. Verify Windows process actions use retained boot/PID/native creation ticks.
   Try a host-binding change and unresolved process identity: no command dispatch.
5. Inspect a retained V2 process receipt: initiated/completed facts, native error
   and outcome must remain distinct. Late evidence must not rewrite terminal
   state. INDETERMINATE requires investigation, not blind retry of a native action.
6. Exercise queue filters/pages, manual file paths, duplicate refusal and empty/
   unavailable states. Verify secrets never appear in browser responses.

Local API tests exercise real Manager authentication, persistence, staging,
approval, polling and result retention with simulated endpoint receipts. They do
not establish OS execution, privileged isolation, reboot recovery or fleet scale.
No live endpoint action is required to validate these code changes. Run real
destructive acceptance only on enrolled disposable test endpoints.
