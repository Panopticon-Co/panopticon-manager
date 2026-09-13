# ADR 004: Response Engine — detection recommends, one shared path authorizes

- Status: accepted
- Date: 2026-09-13

## Context

Before this change, Manager exposed exactly one way to create a dispatchable
command: `POST /api/v1/commands`, gated by a single shared bearer token
(`PANOPTICON_COMMAND_TOKEN`) with no per-caller identity. Nothing connected a
detection alert to a command — an operator (or a script holding the shared
token) had to create one by hand. `vendor/eyedetect`'s `Alert.from_detection_result`
already computes an automated containment recommendation via
`ActiveResponseEngine.resolve_action` (`TERMINATE_PROCESS` /
`ISOLATE_HOST` / `BLOCK_FIREWALL_IP`) and stores it as `alert.active_response`,
but nothing in Manager read that field — the recommendation was inert.

The Linux agent (`panopticon-linux-agent`) implements a closed, typed
7-action command set (`KILL_PROCESS`, `COLLECT_PROCESS_INFO`,
`COLLECT_NETWORK_CONNECTIONS`, `COLLECT_FILE`, `QUARANTINE_FILE`,
`ISOLATE_HOST`, `RELEASE_HOST_ISOLATION`) with no generic/free-form execute
path. Manager's `Command` model already enforces that same closed set and
per-action target schemas. The gap was entirely on the Manager side: nothing
translated an eyedetect recommendation onto that 7-action vocabulary, decided
whether it could fire automatically, or gave an analyst a queue to approve or
reject one.

Locked decisions carried over from the approved implementation plan (not
reopened here):

1. `KILL_PROCESS` always requires analyst approval — never auto-fires from a
   detection, regardless of severity.
2. `ISOLATE_HOST` / `RELEASE_HOST_ISOLATION` always require analyst approval
   (release is never automatable by the same pipeline that triggered
   isolation).
3. `BLOCK_FIREWALL_IP` (an eyedetect recommendation, not an agent action) has
   no dedicated agent-side action — it maps down to `ISOLATE_HOST`. No 8th
   action is added to the closed set.
4. Detection Engine and Console never execute a response directly — the only
   code path that can turn a recommendation into a real command is
   `authorize_and_enqueue()`.

## Decision

**Read the recommendation from the alert, not from a live event.** eyedetect's
`AlertSink.emit(alert)` (`manager/detection/factory.py`) is called with only
the `Alert` dataclass, not the triggering event — by the time an alert exists,
the event that produced it may be long gone from scope. `alert.active_response`
is exactly the recommendation `ActiveResponseEngine.resolve_action` already
computed while the real event was in scope, so
`manager/detection/response.py` reads that field rather than re-deriving
anything or requiring a second copy of the event to be threaded through.
Concretely, `TERMINATE_PROCESS` can never map to `KILL_PROCESS` today, because
`ActiveResponseAction` (`vendor/eyedetect/src/alerting/active_response.py`)
never carries `start_time_ticks`, which the Linux agent's gate requires to
reject PID-reuse. `translate_recommendation()` fails closed in that case —
returns `None`, produces no command — rather than ever guessing a start time.
Closing this gap requires an upstream schema change to eyedetect's event/action
shape, not a Manager-side workaround.

**One staging table, one shared enqueue path.** A new `response_actions` table
(migration 8) holds a row per alert recommendation from the moment it's
translated, independent of whether it can fire immediately or needs approval:
`response_id, alert_id, action, tier, lifecycle_state, target_json, command_id,
created_at, authorized_at, authorized_by, decided_reason`. `tier` is either
`AUTO_SAFE` or `ANALYST_APPROVAL`, decided once by `classify_tier()`:

| Action | Tier | Why |
|---|---|---|
| `COLLECT_PROCESS_INFO` | AUTO_SAFE | read-only |
| `COLLECT_NETWORK_CONNECTIONS` | AUTO_SAFE | read-only |
| `COLLECT_FILE` | ANALYST_APPROVAL | no operator-configured path allowlist exists yet to safely scope an AUTO_SAFE carve-out |
| `QUARANTINE_FILE` | ANALYST_APPROVAL | mutates the endpoint's filesystem |
| `KILL_PROCESS` | ANALYST_APPROVAL | locked decision |
| `ISOLATE_HOST` | ANALYST_APPROVAL | locked decision |
| `RELEASE_HOST_ISOLATION` | ANALYST_APPROVAL | locked decision |

`commands.py`'s existing command-creation logic was extracted, unchanged in
behavior, into `authorize_and_enqueue(conn, command, actor, alert_id=None)` —
the single function that validates the target agent is enrolled, checks
expiry, writes the `commands` row, and audits creation. `POST
/api/v1/commands` (the raw, shared-token-gated endpoint — kept alive for
existing tooling) and the Response Engine's `authorize_response_action()` are
now its only two callers, so they can never drift into different validation
behavior. `commands` gained `alert_id` (nullable FK) and `lifecycle_state`
columns (migration 9) so a dispatched command can be traced back to the alert
and response_action that authorized it, and tracked through
`PENDING → AUTHORIZED → DISPATCHED → ACCEPTED → SUCCEEDED|FAILED|REJECTED`
(set by `poll()` and `submit_result()` respectively, alongside their existing
`command_results`/`command_audit` writes).

**AUTO_SAFE fires immediately; ANALYST_APPROVAL waits for a human.**
`on_alert_created()` — called from `AlertSink.emit` only when `insert_alert`
reports a genuinely new row, never for a replayed/crash-recovered duplicate —
inserts the `response_actions` row and, if its tier is `AUTO_SAFE`, calls
`authorize_response_action()` immediately with `actor="system:response-engine"`.
An `ANALYST_APPROVAL` row is left `PENDING` until a human calls the new
endpoints in `manager/routers/response_actions.py`:

- `GET /api/v1/response-actions` (optional `?state=` filter) — the analyst's
  queue.
- `POST /api/v1/response-actions/{id}/authorize` — turns a `PENDING` row into
  a real command via `authorize_response_action()`.
- `POST /api/v1/response-actions/{id}/reject` — closes a `PENDING` row with a
  reason, no command ever created.
- `POST /api/v1/analysts/enroll` — bootstrap-token-gated (mirrors
  `POST /api/v1/agents/enroll`), issues a per-analyst bearer token stored in
  a new `analyst_credentials` table (migration 10).

All four are gated by `require_analyst_token()`, a distinct identity space
from agent bearer tokens (`enrolled_agents`) and the shared command-creation
token (`PANOPTICON_COMMAND_TOKEN`) — so, unlike the raw endpoint,
`command_audit.actor` finally records a real per-caller identity
(`analyst:<analyst_id>`) for every authorization/rejection decision.

**Transaction ownership follows the caller, not the callee.** `sqlite3` does
not support nested transactions, and `authorize_and_enqueue` is now invoked
from three different transactional contexts: the raw endpoint (its own
top-level request, no ambient transaction), the analyst-authorize/reject
endpoints (which open their own `BEGIN IMMEDIATE` so the command write and the
`response_actions` state change commit atomically), and the automatic
`AUTO_SAFE` path (invoked from inside `manager/detection/worker.py`'s
already-open per-event transaction, so that path's command write, alert
insert, and `events.detect_state='done'` update all commit or roll back
together). `authorize_and_enqueue` therefore checks `conn.in_transaction`
and only opens/commits/rolls back its own transaction when it isn't already
inside one; `authorize_response_action`/`reject_response_action` never manage
transactions themselves at all — every caller is responsible for its own
boundary.

**A Response Engine failure must never discard an alert.** `on_alert_created`
runs inside the detection worker's per-event transaction; an uncaught
exception there would roll back that whole transaction, discarding the alert
that was just durably written — not just the response action. Its entire body
is therefore wrapped in a catch-and-log guard: any unexpected failure means no
`response_actions` row was staged for that alert, logged, but the alert itself
survives. Failures in the automatic-authorization sub-step (e.g.
`authorize_and_enqueue` rejecting because the target agent was since revoked)
are caught specifically and recorded as a `REJECTED` `response_actions` row
with the reason, rather than being swallowed silently or allowed to propagate.

## Consequences

- `TERMINATE_PROCESS → KILL_PROCESS` never fires until eyedetect's active
  response payload carries a PID-reuse-safe process start time. This is a
  known, intentional gap, not an oversight — closing it means changing
  `ActiveResponseAction` upstream, which is out of scope for this ADR.
- `COLLECT_FILE`'s `AUTO_SAFE` path is deliberately never used today (it is
  classified `ANALYST_APPROVAL` unconditionally) until an operator-configured
  path allowlist exists; introducing one is future work, not something to
  fake now.
- `response_actions` and `commands` are only loosely coupled after
  authorization (`response_actions.command_id` points at the `commands` row,
  but each table's `lifecycle_state` is tracked and updated independently) —
  acceptable because the two states answer different questions (has this
  recommendation been decided on vs. has this specific command finished
  executing), but a future dashboard view joining them needs to handle a
  `response_actions` row whose `commands` row has since expired/failed.
- No auto-release TTL exists for `ISOLATE_HOST`/`RELEASE_HOST_ISOLATION` (per
  the locked decision in `panopticon-linux-agent`'s ADR 004) — an
  automatically-authorized isolation is not possible today (`ISOLATE_HOST` is
  always `ANALYST_APPROVAL`), and this ADR does not change that.
