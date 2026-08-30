# ADR 003: single worker, sync handlers, events-table-as-queue

- Status: accepted
- Date: 2026-08-30

## Context

`DetectionRun` (`vendor/eyedetect/src/pipeline_core.py`) is built from
stateful engines — `ProcessTree`, `CorrelationEngine`, `ThresholdEngine`,
`EntityRiskScorer`, `C2BeaconDetector` — that accumulate in-process mutable
state across calls (sliding windows, correlation graphs). None of this state
is persisted or shared externally; it lives in whatever Python process
constructed it, and there is no existing multi-process or multi-worker
coordination for it anywhere in the engine.

The originally-cited justification for an events-table claim/lease design —
"this is the pattern `AlertSpool` already implements" — does not hold up:
`AlertSpool.claim_deliverable()` is a stateless `SELECT` with no row mutation
and no lease timeout; its safety comes entirely from at-least-once redelivery
plus `mark_delivered`/`mark_failed` plus dedup-by-`alert_id`. The claim/lease/
revert-on-crash pattern for the `events` table is therefore new engineering,
not a reuse of existing code, and needs its own tests.

## Decision

One `uvicorn` worker. Every handler that touches SQLite is a sync (`def`, not
`async def`) FastAPI handler — `sqlite3` is synchronous, and FastAPI already
runs sync handlers in a threadpool, so a slow write can't stall the event
loop; `aiosqlite` is not added. Detection runs on exactly one dedicated
background thread, the only code path in the process ever allowed to touch
`DetectionRun` — ingest and check-in handlers only ever read/write SQLite,
never call detection directly.

Multiple uvicorn workers were rejected specifically because of the in-process
mutable state above: four workers would mean four partial views of the same
host's activity, and a threshold rule needing 5 events in 60 seconds might see
2 in one worker and 3 in another and never fire. Sharding detection state by
host is the correct answer at real scale; it is unnecessary engineering for a
1–10 agent laptop demo.

The `events` table is the queue: ingest writes rows with
`detect_state='pending'`; the detection thread claims a bounded batch inside
`BEGIN IMMEDIATE ... UPDATE ... SET detect_state='claimed', claimed_at=? ...
COMMIT`, processes each through `OfficerIngestionAdapter.transform_officer_event`
→ `DetectionRun.process_event`, marks each `done` (or `failed`, attempts
incremented, on exception — a rule bug must poison exactly one event, never
the claim loop). On startup, any row still `claimed` with a lease older than
60 seconds reverts to `pending` — new mechanism, gives crash recovery for
free, and must be tested directly rather than assumed correct by analogy to
`AlertSpool`.

SQLite is opened per-thread with `journal_mode=WAL`, `synchronous=NORMAL`,
`busy_timeout=5000`, `foreign_keys=ON` — set once in `manager/db.py`'s
connection factory, never overridden per-call.

## Consequences

- A concurrency test is required before Phase 3 is done: two simulated agents
  posting concurrently while the detection thread claims, asserting no
  `database is locked` errors and no lost or double-processed rows.
- A crash-recovery test is required specifically for the 60-second lease
  revert: kill the process mid-detection, restart, assert claimed rows return
  to `pending` and are reprocessed exactly once (deterministic `alert_id`
  makes this assertable — though its determinism depends on
  `event_id`/`host_id`/`timestamp` being present; officer-sourced events
  always carry `event.id` since the schema requires it).
- Rule-lifecycle changes (Phase 8) rebuild or mutate `RuleEvaluator` inside a
  long-lived `DetectionRun`, and `ProcessTree`/`ThresholdEngine`/etc. hold
  correlation state with no defined behavior on rule swap — Phase 8's plan
  must explicitly decide whether reloading rules resets that state. Not
  resolved by this ADR.
