# ADR 002: wire protocol and ack semantics

- Status: accepted
- Date: 2026-08-30

## Context

Officer has no network code today. It serializes events via `serialize_event()`
— a one-line compact-JSON NDJSON row per event, covering all five telemetry
families defined in `schema/event.schema.json` (process, network, file,
registry, image_load), even though only process-category telemetry has been
captured live so far. The manager needs to accept exactly these bytes over
HTTP, and both sides need at-least-once delivery to survive a manager restart
without losing endpoint telemetry.

`panopticon-agent/docs/architecture/detection-ingestion-boundary.md` requires
that invalid data get an actionable per-event result rather than silent
coercion, and that ETW/Sysmon views of the same process not be collapsed as
duplicates. That second constraint is about **process identity reconciliation**
(grouping by `host.id + process.entity_id`, Phase 6/7 scope) — a separate
problem from **event delivery idempotency**, which is what this ADR's
`event_id`-based dedup solves.

## Decision

Transport is `POST /api/v1/ingest`, body = the agent's own NDJSON, one event
per line, `Content-Type: application/x-ndjson`, headers
`X-Panopticon-Batch-Id` (UUIDv4, stable across retries), `X-Panopticon-Agent-Id`,
`X-Panopticon-Protocol: 1`. No second serializer is ever written — the same
`serialize_event()` output that goes to stdout today goes on the wire.

Limits: ≤ 1000 events or ≤ 8 MiB per batch. No compression in this phase.

**The manager acks (`200`) once raw events are durably committed to SQLite,
strictly before detection runs.** Detection is downstream and asynchronous; if
ack depended on rule evaluation, one slow correlation rule would stall ingest
for every agent, and a detection bug would show up as endpoint disk
exhaustion instead of a queue-depth metric.

Idempotency, two independent layers:

1. `event_id PRIMARY KEY` on `events` → `INSERT OR IGNORE`. `event.id` is
   already a deterministic `evt_<sha256>` assigned by the agent, so a replayed
   event collapses onto itself for free.
2. `X-Panopticon-Batch-Id` stored in a `batches` table with the response
   returned for it; a repeated batch id returns the stored response without
   reprocessing (TTL 24h). Deferred to **Phase 5** (durable agent spool/retry)
   — Phase 1's tracer bullet has no agent-side retry yet, so there's nothing
   to replay against.

Response is per-event: `{batch_id, received, accepted, duplicates,
rejected: [{line, event_id, reason, detail}], server_time,
min_next_interval_ms}`. A batch with some malformed lines is `200` with those
lines listed in `rejected[]`. Only framing-level failures reject the whole
request: `401`/`403` (Phase 4+), `413` oversize, `422` not NDJSON, `429`
backpressure (Phase 5+), `503` shutting down.

Clock skew: the manager stamps `ingested_at` server-side; `event.timestamp` is
never modified. If `|event.timestamp − now| > 24h`, the event is still
accepted with a `clock_skew` flag and a metric — a wrong clock must never cost
telemetry.

Ordering: per-agent order is the agent's responsibility (Phase 5+). Cross-agent
order is not guaranteed; the detection worker (Phase 3) claims pending events
ordered by `(event_timestamp, event_id)`.

The Pydantic wire mirror models all five telemetry families from Phase 1
onward, matching the schema file's structure exactly.
`schema_version` is accepted as `Literal["0.1","0.2","0.3"]`, matching
`OfficerIngestionAdapter.SUPPORTED_SCHEMA_VERSIONS` — intentionally broader
than the schema file's own current `enum: ["0.2","0.3"]`, for legacy
compatibility. `model_config = ConfigDict(extra="forbid")` mirrors the
schema's `additionalProperties: false` throughout.

## Consequences

- Ack-before-detect means "the manager is up" and "detection is caught up" are
  two different, independently observable facts.
- The two-layer idempotency scheme means Phase 1 ships with only layer 1;
  layer 2 arrives in Phase 5 without changing the wire format — the
  `X-Panopticon-Batch-Id` header is present from Phase 1 even though it isn't
  enforced until Phase 5.
- Modeling all five families from Phase 1 means the schema contract test is
  complete from the start, rather than needing a second pass when V3
  telemetry is finally captured live.
