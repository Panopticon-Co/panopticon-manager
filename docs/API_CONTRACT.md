# Manager API Contract

Reflects what is actually implemented as of 2026-09-13. See `docs/adr/` for the
design rationale behind each subsystem.

## `GET /healthz`

Liveness only, never touches the database.

```json
{"status": "ok", "uptime_seconds": 12.345}
```

## `GET /readyz`

Checks the database is reachable and migrated to the version this build
expects. Returns `503` if not.

```json
{"status": "ready", "schema_version": 1}
```

## `GET /metrics`

Prometheus text exposition format (`Content-Type: text/plain; version=0.0.4`),
rendered by the vendored engine's `Metrics.render_prometheus()`.

## `POST /api/v1/agents/enroll`

Body `{agent_id, host_id}`, header `X-Panopticon-Enrollment-Token` (a single
shared bootstrap secret, `PANOPTICON_ENROLLMENT_TOKEN`). Returns a bearer
token (`access_token`) once; only its SHA-256 digest is stored. Re-enrolling
an `agent_id` overwrites its token/host binding — see
`docs/adr/002-wire-protocol-ack-semantics.md` and `manager/auth.py`.

## `POST /api/v1/ingest`

NDJSON telemetry batch ingest, headers `X-Panopticon-Batch-Id`,
`X-Panopticon-Agent-Id`, `X-Panopticon-Protocol: 1`. Accepts Schema
0.1–0.4 events (0.4 is additive Linux procfs telemetry and requires a
bearer token; 0.1–0.3 Windows ingest does not yet). Bounded to 1000
events / 8MiB per batch. Dedupes by `event_id` (`INSERT OR IGNORE`);
malformed lines are individually rejected without failing the batch.
Design: `docs/adr/002-wire-protocol-ack-semantics.md`,
`docs/LINUX_TELEMETRY_SCHEMA_0_4.md`.

## `POST /api/v1/commands`

Closed, typed command creation. Header `X-Panopticon-Command-Token` (a
single shared secret, `PANOPTICON_COMMAND_TOKEN` — this endpoint has no
per-caller identity yet; see the "known gaps" note below). Body is one of
the 7 closed actions (`KILL_PROCESS`, `COLLECT_PROCESS_INFO`,
`COLLECT_NETWORK_CONNECTIONS`, `COLLECT_FILE`, `QUARANTINE_FILE`,
`ISOLATE_HOST`, `RELEASE_HOST_ISOLATION`) with a per-action target schema
enforced by `Command.enforce_closed_target_schema`. Rejects an
already-expired `expires_at` (422), a target agent that isn't enrolled
(422), and a duplicate `command_id` (409). `manager/routers/commands.py`.

## `GET /api/v1/agents/{agent_id}/commands`

Agent poll, `Authorization: Bearer <token>`. Atomically claims and marks
`delivered_at` on up to 32 undelivered, unexpired commands so a delivered
command is never re-polled. Strictly agent-scoped — a token only ever
sees its own `agent_id`'s queue.

## `POST /api/v1/agents/{agent_id}/command-results`

Typed result submission, same bearer auth. Rejects a result for a
command that doesn't belong to the submitting agent (422), an expired
command (422), and a `correlation_id` mismatch (422). Idempotent on
`result_id` (`INSERT OR IGNORE`).

---

**Known gaps** (tracked for the Response Engine work): command creation
has no per-caller identity — every caller shares one static token,
recorded in `command_audit` only as `system:command-token`. Nothing yet
connects a detection/alert to command creation; that link, plus
analyst authorization, is designed but not implemented. Query endpoints
for alerts/response state, and rule lifecycle management, remain
unimplemented.
