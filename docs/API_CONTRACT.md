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

**Deprecated** in favor of the Response Engine flow below — kept alive for
existing tooling and tests, not for new integrations. Closed, typed command
creation. Header `X-Panopticon-Command-Token` (a single shared secret,
`PANOPTICON_COMMAND_TOKEN` — this endpoint has no per-caller identity;
`command_audit` records its actor only as `system:command-token`). Body is
one of the 7 closed actions (`KILL_PROCESS`, `COLLECT_PROCESS_INFO`,
`COLLECT_NETWORK_CONNECTIONS`, `COLLECT_FILE`, `QUARANTINE_FILE`,
`ISOLATE_HOST`, `RELEASE_HOST_ISOLATION`) with a per-action target schema
enforced by `Command.enforce_closed_target_schema`. Rejects an
already-expired `expires_at` (422), a target agent that isn't enrolled
(422), and a duplicate `command_id` (409). Shares its validation/write path
(`authorize_and_enqueue`) with the Response Engine's authorize endpoint
below — see `manager/routers/commands.py`.

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

## `POST /api/v1/analysts/enroll`

Body `{analyst_id}`, header `X-Panopticon-Analyst-Enrollment-Token` (a
single shared bootstrap secret, `PANOPTICON_ANALYST_ENROLLMENT_TOKEN`,
distinct from the agent enrollment token). Returns a bearer token once;
only its SHA-256 digest is stored in `analyst_credentials`. Mirrors
`POST /api/v1/agents/enroll`'s pattern — see `manager/auth.py`.

## `GET /api/v1/response-actions`

Analyst-gated (`Authorization: Bearer <analyst token>`), optional
`?state=` filter (e.g. `PENDING`, `AUTHORIZED`, `REJECTED`). Lists up to
200 most-recent `response_actions` rows — the queue the Response Engine
stages from detections. See `docs/adr/004-response-engine.md`.

## `POST /api/v1/response-actions/{response_id}/authorize`

Analyst-gated. Turns a `PENDING` response action into a real, dispatchable
command via the same `authorize_and_enqueue` path the raw command endpoint
uses, recording the authenticated analyst as the actor. `404` if the id
doesn't exist or is no longer `PENDING` (already decided).

## `POST /api/v1/response-actions/{response_id}/reject`

Analyst-gated, body `{reason}`. Closes a `PENDING` response action with a
reason and no command is ever created. `404` under the same conditions as
authorize.

---

**Response Engine** (`manager/detection/response.py`,
`docs/adr/004-response-engine.md`): every alert's `active_response`
recommendation (computed upstream by eyedetect) is translated onto the
closed 7-action set and staged as a `response_actions` row. `AUTO_SAFE`
actions (`COLLECT_PROCESS_INFO`, `COLLECT_NETWORK_CONNECTIONS`) enqueue
immediately; everything else (`KILL_PROCESS`, `ISOLATE_HOST`,
`RELEASE_HOST_ISOLATION`, `COLLECT_FILE`, `QUARANTINE_FILE`) always
requires the analyst endpoints above. `TERMINATE_PROCESS → KILL_PROCESS`
never fires today — eyedetect's active-response payload carries no
PID-reuse-safe start time, so it fails closed rather than guessing.

**Known gaps**: rule lifecycle management remains unimplemented. Console
still reads `alerts.ndjson` directly rather than these query endpoints
(tracked separately, Phase 5).
