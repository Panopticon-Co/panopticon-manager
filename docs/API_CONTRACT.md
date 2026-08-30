# Manager API Contract

Stub — filled in as each endpoint lands. Currently implemented (Phase 0):

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

---

Not yet implemented: `POST /api/v1/ingest` (Phase 1 — design locked in
`docs/adr/002-wire-protocol-ack-semantics.md`), enrollment/check-in (Phase 4/6),
query endpoints (Phase 7), rule lifecycle (Phase 8).
