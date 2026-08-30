# Panopticon Manager — Phase Roadmap

Each phase is one PR, leaves `main` green, and ends in something demoable.
Order is chosen so the riskiest unknown dies first. Full design context lives
in the workspace-root `MANAGER_INGESTION_PLANNING_PROMPT.md` and this repo's
`docs/adr/`.

Note on numbering: this table is this project's own phase sequence for the
manager + agent delivery work. It is **not** the same numbering as
`panopticon-agent/docs/roadmap.md`'s own phases — this project's agent-side
work corresponds to that document's Phases 6 ("durable spool", though its
SQLite proposal is superseded here by a flat-file segment spool) and 7
("secure delivery and configuration"), not its Phase 3 (which is unrelated
in-process queue/backpressure work).

| # | Phase | Demo at the end |
|---|---|---|
| **0** | De-fork the manager; FastAPI skeleton; config; migrations runner; `/healthz` `/readyz` `/metrics`; CI | `uvicorn` boots, health is green, CI passes on 3.10–3.12 |
| **1** | **Tracer bullet.** Unauthenticated `POST /api/v1/ingest` on localhost persisting raw events; C++ `officer-delivery` minimum: buffer → WinHTTP POST → drop on 200. No spool, no auth, no detection | Agent on the Windows VM → manager on the Mac → rows in SQLite |
| **2** | Fake agent + load harness: replays sample NDJSON as M agents at N events/sec, with failure injection | `python tools/fake_agent.py --agents 5 --eps 200` and a latency/throughput table |
| **3** | Detection worker: events-table-as-queue, claim loop, `DetectionRun`, alerts table, `alerts.ndjson` retained | Spawn `powershell` from Word on the VM → alert visible in the console within seconds |
| **4** | Enrollment, agent keys, DPAPI identity storage, bearer auth, `401` re-enrol path, revocation | Enrol a fresh VM from zero; revoke it; ingest starts failing with `401` |
| **5** | Durable agent spool, retry/backoff, `429` backpressure, quota + drop counters, batch idempotency | Kill the manager for 10 minutes with the agent running, restart it, zero events lost |
| **6** | Check-in, agent registry, states, config revisions and distribution | Change collection config centrally; the VM picks it up on the next check-in |
| **7** | Query API (filters, cursor pagination, alert detail with evidence), console cutover to `--api-url` | Console reads live from the manager; alert detail shows the process tree |
| **8** | Rule lifecycle API (upload/validate/version/activate/rollback), TLS pinning hardening, `THREAT_MODEL.md`, load results, docs, `v2.0.0` coordinated tag | Upload a new YAML rule via the API, watch it fire without restarting anything |

**Phases 0–3 are the minimum viable pipeline.** If everything after Phase 5
slipped, the project is still a complete, defensible EDR with network
delivery.

## Status

- Phase 0: in progress (this repo's `manager/` package, migrations runner,
  health endpoints, and CI landed in this change; de-fork complete).
