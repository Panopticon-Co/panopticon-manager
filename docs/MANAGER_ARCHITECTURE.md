# Manager Architecture

## What this repo is

`panopticon-manager` is the server side of Panopticon's network path: it
receives Officer's telemetry over HTTPS, runs detection, and (from Phase 7
onward) serves a query API to the console. It vendors
`panopticon-detection-engine` ("eyedetect") as a git submodule at
`vendor/eyedetect` rather than forking it — see `docs/adr/001-repo-topology.md`.

## Package layout

```
manager/
  app.py            FastAPI app factory + lifespan (runs migrations at startup)
  config.py         env-var-backed configuration
  db.py             sqlite3 connection factory (one conn/thread, WAL pragmas)
  migrations.py     numbered schema migrations, modeled on eyedetect's spool.py
  vendor_path.py    sys.path shim for `from src.X import Y` imports of eyedetect
  detection/
    factory.py      DetectionRun construction (stub until Phase 3)
  routers/
    health.py       /healthz /readyz /metrics
vendor/eyedetect/    git submodule -> panopticon-detection-engine, pinned
```

## The submodule seam

Anything importing engine internals does `import manager.vendor_path` first
(for its `sys.path` side effect), then `from src.X import Y` — the same
spelling the engine uses for its own internal imports. This is the one place
the manager's code layout is coupled to the submodule's internal structure;
if `vendor/eyedetect` is bumped and imports start failing, look here first.

`manager/detection/factory.py` is the other coupling point: it will duplicate
`vendor/eyedetect/src/main.py`'s ~13-line `DetectionRun` construction (11
required keyword-only stateful engine args, no factory upstream). If that
constructor's signature changes upstream, this file is where it breaks.

## Process model

One `uvicorn` worker, sync handlers, a single dedicated detection thread once
Phase 3 lands. Full reasoning in `docs/adr/003-process-model.md` — in short,
`DetectionRun`'s engines hold in-process mutable correlation state that must
never be touched from more than one worker or thread.

## Data

One SQLite file (`panopticon.db` by default, `PANOPTICON_DB_PATH`
configurable), WAL mode, no ORM. Migrations are an ordered list of functions
in `manager/migrations.py`, applied at startup; never edit an applied
migration; append a new one. As of Phase 0 the only table is
`schema_migrations` itself — `events`, `agents`, `alerts`, etc. arrive in
later phases per `docs/ROADMAP.md`.

## Wire protocol

Not yet implemented (Phase 1). Design is locked in
`docs/adr/002-wire-protocol-ack-semantics.md`; the concrete request/response
shapes will be documented in `docs/API_CONTRACT.md` once the `/api/v1/ingest`
route exists.
