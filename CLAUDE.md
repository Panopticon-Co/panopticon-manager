# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project overview

`panopticon-manager` is the network/server side of the Panopticon EDR/XDR
platform (a separate polyrepo project — see the workspace-root `../CLAUDE.md`).
It receives Officer's (`panopticon-agent`) telemetry over authenticated HTTPS,
persists it, runs detection, and serves a query API to the console. It is
**not** a fork of `panopticon-detection-engine` — it vendors that project as a
pinned git submodule at `vendor/eyedetect` and depends on it read-only. See
`docs/adr/001-repo-topology.md` for why, and `docs/MANAGER_ARCHITECTURE.md`
for the current package layout.

The manager is past its Phase 0 skeleton: authenticated ingest, agent and
analyst enrollment, the detection worker, incident persistence, the response
engine staging/approval path, the closed command queue, and the analyst query
API all exist and are tested. The cross-repo capstone contract is
`vendor/eyedetect/docs/integration/CONTRACT.md` (sections 5-7 are this repo's
part). `docs/ROADMAP.md` predates much of this.

## Setup / Build

```bash
git submodule update --init
pip install -r requirements.txt -r vendor/eyedetect/requirements.txt
```

Dependencies: `fastapi`, `uvicorn[standard]`, `httpx` (tests), `ruff` (lint) —
plus whatever `vendor/eyedetect/requirements.txt` needs (`pyyaml`, `pydantic`,
`pytest`) for the vendored engine. New dependencies beyond this budget need a
written line of justification, per the workspace-root design brief.

## Test

```bash
pytest -v tests/
ruff check .
```

## Run

```bash
uvicorn manager.app:app --reload
curl localhost:8000/healthz
curl localhost:8000/readyz
curl localhost:8000/metrics
```

Config is environment-variable-backed (`manager/config.py`):
`PANOPTICON_DB_PATH` (default `panopticon.db`), `PANOPTICON_HOST` (default
`0.0.0.0`), `PANOPTICON_PORT` (default `8000`).

## Architecture

- `manager/app.py` — FastAPI app + lifespan: runs migrations, starts the one
  detection worker thread, registers the routers.
- `manager/db.py` — sqlite3 connection factory, one connection per thread,
  WAL/NORMAL/busy_timeout/foreign_keys pragmas. No ORM.
- `manager/migrations.py` — numbered `_migration_N` functions (12 so far).
  Never edit an applied migration; append a new one.
- `manager/vendor_path.py` — `sys.path` shim so `panopticon_detection.*`
  resolves into `vendor/eyedetect`.
- `manager/wire/` — pydantic mirror of the agent's `event.schema.json`
  (0.1–0.4, `extra="forbid"`) and the ingest response shape.
- `manager/detection/worker.py` — the single detection thread (ADR 003):
  claims `events` rows (`detect_state`), normalizes with the engine's
  `OfficerIngestionAdapter`, runs `DetectionRun.process_event` inside one
  `BEGIN IMMEDIATE` per event, prunes on load or idle.
- `manager/detection/factory.py` — wraps the engine's own
  `panopticon_detection.factory.build_detection_run`; `AlertSink.emit` stores
  each alert, upserts incidents, appends `alerts.ndjson`, stages responses.
- `manager/detection/store.py` — all detection writes: `alerts`, `incidents`
  (revision only moves forward; analyst `status` never overwritten),
  `incident_alerts`, `incident_audit`, analyst status changes.
- `manager/detection/response.py` — recommendation → closed command
  (`vendor/response_engine` translation + tiers), policy (behavioral
  disruptive = record only; no duplicate open action per host+action+target),
  15-min PENDING expiry, authorization via `routers/commands.py`.
- `manager/routers/` — `ingest`, `enrollment`, `commands` (agent poll/accept/
  result), `response_actions` (analyst authorize/reject), `alerts`,
  `incidents`, `status`, `health`. Analyst routes use
  `auth.require_analyst_token`.

One SQLite file, one `uvicorn` worker, one detection thread — see
`docs/adr/003-process-model.md` (the engine's `DetectionRun` holds in-process
state that must never be touched from more than one thread). Demo:
`docs/DEMO.md` "Capstone demo (current)"; end-to-end test:
`tests/test_capstone_e2e.py`.

## Changing the wire protocol or the vendored engine's API

The manager's ingest endpoint is a cross-repo API boundary with
`panopticon-agent`'s `schema/event.schema.json` — see
`docs/adr/002-wire-protocol-ack-semantics.md`. Bumping `vendor/eyedetect` to a
new commit is a normal submodule update, but check
`manager/detection/factory.py` and anything importing `panopticon_detection.*` first, since
those are the only places this repo's code depends on the vendored package's
internal shape.

## Remediation stays simulated

Neither the engine nor the manager executes a response: the engine emits a
recommendation, the manager stages it as a closed-vocabulary command, and only
an agent acts on it. No `subprocess`/`os.kill`/`winreg`/socket call to act on a
host belongs anywhere in this repo. `start_time_ticks` is an opaque
pass-through token — never derive or default it; missing means fail closed.
