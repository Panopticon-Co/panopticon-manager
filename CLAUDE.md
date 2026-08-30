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

As of Phase 0, this repo is a FastAPI skeleton: health/readiness/metrics
endpoints and a migrations runner, nothing more. The ingest endpoint, auth,
detection worker, and query API arrive in later phases — see
`docs/ROADMAP.md` for the full sequence and what's actually implemented today.

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

- `manager/app.py` — FastAPI app factory + lifespan hook; runs migrations at
  startup before accepting traffic.
- `manager/db.py` — sqlite3 connection factory, one connection per thread,
  WAL/NORMAL/busy_timeout/foreign_keys pragmas. No ORM — matches the style in
  `vendor/eyedetect/src/reliability/spool.py`.
- `manager/migrations.py` — numbered migration functions, modeled on that same
  file's `_migration_1`/`_MIGRATIONS` pattern. Never edit an applied
  migration; append a new one.
- `manager/vendor_path.py` — `sys.path` shim so `from src.X import Y` resolves
  into the vendored engine, matching its own internal import convention.
- `manager/routers/health.py` — `/healthz` (liveness), `/readyz` (DB +
  migration check), `/metrics` (reuses the vendored engine's
  `Metrics.render_prometheus()` and `HealthState`, rather than reinventing
  them).
- `manager/detection/factory.py` — stub; will hold the `DetectionRun` wiring
  duplicated from `vendor/eyedetect/src/main.py` starting Phase 3 (see
  `docs/adr/001-repo-topology.md` for why it's duplicated, not upstreamed).

One SQLite file (`panopticon.db`), one `uvicorn` worker, sync handlers — see
`docs/adr/003-process-model.md` for why (the vendored engine's `DetectionRun`
holds in-process mutable correlation state that must never be touched from
more than one worker/thread).

## Changing the wire protocol or the vendored engine's API

The manager's ingest endpoint (Phase 1+) is a cross-repo API boundary with
`panopticon-agent`'s `schema/event.schema.json` — see
`docs/adr/002-wire-protocol-ack-semantics.md`. Bumping `vendor/eyedetect` to a
new commit is a normal submodule update, but check
`manager/detection/factory.py` and anything importing `src.*` first, since
those are the only places this repo's code depends on the vendored package's
internal shape.

## Remediation stays simulated

The vendored engine's `EndpointRemediationEngine` records `RemediationAction`
dataclasses only — no real `subprocess`/`os.kill`/`winreg`/socket call
anywhere. This applies to the manager too: do not wire any remediation action
to a real system call until a roadmap phase explicitly calls for it.
