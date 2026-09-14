# panopticon-manager

Backend control plane for **Panopticon&Co**, a capstone EDR/XDR research
platform. This is not a commercial product — no production SLA, uptime
guarantee, or compliance certification is claimed anywhere in this repo.

## Status / maturity

Actively developed prototype with a substantial, passing test suite
(138+ tests as of the last verified run: `pytest tests/`). Core telemetry
ingestion, detection, and the response authorization/dispatch/lifecycle/audit
pipeline are implemented and tested, including true end-to-end tests that
exercise the **real** vendored detection engine to produce a real
`KILL_PROCESS` recommendation, dispatch it, and verify PID-reuse protection.
Some response actions remain boundary-level rather than reachable from a real
detection rule today — see [Known limitations](#known-limitations) below.
Not everything on the phase roadmap (`docs/ROADMAP.md`) is built yet; treat
this README as current-state, not aspirational.

## Overview

`panopticon-manager` receives telemetry and enrolls endpoint agents over
authenticated HTTP, runs detection via a vendored copy of the
[`panopticon-detection-engine`](https://github.com/Panopticon-Co/panopticon-detection-engine)
("eyedetect"), automatically translates new detections into typed response
recommendations via a vendored
[`panopticon-response-engine`](https://github.com/Panopticon-Co/panopticon-response-engine),
and owns command authorization, dispatch, lifecycle tracking, and audit for
the closed set of 7 response actions. It is the authorization and dispatch
boundary of the Panopticon pipeline — the point where a detection becomes an
action an endpoint agent will actually execute.

## Architecture role

```
Endpoint Agent(s)  --telemetry-->  panopticon-manager  --query API-->  panopticon-console
 (agent / linux-agent)                   |
                                          |--(vendored) eyedetect        -> detections
                                          |--(vendored) response-engine  -> recommendations
                                          |--authorization/dispatch/lifecycle/audit
                                          v
                                    Endpoint Agent executes command --> result --> audit
```

`panopticon-manager` vendors both the detection engine and the response
engine as pinned **git submodules** (`vendor/eyedetect`,
`vendor/response_engine`) rather than forking or reimplementing them — see
`docs/adr/001-repo-topology.md` and `docs/adr/006-response-engine-package-extraction.md`.
This keeps one deployable backend: no network RPC between Manager and either
vendored engine, no second service, no microservice infrastructure.

## Key capabilities

- **Telemetry ingestion** (`manager/routers/ingest.py`) — bearer-authenticated
  `POST /api/v1/ingest` from enrolled agents.
- **Detection** (`manager/detection/`) — a worker that runs the vendored
  `eyedetect` engine (84 MITRE-mapped rules as of the current pin) against
  ingested events and emits `Alert`s.
- **Response translation and authorization** (`manager/detection/response.py`,
  `manager/routers/response_actions.py`) — new alerts are automatically
  translated into response recommendations via the vendored response engine;
  `AUTO_SAFE` actions dispatch immediately, `ANALYST_APPROVAL` actions
  (including `KILL_PROCESS`, `ISOLATE_HOST`, `RELEASE_HOST_ISOLATION`) queue
  for a human analyst to authorize or reject.
- **Command dispatch and lifecycle** (`manager/routers/commands.py`) — the
  closed 7-action typed command contract
  (`KILL_PROCESS`, `COLLECT_PROCESS_INFO`, `COLLECT_NETWORK_CONNECTIONS`,
  `COLLECT_FILE`, `QUARANTINE_FILE`, `ISOLATE_HOST`,
  `RELEASE_HOST_ISOLATION`), agent poll/accept/result endpoints, expiry
  sweeps, and a full audit trail (`command_audit`).
- **PID-reuse protection** — `KILL_PROCESS`/`COLLECT_PROCESS_INFO` commands
  carry the triggering process's `start_time_ticks`; the Manager never
  re-resolves or refreshes that value after a real detector first observes
  it, so a target that has since been reused under the same PID is provably
  rejected by an honest endpoint rather than silently mis-targeted.
- **Agent/analyst enrollment and auth** (`manager/auth.py`,
  `manager/routers/enrollment.py`) — two distinct identity spaces (agent
  bearer tokens, analyst bearer tokens), tokens stored only as SHA-256
  digests and compared with `hmac.compare_digest`.
- **Query API** (`manager/routers/alerts.py`) — alert listing for the
  console.
- **Operational endpoints** (`manager/routers/health.py`) —
  `/healthz`, `/readyz`, `/metrics`.

## Repository structure

```
manager/
  app.py            FastAPI app factory / router wiring
  auth.py           Agent + analyst token issuance and verification
  config.py         Environment-driven configuration (ManagerConfig)
  db.py             SQLite schema and access
  migrations.py     Migration runner
  detection/        Detection worker, factory, response translation/lifecycle
  routers/          ingest, alerts, enrollment, commands, response_actions, health
  wire/             Wire-contract models shared across routers
docs/
  MANAGER_ARCHITECTURE.md, ROADMAP.md, API_CONTRACT.md, THREAT_MODEL.md,
  VERSIONING.md, RESPONSE_ENGINE_STATE.md, adr/
tests/              138+ tests, including contract and true end-to-end suites
vendor/
  eyedetect/         pinned submodule: panopticon-detection-engine
  response_engine/   pinned submodule: panopticon-response-engine
tools/
```

## Dependencies

- Python 3.10–3.12, FastAPI, Pydantic v2, Uvicorn, httpx, jsonschema (see
  `requirements.txt`).
- `vendor/eyedetect` and `vendor/response_engine`, pinned git submodules with
  their own `requirements.txt` (the response engine is installed editable).
- `ruff` for linting (`pyproject.toml`).

## Install / build / run

```bash
git clone --recurse-submodules https://github.com/Panopticon-Co/panopticon-manager.git
cd panopticon-manager
pip install -r requirements.txt -r vendor/eyedetect/requirements.txt
```

If you already cloned without `--recurse-submodules`:

```bash
git submodule update --init --recursive
```

Run:

```bash
uvicorn manager.app:app --reload
curl localhost:8000/healthz
curl localhost:8000/readyz
curl localhost:8000/metrics
```

## Test

Run tests **scoped to `tests/`**, matching CI's exact invocation — a bare
`pytest` at the repo root will also try to collect the vendored submodules'
own test directories under `vendor/`, which are independent suites with their
own fixtures and will collide:

```bash
pytest -v tests/
ruff check .
```

CI (`.github/workflows/ci.yml`) runs this across Python 3.10, 3.11, and 3.12,
with sibling checkouts of `panopticon-agent` and `panopticon-contracts` for
schema/wire contract tests.

## Configuration

Environment variables (see `manager/config.py`):

| Variable | Default | Purpose |
|---|---|---|
| `PANOPTICON_DB_PATH` | `panopticon.db` | SQLite database file |
| `PANOPTICON_HOST` | `0.0.0.0` | Bind address |
| `PANOPTICON_PORT` | `8000` | Bind port |
| `PANOPTICON_ALERTS_PATH` | `alerts.ndjson` | Alert NDJSON output, read by the console |
| `PANOPTICON_RULES_DIR` | `vendor/eyedetect/rules` | Detection rule set |
| `PANOPTICON_ENROLLMENT_TOKEN` | — | Shared bootstrap secret for agent enrollment |

## API overview

High-level surface only — see `docs/API_CONTRACT.md` for the full contract:

- `POST /api/v1/agents/enroll` — agent enrollment, issues a per-agent bearer
  token.
- `POST /api/v1/ingest` — agent telemetry ingestion (bearer-authenticated).
- `GET /api/v1/alerts` — alert query for the console.
- `POST /api/v1/analysts/enroll` — analyst enrollment.
- `GET /api/v1/response-actions`, `POST .../authorize`, `POST .../reject` —
  analyst review surface (analyst-bearer-authenticated).
- `POST /api/v1/commands` — raw typed-command enqueue (shared command token).
- `GET /api/v1/agents/{agent_id}/commands` (poll),
  `POST .../commands/{command_id}/accept`,
  `POST .../command-results` — agent-facing dispatch surface
  (agent-bearer-authenticated).
- `/healthz`, `/readyz`, `/metrics` — operational endpoints.

## Integration with other Panopticon repos

- [`panopticon-agent`](https://github.com/Panopticon-Co/panopticon-agent) — Windows endpoint agent ("Officer"), telemetry producer and command executor.
- [`panopticon-linux-agent`](https://github.com/Panopticon-Co/panopticon-linux-agent) — Linux endpoint agent, same role.
- [`panopticon-detection-engine`](https://github.com/Panopticon-Co/panopticon-detection-engine) — detection/correlation engine ("eyedetect"), vendored here as `vendor/eyedetect`.
- [`panopticon-response-engine`](https://github.com/Panopticon-Co/panopticon-response-engine) — response translation/lifecycle domain logic, vendored here as `vendor/response_engine`.
- [`panopticon-contracts`](https://github.com/Panopticon-Co/panopticon-contracts) — canonical cross-repo wire contracts (JSON Schema + golden fixtures) for `Command`/`CommandResult`.
- [`panopticon-console`](https://github.com/Panopticon-Co/panopticon-console) — analyst-facing alert viewer, reads this Manager's query API and (optionally) its response-actions queue.
- [Panopticon-Co](https://github.com/Panopticon-Co) — organization home.

## Security considerations

- **Authorization tiers**: `KILL_PROCESS`, `ISOLATE_HOST`, and
  `RELEASE_HOST_ISOLATION` are hard-coded to require analyst approval —
  they never auto-fire regardless of alert severity.
- **PID-reuse protection**: see [Key capabilities](#key-capabilities) above.
- **Identity separation**: agent tokens, analyst tokens, and the shared
  command-enqueue token are three separate identity spaces; none can
  authenticate as another.
- **Audit trail**: every command transition (`created`, `dispatched`,
  `accepted`, `result_received`, expiry) is recorded in `command_audit`.
- **Closed action set**: the 7-action `Literal` and strict per-action target
  schema (`Command.enforce_closed_target_schema`) reject anything outside
  the closed vocabulary; there is no free-form execute path.
- See `docs/THREAT_MODEL.md` for the full threat model and
  `docs/RESPONSE_ENGINE_STATE.md` for the current, detailed adversarial
  verification record.

## Known limitations

Full detail lives in `docs/RESPONSE_ENGINE_STATE.md` — treat this section as
a pointer, not a duplicate:

- `COLLECT_PROCESS_INFO` and `COLLECT_NETWORK_CONNECTIONS` have a working
  mapping from recommendation to typed command, but no shipped detection
  rule in the vendored engine currently emits either recommendation — these
  paths are exercised end-to-end at the boundary (real dispatch/lifecycle),
  not yet from a genuine rule match. `docs/RESPONSE_ENGINE_STATE.md` labels
  this **boundary-level**, distinct from `KILL_PROCESS`'s **true
  production-path** verification.
- Isolation enforcement and isolation-helper robustness/restart behavior are
  verified where the environment allows it (containerized Linux CI), but
  live enforcement against a real, non-loopback network interface and real
  process elevation remain environment-dependent and have not been
  exercised in every environment this project has run in.
- Remediation stays dry-run in spirit at the recommendation layer — the
  closed 7-action set is the only thing an agent can ever be asked to do,
  and destructive actions require analyst approval.

## Contributing / Security / License

- See `CONTRIBUTING.md` for development setup, including submodule-aware
  contribution notes.
- See `SECURITY.md` for vulnerability reporting.
- See `CODE_OF_CONDUCT.md` for community standards.
- Licensed under the [MIT License](LICENSE).

## Status

See `docs/ROADMAP.md` for phase-by-phase status and `docs/RESPONSE_ENGINE_STATE.md`
for the most current, detailed response-pipeline implementation record.
