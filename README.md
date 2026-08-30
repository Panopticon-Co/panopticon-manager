# panopticon-manager

The network/server side of Panopticon, a capstone EDR/XDR platform. Receives
telemetry from the [`panopticon-agent`](https://github.com/Panopticon-Co/panopticon-agent)
("Officer") Windows endpoint agent over authenticated HTTPS, runs detection
via the vendored [`panopticon-detection-engine`](https://github.com/Panopticon-Co/panopticon-detection-engine)
("eyedetect"), and serves a query API to the [`panopticon-console`](https://github.com/Panopticon-Co/panopticon-console).

> This is a research/capstone project, not a commercial product. As of Phase 0
> this repo is a FastAPI skeleton — health/readiness/metrics endpoints and a
> migrations runner. See `docs/ROADMAP.md` for what's implemented and what's
> still to come.

## Setup

```bash
git clone --recurse-submodules https://github.com/Panopticon-Co/panopticon-manager.git
cd panopticon-manager
pip install -r requirements.txt -r vendor/eyedetect/requirements.txt
```

If you already cloned without `--recurse-submodules`:

```bash
git submodule update --init
```

## Run

```bash
uvicorn manager.app:app --reload
curl localhost:8000/healthz
curl localhost:8000/readyz
curl localhost:8000/metrics
```

## Test

```bash
pytest -v tests/
ruff check .
```

## Architecture

`panopticon-manager` vendors `panopticon-detection-engine` as a pinned git
submodule at `vendor/eyedetect` rather than forking it — see
`docs/adr/001-repo-topology.md`. Full architecture notes:
`docs/MANAGER_ARCHITECTURE.md`. Design decisions and their rationale:
`docs/adr/`. Phase-by-phase plan: `docs/ROADMAP.md`.

## License

MIT.
