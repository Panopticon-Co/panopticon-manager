# ADR 001: vendor eyedetect as a git submodule

- Status: accepted
- Date: 2026-08-30

## Context

`panopticon-manager` was a byte-for-byte fork of `panopticon-detection-engine`
(confirmed: `git diff upstream-detection-engine/main` was empty, same HEAD
commit `39e4100`). It needs to become its own service that reuses the engine's
`DetectionRun`, ingestion normalizers, and reliability primitives
(`spool.py`, `metrics.py`, `health.py`) without re-forking or copy-pasting
source, so that fixes and rule changes in the engine repo don't have to be
manually re-applied in two places.

Alternatives considered: a private package index (no infrastructure exists for
this, and standing one up is out of scope for a one-person semester project); a
git subtree (hides that upstream is a separate, independently-versioned
project, and complicates `docs/VERSIONING.md`'s per-repo tagging); a monorepo
merge (rewrites history across repos this late, at real risk two months before
submission, for no benefit at this scale).

`panopticon-detection-engine` has no packaging metadata (no `setup.py`/
`pyproject.toml` — it's a flat `src/` CLI tool), so an editable pip install
(`-e ./vendor/eyedetect`) is not viable. The manager needs a `sys.path` shim
instead.

## Decision

`panopticon-manager` adds `panopticon-detection-engine` as a git submodule at
`vendor/eyedetect`, pinned to a specific commit (starting at `39e4100`, the
commit both repos shared at fork time). The manager's own `src/`, `rules/`,
`tests/`, `samples/` — the forked copies — are deleted in the same change.

A single module, `manager/vendor_path.py`, inserts `vendor/eyedetect` onto
`sys.path` before any `eyedetect`-originated import, matching the import
spelling the engine already uses internally (`from src.X import Y`, confirmed
in its own `main.py`). Every module that needs engine internals imports
`manager.vendor_path` for its side effect first. `DetectionRun` construction
(the 11-argument engine wiring `main.py` does inline, with no factory of its
own upstream) is **duplicated inside `panopticon-manager`**, in
`manager/detection/factory.py`, rather than added to the engine — this keeps
the submodule strictly read-only from the manager's side, at the cost of
needing to update that one file by hand if the engine's constructor signature
changes.

`docs/VERSIONING.md` gains `panopticon-manager` as a fourth coordinated repo,
tagged `v2.0.0` for this effort, since the default data path moving from file
to network is a breaking change to a published contract under that document's
own MAJOR-bump rule.

## Consequences

- Bumping the engine means one command (`git submodule update --remote
  vendor/eyedetect` + a commit), and the pin makes exactly which engine
  version is running explicit and auditable.
- The manager carries a small, explicit maintenance cost: if
  `DetectionRun.__init__`'s signature changes upstream,
  `manager/detection/factory.py` breaks loudly (an import/constructor error)
  rather than silently drifting.
- CI must check out submodules recursively and install both
  `requirements.txt` files.
- If this pin/shim approach ever causes more than about 30 minutes of
  cumulative CI friction, revisit and consider a subtree instead. Not expected
  at this scale (1–10 agents, one operator).
