"""/healthz, /readyz, /metrics.

Liveness (/healthz) never touches the database — it only asserts the process
is up. Readiness (/readyz) additionally checks the database is reachable and
migrated to the version this build expects, since that's the actual
precondition for serving ingest/query traffic in later phases.

Reuses HealthState and Metrics from the vendored engine (vendor/eyedetect/panopticon_detection/
reliability/{health,metrics}.py) rather than reinventing them — both are
already dependency-free and general-purpose.
"""

from __future__ import annotations

import time

from fastapi import APIRouter, Request, Response

import manager.vendor_path  # noqa: F401  (sys.path side effect, must precede engine imports)
from manager import db, migrations
from panopticon_detection.reliability.health import HealthState
from panopticon_detection.reliability.metrics import Metrics

router = APIRouter()

health_state = HealthState()
metrics = Metrics()

_EXPECTED_SCHEMA_VERSION = len(migrations._MIGRATIONS)


@router.get("/healthz")
def healthz() -> dict:
    return {"status": "ok", "uptime_seconds": round(time.time() - health_state.started_at, 3)}


def worker_health(request: Request) -> dict | None:
    """The detection worker's liveness, or None when no worker runs (app
    built without its lifespan)."""
    worker = getattr(request.app.state, "detection_worker", None)
    return None if worker is None else worker.describe()


@router.get("/readyz")
def readyz(request: Request, response: Response) -> dict:
    try:
        conn = db.connect()
        version = migrations.current_version(conn)
    except Exception as exc:  # pragma: no cover - defensive, exercised via test with bad path
        response.status_code = 503
        return {"status": "not_ready", "reason": str(exc)}

    if version != _EXPECTED_SCHEMA_VERSION:
        response.status_code = 503
        return {
            "status": "not_ready",
            "reason": f"schema at version {version}, expected {_EXPECTED_SCHEMA_VERSION}",
        }
    # Ingest acks before detection runs (ADR 002), so a dead worker is
    # otherwise invisible: events are accepted and no alert ever fires.
    worker = worker_health(request)
    if worker is not None and not worker["alive"]:
        response.status_code = 503
        return {"status": "not_ready", "reason": "detection worker not alive", **worker}
    return {"status": "ready", "schema_version": version}


@router.get("/metrics")
def metrics_endpoint(request: Request) -> Response:
    body = metrics.render_prometheus()
    worker = worker_health(request)
    if worker is not None:
        body += (
            "\n# HELP panopticon_detection_worker_up 1 while the detection worker is alive.\n"
            "# TYPE panopticon_detection_worker_up gauge\n"
            f"panopticon_detection_worker_up {int(worker['alive'])}\n"
        )
    try:
        conn = db.connect()
        pending = conn.execute(
            "SELECT COUNT(*) AS c FROM events WHERE detect_state = 'pending'"
        ).fetchone()["c"]
        body += (
            "\n# HELP panopticon_events_pending Events awaiting detection.\n"
            "# TYPE panopticon_events_pending gauge\n"
            f"panopticon_events_pending {pending}\n"
        )
        # A permanently-failed event (one whose rule evaluation raised) is
        # otherwise invisible outside a direct database query -- the worker
        # never retries or re-queues it (ADR 003: poison exactly one event,
        # never the claim loop), so without this gauge a growing backlog of
        # silently-quarantined events has no operational signal at all.
        failed = conn.execute(
            "SELECT COUNT(*) AS c FROM events WHERE detect_state = 'failed'"
        ).fetchone()["c"]
        body += (
            "\n# HELP panopticon_events_failed Events whose detection permanently failed "
            "(poisoned exactly once, never retried).\n"
            "# TYPE panopticon_events_failed gauge\n"
            f"panopticon_events_failed {failed}\n"
        )
        for state in ("pending", "claimed", "failed"):
            count = conn.execute(
                "SELECT COUNT(*) AS c FROM endpoint_records WHERE detect_state=?", (state,)
            ).fetchone()["c"]
            body += (
                f"\n# HELP panopticon_endpoint_records_{state} "
                f"Canonical records in {state} detection state.\n"
                f"# TYPE panopticon_endpoint_records_{state} gauge\n"
                f"panopticon_endpoint_records_{state} {count}\n"
            )
    except Exception:  # pragma: no cover - metrics must never 500
        pass
    return Response(content=body, media_type="text/plain; version=0.0.4")
