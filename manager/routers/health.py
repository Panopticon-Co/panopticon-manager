"""/healthz, /readyz, /metrics.

Liveness (/healthz) never touches the database — it only asserts the process
is up. Readiness (/readyz) additionally checks the database is reachable and
migrated to the version this build expects, since that's the actual
precondition for serving ingest/query traffic in later phases.

Reuses HealthState and Metrics from the vendored engine (vendor/eyedetect/src/
reliability/{health,metrics}.py) rather than reinventing them — both are
already dependency-free and general-purpose.
"""

from __future__ import annotations

import time

from fastapi import APIRouter, Response

import manager.vendor_path  # noqa: F401  (sys.path side effect, must precede src.* imports)
from manager import db, migrations
from src.reliability.health import HealthState
from src.reliability.metrics import Metrics

router = APIRouter()

health_state = HealthState()
metrics = Metrics()

_EXPECTED_SCHEMA_VERSION = len(migrations._MIGRATIONS)


@router.get("/healthz")
def healthz() -> dict:
    return {"status": "ok", "uptime_seconds": round(time.time() - health_state.started_at, 3)}


@router.get("/readyz")
def readyz(response: Response) -> dict:
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
    return {"status": "ready", "schema_version": version}


@router.get("/metrics")
def metrics_endpoint() -> Response:
    body = metrics.render_prometheus()
    try:
        pending = (
            db.connect()
            .execute("SELECT COUNT(*) AS c FROM events WHERE detect_state = 'pending'")
            .fetchone()["c"]
        )
        body += (
            "\n# HELP panopticon_events_pending Events awaiting detection.\n"
            "# TYPE panopticon_events_pending gauge\n"
            f"panopticon_events_pending {pending}\n"
        )
    except Exception:  # pragma: no cover - metrics must never 500
        pass
    return Response(content=body, media_type="text/plain; version=0.0.4")
