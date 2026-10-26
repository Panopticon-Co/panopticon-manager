"""GET /api/v1/status -- one-call pipeline overview for the console
(CONTRACT.md §7). Counts only; analyst bearer required."""

from __future__ import annotations

from fastapi import APIRouter, Header

from manager import db
from manager.auth import require_analyst_token

router = APIRouter()

_DETECT_STATES = ("pending", "claimed", "done", "failed")
# An incident is "open" until an analyst closes it as resolved/false_positive.
_OPEN_INCIDENT_STATES = ("open", "investigating")


@router.get("/api/v1/status")
async def status(authorization: str | None = Header(default=None)) -> dict:
    require_analyst_token(authorization)
    conn = db.connect()
    events = dict.fromkeys(_DETECT_STATES, 0)
    for row in conn.execute("SELECT detect_state, COUNT(*) AS c FROM events GROUP BY 1"):
        events[row["detect_state"]] = row["c"]
    incidents = {
        row["status"]: row["c"]
        for row in conn.execute("SELECT status, COUNT(*) AS c FROM incidents GROUP BY 1")
    }
    response_actions = {
        row["lifecycle_state"]: row["c"]
        for row in conn.execute(
            "SELECT lifecycle_state, COUNT(*) AS c FROM response_actions GROUP BY 1"
        )
    }
    return {
        "events": events,
        "alerts": conn.execute("SELECT COUNT(*) AS c FROM alerts").fetchone()["c"],
        "incidents_open": sum(incidents.get(s, 0) for s in _OPEN_INCIDENT_STATES),
        "incidents": incidents,
        "response_actions": response_actions,
        "agents_enrolled": conn.execute(
            "SELECT COUNT(*) AS c FROM enrolled_agents WHERE revoked_at IS NULL"
        ).fetchone()["c"],
        "last_event_at": conn.execute(
            "SELECT MAX(event_timestamp) AS t FROM events"
        ).fetchone()["t"],
    }
