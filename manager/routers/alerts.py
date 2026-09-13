"""Read-only alert query surface for analyst-facing clients (e.g. the
console). Detection Engine and this router never execute anything -- see
manager/detection/response.py for the only path that turns an alert
recommendation into a command. Alerts are also written to alerts.ndjson
(manager/detection/factory.py) for standalone/offline consumption; this
endpoint is the SQLite-backed equivalent for a client that wants to poll
Manager directly instead of tailing a file."""

from __future__ import annotations

import json

from fastapi import APIRouter, Header

from manager import db
from manager.auth import require_analyst_token

router = APIRouter()

_COLUMNS = (
    "alert_id",
    "rule_id",
    "level",
    "severity",
    "host_id",
    "agent_id",
    "event_id",
    "alert_timestamp",
    "created_at",
    "mitre_tactic",
    "mitre_technique",
    "alert_json",
)


def _row_to_dict(row) -> dict:
    record = {key: row[key] for key in _COLUMNS}
    record["alert"] = json.loads(record.pop("alert_json"))
    return record


@router.get("/api/v1/alerts")
async def list_alerts(
    authorization: str | None = Header(default=None),
    host_id: str | None = None,
    limit: int = 200,
) -> dict:
    require_analyst_token(authorization)
    bounded_limit = max(1, min(limit, 200))
    conn = db.connect()
    if host_id is not None:
        rows = conn.execute(
            f"SELECT {', '.join(_COLUMNS)} FROM alerts WHERE host_id = ? "
            "ORDER BY created_at DESC, alert_id DESC LIMIT ?",
            (host_id, bounded_limit),
        ).fetchall()
    else:
        rows = conn.execute(
            f"SELECT {', '.join(_COLUMNS)} FROM alerts "
            "ORDER BY created_at DESC, alert_id DESC LIMIT ?",
            (bounded_limit,),
        ).fetchall()
    return {"alerts": [_row_to_dict(row) for row in rows]}
