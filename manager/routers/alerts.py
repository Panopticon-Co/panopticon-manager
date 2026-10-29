"""Read-only alert query surface for analyst-facing clients (e.g. the
console). Detection Engine and this router never execute anything -- see
manager/detection/response.py for the only path that turns an alert
recommendation into a command. Alerts are also written to alerts.ndjson
(manager/detection/factory.py) for standalone/offline consumption; this
endpoint is the SQLite-backed equivalent for a client that wants to poll
Manager directly instead of tailing a file.

Paging is keyset, newest first, on ``(created_at, alert_id)``: pass the
previous page's ``next_before`` as ``before`` (``"<created_at>,<alert_id>"``).
``next_before`` is null on the last page."""

from __future__ import annotations

import json
from typing import Literal

from fastapi import APIRouter, Header, HTTPException, Query

from manager import db
from manager.auth import require_analyst_token
from manager.routers.response_actions import response_actions_for_alerts

router = APIRouter()

ALERT_COLUMNS = (
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
    "detection_source",
    "incident_id",
    "alert_json",
)

MAX_LIMIT = 200


def alert_row_to_dict(row) -> dict:
    record = {key: row[key] for key in ALERT_COLUMNS}
    record["alert"] = json.loads(record.pop("alert_json"))
    return record


def _parse_before(before: str) -> tuple[str, str]:
    created_at, sep, alert_id = before.partition(",")
    if not sep or not created_at or not alert_id:
        raise HTTPException(
            status_code=422, detail="before must be '<created_at>,<alert_id>' from next_before"
        )
    return created_at, alert_id


@router.get("/api/v1/alerts")
async def list_alerts(
    authorization: str | None = Header(default=None),
    host_id: str | None = Query(default=None, max_length=256),
    severity: Literal["low", "medium", "high", "critical"] | None = None,
    rule_id: str | None = Query(default=None, max_length=128),
    source: Literal["rule", "stateful", "behavioral", "correlation"] | None = None,
    incident_id: str | None = Query(default=None, max_length=128),
    before: str | None = Query(default=None, max_length=512),
    limit: int = Query(default=MAX_LIMIT, ge=1, le=MAX_LIMIT),
) -> dict:
    require_analyst_token(authorization)
    clauses: list[str] = []
    params: list = []
    for column, value in (
        ("host_id", host_id),
        ("severity", severity),
        ("rule_id", rule_id),
        ("detection_source", source),
        ("incident_id", incident_id),
    ):
        if value is not None:
            clauses.append(f"{column} = ?")
            params.append(value)
    if before is not None:
        created_at, alert_id = _parse_before(before)
        clauses.append("(created_at < ? OR (created_at = ? AND alert_id < ?))")
        params.extend([created_at, created_at, alert_id])
    where = f"WHERE {' AND '.join(clauses)} " if clauses else ""
    rows = (
        db.connect()
        .execute(
            f"SELECT {', '.join(ALERT_COLUMNS)} FROM alerts {where}"
            "ORDER BY created_at DESC, alert_id DESC LIMIT ?",
            (*params, limit),
        )
        .fetchall()
    )
    next_before = None
    if len(rows) == limit:
        next_before = f"{rows[-1]['created_at']},{rows[-1]['alert_id']}"
    return {"alerts": [alert_row_to_dict(row) for row in rows], "next_before": next_before}


@router.get("/api/v1/alerts/{alert_id}")
async def get_alert(alert_id: str, authorization: str | None = Header(default=None)) -> dict:
    analyst_id = require_analyst_token(authorization)
    conn = db.connect()
    row = conn.execute(
        f"SELECT {', '.join(ALERT_COLUMNS)} FROM alerts WHERE alert_id = ?", (alert_id,)
    ).fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail="no alert with that id")
    return {
        "alert": alert_row_to_dict(row),
        "response_actions": response_actions_for_alerts(conn, [alert_id], analyst_id=analyst_id),
    }
