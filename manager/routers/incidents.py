"""Analyst view of engine incidents (CONTRACT.md §7).

An incident is written by the detection worker (manager/detection/store.py
``upsert_incident``); the only thing an analyst changes here is its
``status``, which the engine never overwrites. Reads only, plus that one
audited write -- no route here can produce a command.
"""

from __future__ import annotations

import json
from typing import Literal

from fastapi import APIRouter, Header, HTTPException, Query
from pydantic import BaseModel, ConfigDict, Field

from manager import db
from manager.auth import require_analyst_token
from manager.detection.store import set_incident_status
from manager.routers.alerts import ALERT_COLUMNS, alert_row_to_dict
from manager.routers.response_actions import response_actions_for_alerts

router = APIRouter()

IncidentStatus = Literal["open", "investigating", "resolved", "false_positive"]

_SUMMARY = (
    "i.incident_id, i.host_id, i.agent_id, i.status, i.severity, i.level, i.score, "
    "i.confidence, i.tactics_json, i.stage_count, i.root_process, i.root_pid, i.revision, "
    "i.latest_alert_id, i.first_seen, i.last_seen, i.created_at, i.updated_at, "
    "(SELECT COUNT(*) FROM incident_alerts ia WHERE ia.incident_id = i.incident_id) "
    "AS alert_count"
)


class StatusRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    status: IncidentStatus
    note: str | None = Field(default=None, max_length=2000)


def _summary(row) -> dict:
    record = {key: row[key] for key in row.keys() if key != "tactics_json"}
    record["tactics"] = json.loads(row["tactics_json"])
    return record


def _load_summary(conn, incident_id: str):
    return conn.execute(
        f"SELECT {_SUMMARY}, i.incident_json FROM incidents i WHERE i.incident_id = ?",
        (incident_id,),
    ).fetchone()


@router.get("/api/v1/incidents")
async def list_incidents(
    authorization: str | None = Header(default=None),
    status: IncidentStatus | None = None,
    host_id: str | None = Query(default=None, max_length=256),
    limit: int = Query(default=100, ge=1, le=200),
) -> dict:
    require_analyst_token(authorization)
    clauses, params = [], []
    if status is not None:
        clauses.append("i.status = ?")
        params.append(status)
    if host_id is not None:
        clauses.append("i.host_id = ?")
        params.append(host_id)
    where = f"WHERE {' AND '.join(clauses)} " if clauses else ""
    rows = (
        db.connect()
        .execute(
            f"SELECT {_SUMMARY} FROM incidents i {where}"
            "ORDER BY i.last_seen DESC, i.incident_id DESC LIMIT ?",
            (*params, limit),
        )
        .fetchall()
    )
    return {"incidents": [_summary(row) for row in rows]}


@router.get("/api/v1/incidents/{incident_id}")
async def get_incident(incident_id: str, authorization: str | None = Header(default=None)) -> dict:
    require_analyst_token(authorization)
    conn = db.connect()
    row = _load_summary(conn, incident_id)
    if row is None:
        raise HTTPException(status_code=404, detail="no incident with that id")
    incident = _summary(row)
    incident.pop("incident_json", None)
    incident["evidence"] = json.loads(row["incident_json"])

    columns = ", ".join(f"a.{c}" for c in ALERT_COLUMNS)
    member_rows = conn.execute(
        f"SELECT {columns}, ia.role FROM incident_alerts ia "
        "JOIN alerts a ON a.alert_id = ia.alert_id WHERE ia.incident_id = ? "
        "ORDER BY a.alert_timestamp, a.alert_id",
        (incident_id,),
    ).fetchall()
    alerts = []
    for member in member_rows:
        record = alert_row_to_dict(member)
        record["role"] = member["role"]
        alerts.append(record)

    audit = [
        {**dict(a), "detail": json.loads(a["detail"]) if a["detail"] else None}
        for a in conn.execute(
            "SELECT audit_id, event, actor, detail, occurred_at FROM incident_audit "
            "WHERE incident_id = ? ORDER BY occurred_at, rowid",
            (incident_id,),
        ).fetchall()
    ]
    return {
        "incident": incident,
        "alerts": alerts,
        "response_actions": response_actions_for_alerts(conn, [a["alert_id"] for a in alerts]),
        "audit": audit,
    }


@router.post("/api/v1/incidents/{incident_id}/status")
async def update_status(
    incident_id: str, request: StatusRequest, authorization: str | None = Header(default=None)
) -> dict:
    analyst_id = require_analyst_token(authorization)
    conn = db.connect()
    conn.execute("BEGIN IMMEDIATE")
    try:
        found = set_incident_status(
            conn, incident_id, request.status, actor=f"analyst:{analyst_id}", note=request.note
        )
        if not found:
            raise HTTPException(status_code=404, detail="no incident with that id")
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    row = _load_summary(conn, incident_id)
    incident = _summary(row)
    incident.pop("incident_json", None)
    return {"incident": incident}
