"""Analyst-facing view and authorization surface for the Response Engine.

response_actions rows are staged by manager/detection/response.py the moment
an alert recommends one of the closed 7 actions -- this router is how a human
analyst sees that queue and turns a PENDING row into a real dispatchable
command (authorize) or closes it out without one (reject). Gated by
require_analyst_token, a distinct identity space from agent bearer tokens and
the shared command-creation token, so command_audit finally records a real
per-caller actor for these decisions.
"""

from __future__ import annotations

import json
import sqlite3
from typing import Literal

from fastapi import APIRouter, Header, HTTPException
from pydantic import BaseModel, ConfigDict, Field

from manager import db
from manager.auth import enroll_analyst, require_analyst_token
from manager.detection.response import (
    authorize_response_action,
    expire_stale_response_actions,
    reject_response_action,
)

router = APIRouter()

_COLUMNS = (
    "response_id",
    "alert_id",
    "action",
    "tier",
    "lifecycle_state",
    "target_json",
    "command_id",
    "created_at",
    "authorized_at",
    "authorized_by",
    "decided_reason",
)


class AnalystEnrollmentRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    analyst_id: str = Field(min_length=1, max_length=128)


class AnalystEnrollmentResponse(BaseModel):
    analyst_id: str
    access_token: str
    token_type: str = "Bearer"


class RejectRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    reason: str = Field(min_length=1, max_length=512)


_SELECT_PENDING = (
    "SELECT response_id FROM response_actions "
    "WHERE response_id = ? AND lifecycle_state = 'PENDING'"
)


ResponseActionState = Literal["PENDING", "AUTHORIZED", "REJECTED", "EXPIRED"]

_SELECT = (
    f"SELECT {', '.join('ra.' + c for c in _COLUMNS)}, "
    "c.lifecycle_state AS command_lifecycle_state "
    "FROM response_actions ra LEFT JOIN commands c ON c.command_id = ra.command_id"
)


def _row_to_dict(row) -> dict:
    record = {key: row[key] for key in _COLUMNS}
    record["target"] = json.loads(record.pop("target_json"))
    return record


def _with_command_audit(conn: sqlite3.Connection, rows) -> list[dict]:
    """Serialize response_actions rows (selected with ``_SELECT``), adding the
    linked command's ``command_lifecycle_state`` and its ``command_audit``
    rows as ``audit`` (empty for an action that never produced a command)."""
    out = []
    for row in rows:
        record = _row_to_dict(row)
        record["command_lifecycle_state"] = row["command_lifecycle_state"]
        record["audit"] = []
        if row["command_id"] is not None:
            record["audit"] = [
                dict(a)
                for a in conn.execute(
                    "SELECT audit_id, event, actor, detail, occurred_at FROM command_audit "
                    "WHERE command_id = ? ORDER BY occurred_at, rowid",
                    (row["command_id"],),
                ).fetchall()
            ]
        out.append(record)
    return out


def expire_pending(conn: sqlite3.Connection) -> None:
    """Run the lazy PENDING -> EXPIRED sweep in its own short transaction, so
    every read shows current lifecycle states."""
    conn.execute("BEGIN IMMEDIATE")
    try:
        expire_stale_response_actions(conn)
        conn.commit()
    except Exception:
        conn.rollback()
        raise


def response_actions_for_alerts(conn: sqlite3.Connection, alert_ids: list[str]) -> list[dict]:
    """Response actions (with command lifecycle and audit) for these alerts,
    oldest first. Used by the alert and incident detail routes."""
    if not alert_ids:
        return []
    expire_pending(conn)
    placeholders = ", ".join("?" for _ in alert_ids)
    rows = conn.execute(
        f"{_SELECT} WHERE ra.alert_id IN ({placeholders}) ORDER BY ra.created_at, ra.response_id",
        tuple(alert_ids),
    ).fetchall()
    return _with_command_audit(conn, rows)


@router.post("/api/v1/analysts/enroll", response_model=AnalystEnrollmentResponse)
async def enroll(
    request: AnalystEnrollmentRequest, x_panopticon_analyst_enrollment_token: str = Header(...)
) -> AnalystEnrollmentResponse:
    token = enroll_analyst(request.analyst_id, x_panopticon_analyst_enrollment_token)
    return AnalystEnrollmentResponse(analyst_id=request.analyst_id, access_token=token)


@router.get("/api/v1/response-actions")
async def list_response_actions(
    authorization: str | None = Header(default=None),
    state: ResponseActionState | None = None,
) -> dict:
    require_analyst_token(authorization)
    conn = db.connect()
    expire_pending(conn)
    if state is not None:
        rows = conn.execute(
            f"{_SELECT} WHERE ra.lifecycle_state = ? ORDER BY ra.created_at DESC LIMIT 200",
            (state,),
        ).fetchall()
    else:
        rows = conn.execute(f"{_SELECT} ORDER BY ra.created_at DESC LIMIT 200").fetchall()
    return {"response_actions": _with_command_audit(conn, rows)}


@router.post("/api/v1/response-actions/{response_id}/authorize")
async def authorize(response_id: str, authorization: str | None = Header(default=None)) -> dict:
    analyst_id = require_analyst_token(authorization)
    conn = db.connect()
    conn.execute("BEGIN IMMEDIATE")
    try:
        expire_stale_response_actions(conn)
        row = conn.execute(_SELECT_PENDING, (response_id,)).fetchone()
        if row is None:
            raise HTTPException(status_code=404, detail="no pending response action with that id")
        authorize_response_action(conn, response_id, actor=f"analyst:{analyst_id}")
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    return {"response_id": response_id, "authorized": True}


@router.post("/api/v1/response-actions/{response_id}/reject")
async def reject(
    response_id: str, request: RejectRequest, authorization: str | None = Header(default=None)
) -> dict:
    analyst_id = require_analyst_token(authorization)
    conn = db.connect()
    conn.execute("BEGIN IMMEDIATE")
    try:
        expire_stale_response_actions(conn)
        row = conn.execute(_SELECT_PENDING, (response_id,)).fetchone()
        if row is None:
            raise HTTPException(status_code=404, detail="no pending response action with that id")
        reject_response_action(
            conn, response_id, actor=f"analyst:{analyst_id}", reason=request.reason
        )
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    return {"response_id": response_id, "rejected": True}
