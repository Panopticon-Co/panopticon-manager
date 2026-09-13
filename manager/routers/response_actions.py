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


def _row_to_dict(row) -> dict:
    record = {key: row[key] for key in _COLUMNS}
    record["target"] = json.loads(record.pop("target_json"))
    return record


@router.post("/api/v1/analysts/enroll", response_model=AnalystEnrollmentResponse)
async def enroll(
    request: AnalystEnrollmentRequest, x_panopticon_analyst_enrollment_token: str = Header(...)
) -> AnalystEnrollmentResponse:
    token = enroll_analyst(request.analyst_id, x_panopticon_analyst_enrollment_token)
    return AnalystEnrollmentResponse(analyst_id=request.analyst_id, access_token=token)


@router.get("/api/v1/response-actions")
async def list_response_actions(
    authorization: str | None = Header(default=None),
    state: str | None = None,
) -> dict:
    require_analyst_token(authorization)
    conn = db.connect()
    conn.execute("BEGIN IMMEDIATE")
    try:
        expire_stale_response_actions(conn)
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    if state is not None:
        rows = conn.execute(
            f"SELECT {', '.join(_COLUMNS)} FROM response_actions "
            "WHERE lifecycle_state = ? ORDER BY created_at DESC LIMIT 200",
            (state,),
        ).fetchall()
    else:
        rows = conn.execute(
            f"SELECT {', '.join(_COLUMNS)} FROM response_actions ORDER BY created_at DESC LIMIT 200"
        ).fetchall()
    return {"response_actions": [_row_to_dict(row) for row in rows]}


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
