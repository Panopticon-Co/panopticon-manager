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

import hashlib
import json
import os
import sqlite3
from datetime import datetime, timezone
from typing import Literal

from fastapi import APIRouter, Header, HTTPException, Query
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field, field_validator
from response_engine.access import AnalystRole
from response_engine.catalog import action_catalog
from response_engine.contract import Action

from manager import db
from manager.analyst_response import resolve_manual_target
from manager.auth import (
    analyst_access,
    enroll_analyst,
    require_analyst_permission,
    require_analyst_token,
)
from manager.detection.response import (
    _insert_response_action,
    authorize_response_action,
    expire_stale_response_actions,
    find_open_duplicate,
    reject_response_action,
)
from manager.response_audit import record_decision
from manager.routers.commands import _audit, _expire_stale_commands
from manager.timeutil import iso_now

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
    "origin",
    "requested_by",
    "request_reason",
    "requested_agent_id",
    "requested_host_id",
)


class AnalystEnrollmentRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    analyst_id: str = Field(min_length=1, max_length=128)
    role: AnalystRole = AnalystRole.ANALYST


class AnalystEnrollmentResponse(BaseModel):
    analyst_id: str
    access_token: str
    role: AnalystRole = AnalystRole.ANALYST
    token_type: str = "Bearer"


class RejectRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    reason: str = Field(min_length=1, max_length=512)

    @field_validator("reason")
    @classmethod
    def nonblank(cls, value):
        if not value.strip():
            raise ValueError("reason must not be blank")
        return value.strip()


class ManualRequest(RejectRequest):
    alert_id: str = Field(min_length=1, max_length=128)
    action: Action
    target: dict = Field(default_factory=dict, max_length=16)
    request_id: str | None = Field(
        default=None, min_length=1, max_length=128, pattern=r"^[A-Za-z0-9._:-]+$"
    )

    @field_validator("request_id")
    @classmethod
    def provided_id_is_not_null(cls, value):
        if value is None:
            raise ValueError("request_id must be omitted or a nonempty string")
        return value


_SELECT_PENDING = (
    "SELECT response_id FROM response_actions WHERE response_id = ? AND lifecycle_state = 'PENDING'"
)


ResponseActionState = Literal["PENDING", "AUTHORIZED", "REJECTED", "EXPIRED"]
CommandState = Literal[
    "AUTHORIZED",
    "DISPATCHED",
    "ACCEPTED",
    "SUCCEEDED",
    "FAILED",
    "REJECTED",
    "EXPIRED",
    "CANCELLED",
    "INDETERMINATE",
]

_SELECT = (
    f"SELECT {', '.join('ra.' + c for c in _COLUMNS)}, "
    "c.lifecycle_state AS command_lifecycle_state, c.command_json, c.expires_at, "
    "a.agent_id, a.host_id "
    "FROM response_actions ra JOIN alerts a ON a.alert_id=ra.alert_id "
    "LEFT JOIN commands c ON c.command_id = ra.command_id"
)


def _row_to_dict(row) -> dict:
    record = {key: row[key] for key in _COLUMNS}
    record["target"] = json.loads(record.pop("target_json"))
    return record


def _with_command_audit(conn: sqlite3.Connection, rows, *, full_history=False) -> list[dict]:
    """Serialize response_actions rows (selected with ``_SELECT``), adding the
    linked command's ``command_lifecycle_state`` and its ``command_audit``
    rows as ``audit`` (empty for an action that never produced a command)."""
    out = []
    for row in rows:
        record = _row_to_dict(row)
        record["command_lifecycle_state"] = row["command_lifecycle_state"]
        record["agent_id"] = row["agent_id"]
        record["host_id"] = row["host_id"]
        record["expires_at"] = row["expires_at"]
        record["command"] = json.loads(row["command_json"]) if row["command_json"] else None
        record["results"] = []
        record["receipts"] = []
        record["audit"] = []
        decision_rows = conn.execute(
            "SELECT event_id,event,actor,detail,occurred_at FROM response_decision_audit "
            "WHERE response_id=? ORDER BY occurred_at,rowid"
            + ("" if full_history else " LIMIT 101"),
            (row["response_id"],),
        ).fetchall()
        record["decision_audit"] = [
            {**dict(r), "detail": json.loads(r["detail"]) if r["detail"] else None}
            for r in (decision_rows if full_history else decision_rows[:100])
        ]
        record["evidence_truncated"] = not full_history and len(decision_rows) > 100
        if row["command_id"] is not None:
            record["results"] = [
                dict(r)
                for r in conn.execute(
                    "SELECT result_id,outcome,detail,received_at FROM command_results "
                    "WHERE command_id=? ORDER BY received_at,result_id",
                    (row["command_id"],),
                )
            ]
            record["receipts"] = [
                {"received_at": r["received_at"], "payload": json.loads(r["raw_json"])}
                for r in conn.execute(
                    "SELECT received_at,raw_json FROM command_result_receipts "
                    "WHERE command_id=? ORDER BY received_at,result_id"
                    + ("" if full_history else " LIMIT 21"),
                    (row["command_id"],),
                )
            ]
            record["audit"] = [
                dict(a)
                for a in conn.execute(
                    "SELECT audit_id, event, actor, detail, occurred_at FROM command_audit "
                    "WHERE command_id = ? ORDER BY occurred_at, rowid"
                    + ("" if full_history else " LIMIT 101"),
                    (row["command_id"],),
                ).fetchall()
            ]
            if not full_history:
                record["evidence_truncated"] |= (
                    len(record["audit"]) > 100 or len(record["receipts"]) > 20
                )
                record["audit"] = record["audit"][:100]
                record["receipts"] = record["receipts"][:20]
        out.append(record)
    return out


def expire_pending(conn: sqlite3.Connection) -> None:
    """Run the lazy PENDING -> EXPIRED sweep in its own short transaction, so
    every read shows current lifecycle states."""
    conn.execute("BEGIN IMMEDIATE")
    try:
        expire_stale_response_actions(conn)
        _expire_stale_commands(conn, datetime.now(timezone.utc).isoformat())
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
    token = enroll_analyst(request.analyst_id, x_panopticon_analyst_enrollment_token, request.role)
    return AnalystEnrollmentResponse(
        analyst_id=request.analyst_id, access_token=token, role=request.role
    )


@router.get("/api/v1/analysts/me")
async def current_analyst(authorization: str | None = Header(default=None)) -> dict:
    return {**analyst_access(authorization), "separate_approver_required": separate_approver()}


def separate_approver() -> bool:
    # Typos must not silently weaken an explicitly configured approval policy.
    value = os.environ.get("PANOPTICON_REQUIRE_SEPARATE_APPROVER", "false").strip().lower()
    if value not in {"true", "false", "1", "0"}:
        raise HTTPException(503, "separate-approver policy configuration is invalid")
    return value in {"true", "1"}


@router.get("/api/v1/response-actions")
async def list_response_actions(
    authorization: str | None = Header(default=None),
    state: ResponseActionState | None = None,
    command_state: CommandState | None = None,
    host_id: str | None = Query(default=None, max_length=128),
    alert_id: str | None = Query(default=None, max_length=128),
    limit: int = Query(default=200, ge=1, le=200),
    offset: int = Query(default=0, ge=0, le=1000000),
) -> dict:
    require_analyst_token(authorization)
    conn = db.connect()
    expire_pending(conn)
    terms, params = [], []
    for column, value in (
        ("ra.lifecycle_state", state),
        ("c.lifecycle_state", command_state),
        ("a.host_id", host_id),
        ("ra.alert_id", alert_id),
    ):
        if value is not None:
            terms.append(column + " = ?")
            params.append(value)
    where = " WHERE " + " AND ".join(terms) if terms else ""
    rows = conn.execute(
        _SELECT + where + " ORDER BY ra.created_at DESC,ra.response_id DESC LIMIT ? OFFSET ?",
        (*params, limit + 1, offset),
    ).fetchall()
    return {
        "response_actions": _with_command_audit(conn, rows[:limit]),
        "next_offset": offset + limit if len(rows) > limit else None,
    }


@router.get("/api/v1/response-actions/catalog")
async def catalog(authorization: str | None = Header(default=None)) -> dict:
    access = analyst_access(authorization)
    return {
        "actions": [item.model_dump(mode="json") for item in action_catalog()],
        "analyst": {**access, "separate_approver_required": separate_approver()},
    }


@router.post("/api/v1/response-actions", status_code=201)
async def create_manual(request: ManualRequest, authorization: str | None = Header(None)) -> dict:
    actor = "analyst:" + require_analyst_permission(authorization, "response:request")
    conn = db.connect()
    conn.execute("BEGIN IMMEDIATE")
    try:
        digest = hashlib.sha256(
            json.dumps(
                request.model_dump(exclude={"request_id"}), sort_keys=True, separators=(",", ":")
            ).encode()
        ).hexdigest()
        if request.request_id is not None:
            prior = conn.execute(
                "SELECT k.payload_digest,ra.response_id,ra.lifecycle_state,ra.target_json "
                "FROM response_request_keys k JOIN response_actions ra "
                "ON ra.response_id=k.response_id WHERE k.analyst_id=? AND k.request_id=?",
                (actor, request.request_id),
            ).fetchone()
            if prior is not None:
                if prior["payload_digest"] != digest:
                    raise HTTPException(409, "request_id is already bound to a different request")
                conn.commit()
                return {
                    "response_id": prior["response_id"],
                    "lifecycle_state": prior["lifecycle_state"],
                    "target": json.loads(prior["target_json"]),
                    "replayed": True,
                }
        expire_stale_response_actions(conn)
        _expire_stale_commands(conn, datetime.now(timezone.utc).isoformat())
        agent, host, target = resolve_manual_target(
            conn, request.alert_id, request.action, request.target
        )
        # Match the enrolled host even for older alerts without a denormalized host_id.
        duplicate = conn.execute(
            "SELECT ra.target_json FROM response_actions ra "
            "JOIN alerts a ON a.alert_id=ra.alert_id "
            "LEFT JOIN commands c ON c.command_id=ra.command_id WHERE a.agent_id=? AND ra.action=? "
            "AND (ra.lifecycle_state='PENDING' OR (ra.lifecycle_state='AUTHORIZED' "
            "AND c.lifecycle_state IN ('AUTHORIZED','DISPATCHED','ACCEPTED')))",
            (agent, request.action),
        ).fetchall()
        if find_open_duplicate(conn, host, request.action, target) or any(
            json.loads(r["target_json"]) == target for r in duplicate
        ):
            raise HTTPException(409, "an equivalent response is already pending or in flight")
        response_id = _insert_response_action(
            conn,
            alert_id=request.alert_id,
            action=request.action,
            tier="ANALYST_APPROVAL",
            state="PENDING",
            target=target,
            reason=request.reason,
            actor=actor,
        )
        conn.execute(
            "UPDATE response_actions SET origin='analyst',requested_by=?,request_reason=?,"
            "requested_agent_id=?,requested_host_id=? WHERE response_id=?",
            (actor, request.reason, agent, host, response_id),
        )
        if request.request_id is not None:
            conn.execute(
                "INSERT INTO response_request_keys VALUES (?,?,?,?)",
                (actor, request.request_id, digest, response_id),
            )
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    return {"response_id": response_id, "lifecycle_state": "PENDING", "target": target}


@router.post("/api/v1/response-actions/{response_id}/cancel")
async def cancel(
    response_id: str, request: RejectRequest, authorization: str | None = Header(default=None)
) -> dict:
    actor = "analyst:" + require_analyst_permission(authorization, "response:decide")
    conn = db.connect()
    conn.execute("BEGIN IMMEDIATE")
    try:
        _expire_stale_commands(conn, datetime.now(timezone.utc).isoformat())
        row = conn.execute(
            "SELECT c.command_id,c.lifecycle_state FROM response_actions ra JOIN commands c "
            "ON c.command_id=ra.command_id WHERE ra.response_id=?",
            (response_id,),
        ).fetchone()
        if row is None:
            raise HTTPException(404, "response has no queued command")
        if row["lifecycle_state"] != "CANCELLED":
            if row["lifecycle_state"] != "AUTHORIZED":
                raise HTTPException(409, "only commands awaiting dispatch can be cancelled")
            conn.execute(
                "UPDATE commands SET lifecycle_state='CANCELLED' WHERE command_id=?",
                (row["command_id"],),
            )
            _audit(conn, row["command_id"], "cancelled", actor, request.reason)
            record_decision(conn, response_id, "cancelled", actor, {"reason": request.reason})
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    return {"response_id": response_id, "cancelled": True}


@router.post("/api/v1/response-actions/{response_id}/authorize")
async def authorize(response_id: str, authorization: str | None = Header(default=None)) -> dict:
    analyst_id = require_analyst_permission(authorization, "response:decide")
    conn = db.connect()
    conn.execute("BEGIN IMMEDIATE")
    try:
        expire_stale_response_actions(conn)
        row = conn.execute(_SELECT_PENDING, (response_id,)).fetchone()
        if row is None:
            raise HTTPException(status_code=404, detail="no pending response action with that id")
        if separate_approver():
            requester = conn.execute(
                "SELECT requested_by FROM response_actions WHERE response_id=?", (response_id,)
            ).fetchone()["requested_by"]
            if requester == "analyst:" + analyst_id:
                raise HTTPException(403, "a different analyst must approve this manual request")
        authorize_response_action(conn, response_id, actor=f"analyst:{analyst_id}")
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    current = conn.execute(
        "SELECT lifecycle_state,decided_reason FROM response_actions WHERE response_id=?",
        (response_id,),
    ).fetchone()
    return {
        "response_id": response_id,
        "authorized": current["lifecycle_state"] == "AUTHORIZED",
        "lifecycle_state": current["lifecycle_state"],
        "reason": current["decided_reason"],
    }


@router.post("/api/v1/response-actions/{response_id}/reject")
async def reject(
    response_id: str, request: RejectRequest, authorization: str | None = Header(default=None)
) -> dict:
    analyst_id = require_analyst_permission(authorization, "response:decide")
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


@router.get("/api/v1/response-actions/{response_id}/export")
async def export_response(response_id: str, authorization: str | None = Header(None)):
    require_analyst_token(authorization)
    conn = db.connect()
    expire_pending(conn)
    # One read snapshot keeps state, command and histories internally consistent.
    conn.execute("BEGIN")
    try:
        rows = conn.execute(_SELECT + " WHERE ra.response_id=?", (response_id,)).fetchall()
        if not rows:
            raise HTTPException(404, "no response action with that id")
        record = _with_command_audit(conn, rows, full_history=True)[0]
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    return JSONResponse(
        {"schema_version": "1", "exported_at": iso_now(), "response_action": record}
    )
