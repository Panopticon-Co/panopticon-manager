"""Privileged bounded audit queries and independently exportable signed anchors."""

import json
import sqlite3
from datetime import datetime

from fastapi import APIRouter, Header, HTTPException, Query
from pydantic import BaseModel, ConfigDict, Field

from manager import audit_chain, command_signing, db
from manager.auth import require_analyst_permission

router = APIRouter()


class CheckpointRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    request_id: str = Field(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9._:-]+$")


@router.get("/api/v1/response-audit")
async def query(
    request_id: str | None = Query(None, min_length=1, max_length=128),
    actor: str | None = Query(None, min_length=1, max_length=256),
    asset_id: str | None = Query(None, min_length=1, max_length=256),
    since: datetime | None = None,
    until: datetime | None = None,
    after: int = Query(0, ge=0, le=0x7FFFFFFFFFFFFFFF),
    limit: int = Query(100, ge=1, le=200),
    authorization: str | None = Header(None),
):
    require_analyst_permission(authorization, "response:decide")
    terms, args = ["sequence > ?"], [after]
    for name, value in (("request_id", request_id), ("actor", actor), ("asset_id", asset_id)):
        if value is not None:
            terms.append(f"{name}=?")
            args.append(value)
    for name, value, operator in (("since", since, ">="), ("until", until, "<=")):
        if value is not None:
            if value.utcoffset() is None:
                raise HTTPException(422, f"{name} requires an explicit timezone")
            terms.append(f"julianday(occurred_at) {operator} julianday(?)")
            args.append(value.isoformat())
    if since is not None and until is not None and since > until:
        raise HTTPException(422, "since must not be after until")
    rows = (
        db.connect()
        .execute(
            "SELECT * FROM response_audit_ledger WHERE "
            + " AND ".join(terms)
            + " ORDER BY sequence LIMIT ?",
            (*args, limit),
        )
        .fetchall()
    )
    events = []
    for raw in rows:
        item = dict(raw)
        item["payload"] = json.loads(item.pop("payload_json"))
        item["provenance"] = "legacy_snapshot_only" if item["legacy_import"] else "chained_event"
        events.append(item)
    return {
        "schema_version": "1",
        "events": events,
        "next_after": events[-1]["sequence"] if events else after,
        "verification": "query results are not a full-chain verification",
    }


@router.get("/api/v1/response-audit/verify")
async def verify(authorization: str | None = Header(None), strict_history: bool = False):
    require_analyst_permission(authorization, "response:decide")
    conn = db.connect()
    # One read snapshot prevents concurrent append from producing false coverage failures.
    conn.execute("BEGIN")
    try:
        result = audit_chain.verify(conn, require_chained_history=strict_history)
        conn.commit()
        return result
    except (ValueError, sqlite3.DatabaseError) as exc:
        conn.rollback()
        raise HTTPException(503, "response audit verification failed") from exc


@router.post("/api/v1/response-audit/checkpoints", status_code=201)
async def checkpoint(request: CheckpointRequest, authorization: str | None = Header(None)):
    actor = "analyst:" + require_analyst_permission(authorization, "response:decide")
    conn = db.connect()
    conn.execute("BEGIN IMMEDIATE")
    try:
        require_analyst_permission(authorization, "response:decide")
        result = audit_chain.checkpoint(
            conn, actor=actor, request_key=actor + ":" + request.request_id
        )
        conn.commit()
        return result
    except (ValueError, sqlite3.DatabaseError, command_signing.SigningUnavailable) as exc:
        conn.rollback()
        raise HTTPException(
            503, "audit checkpoint unavailable; no unsigned checkpoint issued"
        ) from exc
    except Exception:
        conn.rollback()
        raise
