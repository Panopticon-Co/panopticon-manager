"""Dedicated scope administration; no response execution or implicit access grant."""

from typing import Literal

from fastapi import APIRouter, Header, HTTPException, Query
from pydantic import BaseModel, ConfigDict, Field, StrictInt, field_validator

from manager import artifact_access as access
from manager import db
from manager.artifact_keys import record
from manager.auth import require_analyst_permission

router = APIRouter()


class Revoke(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    schema_version: Literal["1"]
    policy_version: StrictInt = Field(ge=1, le=1)
    request_id: str = Field(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9._:-]+$")
    reason: str = Field(min_length=1, max_length=512)

    @field_validator("reason")
    @classmethod
    def nonblank(cls, value):
        if not value.strip():
            raise ValueError("reason must not be blank")
        return value


class Grant(Revoke):
    analyst_id: str = Field(min_length=1, max_length=128)
    host_id: str = Field(min_length=1, max_length=256)
    alert_id: str = Field(min_length=1, max_length=128)


def change(authorization, kind, value, grant_id=None):
    actor = "analyst:" + require_analyst_permission(authorization, "artifact:scope:manage")
    conn = db.connect()
    conn.execute("BEGIN IMMEDIATE")
    try:
        require_analyst_permission(authorization, "artifact:scope:manage")
        result = access.operate(conn, actor, kind, value.model_dump(), grant_id)
        conn.commit()
        return result
    except HTTPException as exc:
        conn.rollback()
        conn.execute("BEGIN IMMEDIATE")
        try:
            record(
                conn,
                "artifact_access_refused",
                actor,
                getattr(value, "host_id", None),
                value.request_id,
                {
                    "operation": kind,
                    "grant_id": grant_id,
                    "policy_version": 1,
                    "reason": exc.detail,
                },
            )
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        raise
    except Exception:
        conn.rollback()
        raise


@router.post("/api/v1/artifact-access/grants")
async def grant(value: Grant, authorization: str | None = Header(None)):
    return change(authorization, "grant", value)


@router.post("/api/v1/artifact-access/grants/{grant_id}/revoke")
async def revoke(grant_id: str, value: Revoke, authorization: str | None = Header(None)):
    return change(authorization, "revoke", value, grant_id)


@router.get("/api/v1/artifact-access/grants")
async def grants(
    authorization: str | None = Header(None),
    analyst_id: str | None = Query(None, min_length=1, max_length=128),
    host_id: str | None = Query(None, min_length=1, max_length=256),
    alert_id: str | None = Query(None, min_length=1, max_length=128),
    limit: int = Query(100, ge=1, le=200),
):
    require_analyst_permission(authorization, "artifact:scope:manage")
    terms, args = [], []
    for field, value in (("analyst_id", analyst_id), ("host_id", host_id), ("alert_id", alert_id)):
        if value is not None:
            terms.append(field + "=?")
            args.append(value)
    where = " WHERE " + " AND ".join(terms) if terms else ""
    rows = (
        db.connect()
        .execute(
            f"SELECT {access.PUBLIC_COLUMNS} FROM artifact_access_grants"
            + where
            + " ORDER BY created_at DESC,grant_id DESC LIMIT ?",
            (*args, limit),
        )
        .fetchall()
    )
    return {
        "schema_version": "1",
        "policy_version": access.POLICY_VERSION,
        "grants": [dict(row) for row in rows],
    }
