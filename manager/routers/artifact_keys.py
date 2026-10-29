"""Artifact identity control plane; no new endpoint response actions."""

import hashlib
import json
from typing import Literal

from fastapi import APIRouter, Header, HTTPException
from pydantic import BaseModel, ConfigDict, Field

from manager import artifact_keys as keys
from manager import audit_chain, db
from manager.auth import require_agent_token, require_analyst_permission
from manager.timeutil import iso_now

router = APIRouter()


class RotationRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    schema_version: Literal["1"]
    request_id: str = Field(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9._:-]+$")
    old_key_id: str = Field(pattern=r"^[0-9a-f]{16}$")
    new_public_key: str = Field(min_length=88, max_length=88)
    nonce: str = Field(min_length=44, max_length=44)
    old_signature: str = Field(pattern=r"^[A-Za-z0-9+/]{86}==$", max_length=88)
    new_signature: str = Field(pattern=r"^[A-Za-z0-9+/]{86}==$", max_length=88)


class IdentityDecision(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    request_id: str = Field(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9._:-]+$")
    reason: str = Field(min_length=1, max_length=1000)


def _refusal(conn, agent_id, request_id, actor, detail):
    conn.rollback()
    conn.execute("BEGIN IMMEDIATE")
    row = conn.execute(
        "SELECT host_id FROM enrolled_agents WHERE agent_id=?", (agent_id,)
    ).fetchone()
    keys.record(
        conn,
        "artifact_identity_refused",
        actor,
        row[0] if row else None,
        request_id,
        {"reason": detail},
    )
    conn.commit()


@router.post("/api/v1/agents/{agent_id}/artifact-key-rotations", status_code=201)
async def rotate(agent_id: str, request: RotationRequest, authorization: str | None = Header(None)):
    require_agent_token(agent_id, authorization)
    conn = db.connect()
    conn.execute("BEGIN IMMEDIATE")
    try:
        require_agent_token(agent_id, authorization)
        result = keys.request_rotation(conn, agent_id, request.model_dump())
        conn.commit()
        return result
    except HTTPException as exc:
        _refusal(conn, agent_id, request.request_id, "agent:" + agent_id, exc.detail)
        raise
    except Exception:
        conn.rollback()
        raise


@router.get("/api/v1/agents/{agent_id}/artifact-key-rotations/{request_id}")
async def rotation_status(agent_id: str, request_id: str, authorization: str | None = Header(None)):
    require_agent_token(agent_id, authorization)
    row = (
        db.connect()
        .execute(
            "SELECT request_id,state,new_key_id,approved_at "
            "FROM artifact_key_rotations WHERE agent_id=? AND request_id=?",
            (agent_id, request_id),
        )
        .fetchone()
    )
    if row is None:
        raise HTTPException(404, "artifact key rotation unavailable")
    return dict(row)


@router.post("/api/v1/agents/{agent_id}/artifact-key-rotations/{request_id}/approve")
async def approve(agent_id: str, request_id: str, authorization: str | None = Header(None)):
    actor = "analyst:" + require_analyst_permission(authorization, "response:decide")
    conn = db.connect()
    conn.execute("BEGIN IMMEDIATE")
    try:
        require_analyst_permission(authorization, "response:decide")
        result = keys.approve_rotation(conn, agent_id, request_id, actor)
        conn.commit()
        return result
    except HTTPException as exc:
        _refusal(conn, agent_id, request_id, actor, exc.detail)
        raise
    except Exception:
        conn.rollback()
        raise


@router.get("/api/v1/agents/{agent_id}/artifact-keys")
async def history(agent_id: str, authorization: str | None = Header(None)):
    require_analyst_permission(authorization, "response:decide")
    rows = (
        db.connect()
        .execute(
            "SELECT * FROM artifact_signing_keys WHERE agent_id=? ORDER BY key_version", (agent_id,)
        )
        .fetchall()
    )
    return {
        "agent_id": agent_id,
        "keys": [{**dict(row), "trust_status": keys.key_status(row)} for row in rows],
    }


def _identity_operation(conn, agent_id, actor, request, *, key_id=None):
    payload = {"agent_id": agent_id, "key_id": key_id, **request.model_dump()}
    digest = hashlib.sha256(audit_chain.canonical(payload).encode()).hexdigest()
    prior = conn.execute(
        "SELECT * FROM artifact_identity_operations WHERE actor=? AND request_id=?",
        (actor, request.request_id),
    ).fetchone()
    if prior:
        if prior["payload_digest"] != digest:
            raise HTTPException(409, "identity retry key binds another decision")
        return json.loads(prior["result_json"])
    enrolled = conn.execute(
        "SELECT * FROM enrolled_agents WHERE agent_id=?", (agent_id,)
    ).fetchone()
    if enrolled is None:
        raise HTTPException(404, "endpoint identity unavailable")
    now = iso_now()
    if key_id is not None:
        row = conn.execute(
            "SELECT * FROM artifact_signing_keys WHERE agent_id=? AND key_id=?", (agent_id, key_id)
        ).fetchone()
        if row is None:
            raise HTTPException(404, "artifact key unavailable")
        changed = row["compromised_at"] is None
        if changed:
            conn.execute(
                "UPDATE artifact_signing_keys SET compromised_at=?,compromise_reason=? "
                "WHERE agent_id=? AND key_id=?",
                (now, request.reason, agent_id, key_id),
            )
        event, state = "artifact_key_compromised", "compromised_key"
    else:
        changed = enrolled["revoked_at"] is None
        if changed:
            conn.execute(
                "UPDATE enrolled_agents SET revoked_at=? WHERE agent_id=?", (now, agent_id)
            )
            conn.execute(
                "UPDATE artifact_signing_keys SET retired_at=? "
                "WHERE agent_id=? AND retired_at IS NULL",
                (now, agent_id),
            )
        event, state = "artifact_enrollment_revoked", "revoked_enrollment"
    result = {"agent_id": agent_id, "key_id": key_id, "state": state, "changed": changed}
    if changed:
        keys.record(
            conn,
            event,
            actor,
            enrolled["host_id"],
            request.request_id,
            {"agent_id": agent_id, "key_id": key_id, "reason": request.reason},
        )
    conn.execute(
        "INSERT INTO artifact_identity_operations VALUES (?,?,?,?)",
        (actor, request.request_id, digest, audit_chain.canonical(result)),
    )
    return result


async def _decide(agent_id, request, authorization, *, key_id=None):
    actor = "analyst:" + require_analyst_permission(authorization, "response:decide")
    conn = db.connect()
    conn.execute("BEGIN IMMEDIATE")
    try:
        require_analyst_permission(authorization, "response:decide")
        result = _identity_operation(conn, agent_id, actor, request, key_id=key_id)
        conn.commit()
        return result
    except HTTPException as exc:
        _refusal(conn, agent_id, request.request_id, actor, exc.detail)
        raise
    except Exception:
        conn.rollback()
        raise


@router.post("/api/v1/agents/{agent_id}/artifact-keys/{key_id}/revoke")
async def revoke_key(
    agent_id: str, key_id: str, request: IdentityDecision, authorization: str | None = Header(None)
):
    return await _decide(agent_id, request, authorization, key_id=key_id)


@router.post("/api/v1/agents/{agent_id}/artifact-enrollment/revoke")
async def revoke_enrollment(
    agent_id: str, request: IdentityDecision, authorization: str | None = Header(None)
):
    return await _decide(agent_id, request, authorization)
