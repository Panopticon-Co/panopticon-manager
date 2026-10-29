"""Authenticated, bounded upload framing; all evidence verification stays server-side."""

from contextlib import asynccontextmanager
from typing import Annotated

from fastapi import APIRouter, Header, HTTPException, Path, Request

from manager import artifact_transfers as transfers
from manager import db
from manager.artifact_keys import record
from manager.auth import require_agent_token
from manager.routers.response_artifacts import _upload_slots
from manager.wire.linux_endpoint import strict_json

router = APIRouter()
ArtifactID = Annotated[str, Path(pattern=r"^art_[0-9a-f]{64}$")]
Offset = Annotated[int, Path(ge=0, le=1048575)]


@asynccontextmanager
async def operation(agent_id, command_id, authorization):
    require_agent_token(agent_id, authorization)
    if not _upload_slots.acquire(blocking=False):
        raise HTTPException(429, "artifact capacity busy; retain original and retry")
    conn = db.connect()
    try:
        yield conn
        conn.commit()
    except HTTPException as exc:
        conn.rollback()
        conn.execute("BEGIN IMMEDIATE")
        # Expiry is system policy, independent of whether this new request is
        # accepted. Otherwise a quota refusal could undo the cleanup that frees
        # reservations and leave abandoned sessions permanently consuming budget.
        transfers.expire(conn)
        owner = conn.execute(
            "SELECT ra.response_id,json_extract(c.command_json,'$.host_id') AS host_id "
            "FROM commands c LEFT JOIN response_actions ra ON ra.command_id=c.command_id "
            "WHERE c.command_id=? AND c.agent_id=?",
            (command_id, agent_id),
        ).fetchone()
        record(
            conn,
            "artifact_transfer_refused",
            "agent:" + agent_id,
            owner["host_id"] if owner else None,
            owner["response_id"] if owner else None,
            {"command_id": command_id, "reason": exc.detail},
        )
        conn.commit()
        raise
    except Exception:
        conn.rollback()
        raise
    finally:
        _upload_slots.release()


async def body(request, media_type, maximum):
    if request.headers.get("content-type", "").split(";")[0].lower() != media_type:
        raise HTTPException(422, "artifact transfer content type disagrees")
    data = bytearray()
    async for chunk in request.stream():
        if len(data) + len(chunk) > maximum:
            raise HTTPException(413, "artifact transfer body exceeds bound")
        data.extend(chunk)
    return bytes(data)


async def document(request, model, maximum):
    data = await body(request, "application/json", maximum)
    try:
        return model.model_validate(strict_json(data.decode("utf-8")))
    except (ValueError, RecursionError) as exc:
        raise HTTPException(422, "invalid closed artifact transfer request") from exc


def begin(conn, agent_id, authorization):
    conn.execute("BEGIN IMMEDIATE")
    require_agent_token(agent_id, authorization)


@router.post("/api/v1/agents/{agent_id}/commands/{command_id}/artifact-transfers")
async def admit(
    agent_id: str, command_id: str, request: Request, authorization: str | None = Header(None)
):
    async with operation(agent_id, command_id, authorization) as conn:
        value = await document(request, transfers.Admission, 8192)
        begin(conn, agent_id, authorization)
        return transfers.admit(conn, agent_id, command_id, value)


@router.put(
    "/api/v1/agents/{agent_id}/commands/{command_id}/artifact-transfers/{artifact_id}/chunks/{offset}"
)
async def chunk(
    agent_id: str,
    command_id: str,
    artifact_id: ArtifactID,
    offset: Offset,
    request: Request,
    x_panopticon_chunk_sha256: str = Header(pattern=r"^[0-9a-f]{64}$"),
    authorization: str | None = Header(None),
):
    async with operation(agent_id, command_id, authorization) as conn:
        data = await body(request, "application/octet-stream", transfers.CHUNK_BYTES)
        begin(conn, agent_id, authorization)
        return transfers.put_chunk(
            conn, agent_id, command_id, artifact_id, offset, x_panopticon_chunk_sha256, data
        )


@router.post(
    "/api/v1/agents/{agent_id}/commands/{command_id}/artifact-transfers/{artifact_id}/complete"
)
async def complete(
    agent_id: str,
    command_id: str,
    artifact_id: ArtifactID,
    request: Request,
    authorization: str | None = Header(None),
):
    async with operation(agent_id, command_id, authorization) as conn:
        value = await document(request, transfers.Completion, 1024)
        begin(conn, agent_id, authorization)
        return transfers.complete(conn, agent_id, command_id, artifact_id, value)
