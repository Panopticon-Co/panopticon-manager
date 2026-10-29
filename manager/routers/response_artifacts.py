"""Agent artifact acceptance and analyst attachment downloads; no arbitrary paths."""

import base64
import hashlib
import threading
from typing import Literal

from fastapi import APIRouter, Header, HTTPException, Query, Request, Response
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field

from manager import artifact_delivery as delivery
from manager import db
from manager import response_artifacts as store
from manager.artifact_access import require_artifact
from manager.artifact_keys import record
from manager.auth import require_agent_token, require_analyst_token
from manager.timeutil import iso_now
from manager.wire.linux_endpoint import strict_json

router = APIRouter()
_upload_slots = threading.BoundedSemaphore(4)
READ_HEADERS = {"Cache-Control": "no-store", "X-Content-Type-Options": "nosniff"}


@router.post("/api/v1/agents/{agent_id}/commands/{command_id}/artifacts")
async def upload(
    agent_id: str, command_id: str, request: Request, authorization: str | None = Header(None)
):
    conn = db.connect()
    conn.execute("BEGIN IMMEDIATE")
    try:
        require_agent_token(agent_id, authorization)
        linked = conn.execute(
            "SELECT ra.response_id,json_extract(c.command_json,'$.host_id') AS host_id "
            "FROM commands c LEFT JOIN response_actions ra ON ra.command_id=c.command_id "
            "WHERE c.command_id=? AND c.agent_id=?", (command_id, agent_id)
        ).fetchone()
        record(conn, "artifact_unsigned_upload_refused", "agent:" + agent_id,
               linked["host_id"] if linked else None, linked["response_id"] if linked else None,
               {"command_id": command_id, "reason": "unsigned artifact uploads are retired"})
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    raise HTTPException(410, "unsigned artifact uploads are retired; use signed artifact transfer")


@router.get("/api/v1/response-artifacts/{artifact_id}/custody")
async def custody(
    artifact_id: str,
    after: int = Query(0, ge=0, le=0x7FFFFFFFFFFFFFFF),
    limit: int = Query(200, ge=1, le=200),
    authorization: str | None = Header(None),
):
    conn = db.connect()
    conn.execute("BEGIN IMMEDIATE")
    try:
        require_artifact(conn, artifact_id, authorization)
        events = store.custody_rows(conn, artifact_id, after=after, limit=limit)
        conn.commit()
    except HTTPException as exc:
        conn.rollback()
        audit_read_refusal(conn, artifact_id, authorization, exc)
        raise
    except Exception:
        conn.rollback()
        raise
    return JSONResponse(
        {
            "artifact_id": artifact_id,
            "events": events,
            "next_after": events[-1]["sequence"] if events else after,
        },
        headers=READ_HEADERS,
    )


@router.post("/api/v1/agents/{agent_id}/commands/{command_id}/artifacts/signed")
async def upload_signed(
    agent_id: str, command_id: str, request: Request, authorization: str | None = Header(None)
):
    require_agent_token(agent_id, authorization)
    if not _upload_slots.acquire(blocking=False):
        raise HTTPException(429, "artifact capacity busy; retain evidence and retry")
    conn = db.connect()
    try:
        if request.headers.get("content-type", "").split(";")[0].lower() != "application/json":
            raise HTTPException(422, "artifact upload requires application/json")
        body = bytearray()
        async for chunk in request.stream():
            body.extend(chunk)
            if len(body) > store.MAX_BODY:
                raise HTTPException(413, "artifact request exceeds bounded upload size")
        try:
            upload = store.SignedArtifactUpload.model_validate(strict_json(body.decode("utf-8")))
        except (ValueError, RecursionError) as exc:
            raise HTTPException(422, "invalid closed signed artifact upload") from exc
        conn.execute("BEGIN IMMEDIATE")
        require_agent_token(agent_id, authorization)
        result = store.retain_signed(conn, agent_id, command_id, upload)
        conn.commit()
        return result
    except HTTPException as exc:
        conn.rollback()
        conn.execute("BEGIN IMMEDIATE")
        command = conn.execute(
            "SELECT ra.response_id,json_extract(c.command_json,'$.host_id') "
            "AS host_id FROM commands c LEFT JOIN response_actions ra "
            "ON ra.command_id=c.command_id WHERE c.command_id=? AND c.agent_id=?",
            (command_id, agent_id),
        ).fetchone()
        record(
            conn,
            "artifact_manifest_refused",
            "agent:" + agent_id,
            command["host_id"] if command else None,
            command["response_id"] if command else None,
            {"command_id": command_id, "reason": exc.detail},
        )
        conn.commit()
        raise
    except Exception:
        conn.rollback()
        raise
    finally:
        _upload_slots.release()


@router.get("/api/v1/response-artifacts/{artifact_id}/content")
async def content(artifact_id: str, authorization: str | None = Header(None)):
    conn = db.connect()
    conn.execute("BEGIN IMMEDIATE")
    try:
        analyst, row = require_artifact(conn, artifact_id, authorization)
        data, manifest, signing, _ = delivery.verified(conn, row, analyst)
        package = delivery.package(data, manifest, signing)
        store.custody_event(
            conn,
            artifact_id,
            "download_requested",
            "analyst:" + analyst,
            {"sha256": row["sha256"], "content_bytes": len(data)},
        )
        conn.commit()
    except HTTPException as exc:
        conn.rollback()
        audit_read_refusal(conn, artifact_id, authorization, exc)
        raise
    except Exception:
        conn.rollback()
        raise
    return Response(
        store.canonical(package).encode(),
        media_type="application/json",
        headers={
            "Content-Disposition": f'attachment; filename="{artifact_id}.json"',
            "X-Content-Type-Options": "nosniff",
            "Cache-Control": "no-store",
        },
    )


def audit_read_refusal(conn, artifact_id, authorization, error):
    if error.status_code != 403 and not isinstance(error, delivery.EvidenceRefusal):
        return
    # Authenticate again after rollback; never accept an actor from the request body.
    analyst = require_analyst_token(authorization)
    conn.execute("BEGIN IMMEDIATE")
    try:
        row = conn.execute(
            "SELECT a.host_id,ra.response_id FROM response_artifacts a "
            "LEFT JOIN response_actions ra ON ra.command_id=a.command_id WHERE a.artifact_id=?",
            (artifact_id,),
        ).fetchone()
        if isinstance(error, delivery.EvidenceRefusal):
            store.custody_event(conn, artifact_id, error.event, error.actor, error.evidence_detail)
        if error.status_code == 403:
            record(
                conn,
                "artifact_access_denied",
                "analyst:" + analyst,
                row["host_id"] if row else None,
                row["response_id"] if row else None,
                {"artifact_id": artifact_id, "reason": error.detail, "policy_version": 1},
            )
        conn.commit()
    except Exception:
        conn.rollback()
        raise


def read_transaction(artifact_id, authorization, operation, *, allow_compromised=False):
    conn = db.connect()
    conn.execute("BEGIN IMMEDIATE")
    try:
        analyst, row = require_artifact(conn, artifact_id, authorization)
        verified = delivery.verified(conn, row, analyst, allow_compromised=allow_compromised)
        result = operation(conn, analyst, row, *verified)
        conn.commit()
        return JSONResponse(result, headers=READ_HEADERS)
    except HTTPException as exc:
        conn.rollback()
        audit_read_refusal(conn, artifact_id, authorization, exc)
        raise
    except Exception:
        conn.rollback()
        raise


@router.get("/api/v1/response-artifacts/{artifact_id}/context")
async def context(artifact_id: str, authorization: str | None = Header(None)):
    def build(conn, analyst, row, data, manifest, signing, digest):
        trusted = {
            field: row[field]
            for field in (
                "artifact_id",
                "agent_id",
                "host_id",
                "command_id",
                "correlation_id",
                "alert_id",
                "response_id",
            )
        }
        trusted.update(
            {
                field: signing[field]
                for field in ("key_id", "key_version", "public_key", "trust_status")
            }
        )
        if signing["trust_status"] == "compromised_key":
            trusted.update(
                compromised_at=signing["compromised_at"],
                compromise_reason=signing["compromise_reason"],
            )
        store.custody_event(
            conn,
            artifact_id,
            "artifact_context_viewed",
            "analyst:" + analyst,
            {"manifest_sha256": digest, "trust_status": signing["trust_status"]},
        )
        return {
            "schema_version": "1",
            "artifact_id": artifact_id,
            "manifest": manifest,
            "manifest_sha256": digest,
            "trusted": trusted,
            "chunk_bytes": 65536,
        }

    return read_transaction(artifact_id, authorization, build, allow_compromised=True)


@router.get("/api/v1/response-artifacts/{artifact_id}/chunks")
async def chunks(
    artifact_id: str,
    offset: int = Query(..., ge=0, le=1048576),
    manifest_sha256: str = Query(..., pattern=r"^[0-9a-f]{64}$"),
    authorization: str | None = Header(None),
):
    def build(conn, analyst, row, data, manifest, signing, digest):
        if digest != manifest_sha256:
            raise HTTPException(409, "artifact download manifest binding changed")
        if offset >= len(data) or offset % 65536:
            raise HTTPException(422, "artifact download offset must identify a complete frame")
        chunk = data[offset : offset + 65536]
        chunk_sha = hashlib.sha256(chunk).hexdigest()
        store.custody_event(
            conn,
            artifact_id,
            "artifact_download_chunk",
            "analyst:" + analyst,
            {
                "manifest_sha256": digest,
                "offset": offset,
                "content_bytes": len(chunk),
                "sha256": chunk_sha,
            },
        )
        return {
            "schema_version": "1",
            "artifact_id": artifact_id,
            "manifest_sha256": digest,
            "offset": offset,
            "content_bytes": len(chunk),
            "sha256": chunk_sha,
            "content_base64": base64.b64encode(chunk).decode(),
            "next_offset": offset + len(chunk),
            "complete": offset + len(chunk) == len(data),
        }

    return read_transaction(artifact_id, authorization, build)


class ViewRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    schema_version: Literal["1"]
    request_id: str = Field(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9._:-]+$")
    manifest_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    operation: Literal["view", "download"]


@router.post("/api/v1/response-artifacts/{artifact_id}/view")
async def viewed(artifact_id: str, request: ViewRequest, authorization: str | None = Header(None)):
    def build(conn, analyst, row, data, manifest, signing, digest):
        if digest != request.manifest_sha256:
            raise HTTPException(409, "artifact acknowledgement manifest binding changed")
        credential = conn.execute(
            "SELECT token_digest FROM analyst_credentials WHERE analyst_id=?", (analyst,)
        ).fetchone()[0]
        prior = conn.execute(
            "SELECT * FROM artifact_view_receipts WHERE analyst_id=? AND credential_digest=? "
            "AND request_id=?",
            (analyst, credential, request.request_id),
        ).fetchone()
        if prior is not None:
            if (
                prior["artifact_id"] != artifact_id
                or prior["manifest_sha256"] != digest
                or prior["operation"] != request.operation
            ):
                raise HTTPException(409, "artifact acknowledgement request ID already used")
            recorded_at = prior["recorded_at"]
        else:
            recorded_at = iso_now()
            conn.execute(
                "INSERT INTO artifact_view_receipts VALUES (?,?,?,?,?,?,?)",
                (
                    analyst,
                    credential,
                    request.request_id,
                    artifact_id,
                    digest,
                    request.operation,
                    recorded_at,
                ),
            )
            store.custody_event(
                conn,
                artifact_id,
                "artifact_viewed",
                "analyst:" + analyst,
                {
                    "manifest_sha256": digest,
                    "operation": request.operation,
                    "view_request_id": request.request_id,
                    "sha256": row["sha256"],
                    "content_bytes": len(data),
                },
            )
        return {
            "schema_version": "1",
            "artifact_id": artifact_id,
            "manifest_sha256": digest,
            "operation": request.operation,
            "recorded_at": recorded_at,
            "recorded": True,
        }

    return read_transaction(artifact_id, authorization, build)
