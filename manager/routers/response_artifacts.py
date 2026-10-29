"""Agent artifact acceptance and analyst attachment downloads; no arbitrary paths."""

import base64
import hashlib
import json
import threading

from fastapi import APIRouter, Header, HTTPException, Query, Request, Response
from response_engine.artifacts import artifact_signing_input

from manager import db
from manager import response_artifacts as store
from manager.artifact_keys import record, retained_status, verify_signature
from manager.auth import require_agent_token, require_analyst_token
from manager.wire.linux_endpoint import strict_json

router = APIRouter()
_upload_slots = threading.BoundedSemaphore(4)


async def _accept_upload(
    agent_id: str, command_id: str, request: Request, authorization: str | None = Header(None)
):
    if request.headers.get("content-type", "").split(";")[0].lower() != "application/json":
        raise HTTPException(422, "artifact upload requires application/json")
    body = bytearray()
    async for chunk in request.stream():
        body.extend(chunk)
        if len(body) > store.MAX_BODY:
            raise HTTPException(413, "artifact request exceeds bounded upload size")
    try:
        value = store.ArtifactUpload.model_validate(strict_json(body.decode("utf-8")))
    except (ValueError, RecursionError) as exc:
        raise HTTPException(422, "invalid closed artifact upload") from exc
    content = store.decoded_content(value)
    conn = db.connect()
    conn.execute("BEGIN IMMEDIATE")
    try:
        require_agent_token(agent_id, authorization)
        reply = store.retain(conn, agent_id, command_id, value, content)
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    return reply


@router.post("/api/v1/agents/{agent_id}/commands/{command_id}/artifacts")
async def upload(
    agent_id: str, command_id: str, request: Request, authorization: str | None = Header(None)
):
    require_agent_token(agent_id, authorization)
    if not _upload_slots.acquire(blocking=False):
        raise HTTPException(429, "artifact upload capacity busy; retain evidence and retry")
    try:
        return await _accept_upload(agent_id, command_id, request, authorization)
    finally:
        _upload_slots.release()


@router.get("/api/v1/response-artifacts/{artifact_id}/custody")
async def custody(
    artifact_id: str,
    after: int = Query(0, ge=0, le=0x7FFFFFFFFFFFFFFF),
    limit: int = Query(200, ge=1, le=200),
    authorization: str | None = Header(None),
):
    require_analyst_token(authorization)
    conn = db.connect()
    if (
        conn.execute(
            "SELECT 1 FROM response_artifacts WHERE artifact_id=?", (artifact_id,)
        ).fetchone()
        is None
    ):
        raise HTTPException(404, "artifact unavailable")
    events = store.custody_rows(conn, artifact_id, after=after, limit=limit)
    return {
        "artifact_id": artifact_id,
        "events": events,
        "next_after": events[-1]["sequence"] if events else after,
    }


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
    analyst = require_analyst_token(authorization)
    conn = db.connect()
    conn.execute("BEGIN IMMEDIATE")
    try:
        require_analyst_token(authorization)
        row = conn.execute(
            "SELECT content,sha256,content_bytes FROM response_artifacts WHERE artifact_id=?",
            (artifact_id,),
        ).fetchone()
        if row is None:
            raise HTTPException(404, "artifact unavailable")
        signing = retained_status(conn, artifact_id)
        if signing["trust_status"] == "compromised_key":
            store.custody_event(
                conn,
                artifact_id,
                "retrieval_blocked_compromised_key",
                "analyst:" + analyst,
                {"key_id": signing["key_id"]},
            )
            conn.commit()
            raise HTTPException(
                403, "artifact signer is compromised; evidence preserved for review"
            )
        data = bytes(row["content"])
        if len(data) != row["content_bytes"] or hashlib.sha256(data).hexdigest() != row["sha256"]:
            store.custody_event(
                conn, artifact_id, "integrity_check_failed", "system:artifact-store", {}
            )
            conn.commit()
            raise HTTPException(
                503, "artifact integrity check failed; original retained for investigation"
            )
        attestation = conn.execute(
            """SELECT a.manifest_json,k.public_key FROM artifact_manifest_attestations a
            JOIN artifact_signing_keys k ON k.agent_id=a.agent_id AND k.key_id=a.key_id
            WHERE a.artifact_id=?""",
            (artifact_id,),
        ).fetchone()
        package = None
        if attestation is not None:
            try:
                manifest = json.loads(attestation["manifest_json"])
                verification = conn.execute(
                    "SELECT detail FROM response_artifact_custody "
                    "WHERE artifact_id=? AND event='artifact_signature_verified' "
                    "ORDER BY sequence LIMIT 1",
                    (artifact_id,),
                ).fetchone()
                manifest_digest = hashlib.sha256(store.canonical(manifest).encode()).hexdigest()
                valid = (
                    verification is not None
                    and json.loads(verification["detail"]).get("manifest_sha256") == manifest_digest
                    and manifest["artifact_id"] == artifact_id
                    and manifest["sha256"] == row["sha256"]
                    and manifest["content_bytes"] == row["content_bytes"]
                    and verify_signature(
                        attestation["public_key"],
                        manifest["authorization"]["signature"],
                        artifact_signing_input(manifest),
                    )
                )
            except (ValueError, KeyError, TypeError, AttributeError):
                valid = False
            if not valid:
                store.custody_event(
                    conn,
                    artifact_id,
                    "integrity_check_failed",
                    "system:artifact-verifier",
                    {"kind": "signed_manifest"},
                )
                conn.commit()
                raise HTTPException(503, "artifact manifest integrity failed; evidence preserved")
            package = {
                "manifest": manifest,
                "content_base64": base64.b64encode(data).decode(),
                "signing_key": signing,
            }
        store.custody_event(
            conn,
            artifact_id,
            "download_requested",
            "analyst:" + analyst,
            {"sha256": row["sha256"], "content_bytes": len(data)},
        )
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    return Response(
        store.canonical(package).encode() if package is not None else data,
        media_type="application/json",
        headers={
            "Content-Disposition": f'attachment; filename="{artifact_id}.json"',
            "X-Content-Type-Options": "nosniff",
            "Cache-Control": "no-store",
        },
    )
