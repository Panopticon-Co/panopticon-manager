"""Bounded resumable uploads. Callers hold one BEGIN IMMEDIATE transaction."""

import base64
import hashlib
import json
from datetime import datetime, timedelta, timezone
from typing import Literal

from fastapi import HTTPException
from pydantic import BaseModel, ConfigDict, Field
from response_engine.artifacts import ArtifactManifest

from manager import artifact_keys as keys
from manager import response_artifacts as store
from manager.timeutil import iso_at, iso_now

CHUNK_BYTES = 65536
MAX_OPEN = 128
MAX_AGENT_OPEN = 4
SESSION_LIFETIME = timedelta(hours=24)


class Admission(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    schema_version: Literal["1"]
    manifest: ArtifactManifest


class Completion(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    schema_version: Literal["1"]
    manifest_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")


def manifest_digest(manifest):
    return hashlib.sha256(store.canonical(manifest).encode()).hexdigest()


def _request_id(conn, command_id):
    row = conn.execute(
        "SELECT response_id FROM response_actions WHERE command_id=?", (command_id,)
    ).fetchone()
    return row[0] if row else None


def _record(conn, row, event, actor, detail):
    keys.record(
        conn,
        event,
        actor,
        row["host_id"],
        _request_id(conn, row["command_id"]),
        {"artifact_id": row["artifact_id"], "command_id": row["command_id"], **detail},
    )


def progress(manifest, received, expires_at, *, complete=False):
    return {
        "schema_version": "1",
        "artifact_id": manifest["artifact_id"],
        "sha256": manifest["sha256"],
        "manifest_sha256": manifest_digest(manifest),
        "received_bytes": received,
        "chunk_bytes": CHUNK_BYTES,
        "complete": complete,
        "expires_at": None if complete else expires_at,
    }


def expire(conn):
    # At most MAX_OPEN unfinished sessions can exist, so cleanup is bounded.
    rows = conn.execute(
        "SELECT * FROM response_artifact_transfers WHERE state='OPEN' "
        "AND expires_at<=? ORDER BY expires_at LIMIT ?",
        (iso_now(), MAX_OPEN),
    ).fetchall()
    for row in rows:
        hashes = [
            dict(chunk)
            for chunk in conn.execute(
                "SELECT offset,sha256,length(content) AS content_bytes "
                "FROM response_artifact_chunks "
                "WHERE artifact_id=? ORDER BY offset",
                (row["artifact_id"],),
            )
        ]
        _record(
            conn,
            row,
            "artifact_transfer_expired",
            "system:artifact-transfer",
            {
                "received_bytes": row["received_bytes"],
                "partial_chunks": hashes,
                "unverified_partial_bytes_discarded": True,
            },
        )
        conn.execute(
            "DELETE FROM response_artifact_chunks WHERE artifact_id=?", (row["artifact_id"],)
        )
        conn.execute(
            "UPDATE response_artifact_transfers SET state='EXPIRED',received_bytes=0 "
            "WHERE artifact_id=?",
            (row["artifact_id"],),
        )


def _retained(conn, agent_id, command_id, manifest):
    row = conn.execute(
        "SELECT a.content,t.manifest_json FROM response_artifacts a "
        "JOIN artifact_manifest_attestations t ON t.artifact_id=a.artifact_id "
        "WHERE a.artifact_id=?",
        (manifest["artifact_id"],),
    ).fetchone()
    if row is None:
        return None
    if row["manifest_json"] != store.canonical(manifest):
        raise HTTPException(409, "artifact identity already binds another signed manifest")
    value = store.SignedArtifactUpload.model_validate(
        {"manifest": manifest, "content_base64": base64.b64encode(bytes(row["content"])).decode()}
    )
    return store.retain_signed(conn, agent_id, command_id, value)


def _reserve(conn, manifest, *, existing=False):
    usage = conn.execute("SELECT * FROM response_artifact_transfer_usage WHERE id=1").fetchone()
    retained = conn.execute("SELECT * FROM response_artifact_usage WHERE id=1").fetchone()
    agent = conn.execute(
        "SELECT COUNT(*) FROM response_artifact_transfers WHERE agent_id=? AND state='OPEN'",
        (manifest["agent_id"],),
    ).fetchone()[0]
    local = conn.execute(
        """SELECT COUNT(*) AS n,COALESCE(SUM(content_bytes),0) AS bytes FROM (
        SELECT content_bytes FROM response_artifacts WHERE command_id=? UNION ALL
        SELECT content_bytes FROM response_artifact_transfers
            WHERE command_id=? AND state='OPEN')""",
        (manifest["command_id"], manifest["command_id"]),
    ).fetchone()
    if (
        agent >= MAX_AGENT_OPEN
        or usage["open_sessions"] >= MAX_OPEN
        or (not existing and usage["total_sessions"] >= store.MAX_GLOBAL_COUNT)
        or local["n"] >= store.MAX_COMMAND_COUNT
        or local["bytes"] + manifest["content_bytes"] > store.MAX_COMMAND_BYTES
        or retained["artifacts"] + usage["open_sessions"] >= store.MAX_GLOBAL_COUNT
        or retained["content_bytes"] + usage["reserved_bytes"] + manifest["content_bytes"]
        > store.storage_quota()
    ):
        raise HTTPException(507, "artifact transfer budget exhausted; retained evidence preserved")


def admit(conn, agent_id, command_id, request):
    manifest = request.manifest.model_dump()
    store.validate_binding(conn, agent_id, command_id, request.manifest)
    expire(conn)
    prior = conn.execute(
        "SELECT * FROM response_artifact_transfers WHERE artifact_id=?", (manifest["artifact_id"],)
    ).fetchone()
    if prior is not None and prior["manifest_json"] != store.canonical(manifest):
        raise HTTPException(409, "transfer retry identity binds another signed manifest")
    if _retained(conn, agent_id, command_id, manifest):
        return progress(manifest, manifest["content_bytes"], None, complete=True)
    admitted = prior["admitted_at"] if prior is not None and prior["state"] == "OPEN" else None
    keys.verify_manifest(conn, agent_id, manifest, admitted_at=admitted)
    if prior is not None and prior["state"] == "OPEN":
        return progress(manifest, prior["received_bytes"], prior["expires_at"])
    if prior is not None and prior["state"] == "COMPLETE":
        raise HTTPException(503, "completed artifact retention is unavailable")
    if conn.execute(
        "SELECT 1 FROM response_artifacts WHERE artifact_id=?", (manifest["artifact_id"],)
    ).fetchone():
        raise HTTPException(409, "unsigned evidence cannot become signed transfer provenance")
    _reserve(conn, manifest, existing=prior is not None)
    now = iso_now()
    expiry = iso_at(datetime.now(timezone.utc) + SESSION_LIFETIME)
    if prior is None:
        conn.execute(
            """INSERT INTO response_artifact_transfers
            (artifact_id,agent_id,command_id,host_id,manifest_json,manifest_sha256,content_bytes,
                received_bytes,state,admitted_at,expires_at) VALUES (?,?,?,?,?,?,?,0,'OPEN',?,?)""",
            (
                manifest["artifact_id"],
                agent_id,
                command_id,
                manifest["host_id"],
                store.canonical(manifest),
                manifest_digest(manifest),
                manifest["content_bytes"],
                now,
                expiry,
            ),
        )
    else:
        conn.execute(
            "UPDATE response_artifact_transfers SET state='OPEN',received_bytes=0,"
            "admitted_at=?,expires_at=? WHERE artifact_id=?",
            (now, expiry, manifest["artifact_id"]),
        )
    _record(
        conn,
        manifest,
        "artifact_transfer_admitted",
        "agent:" + agent_id,
        {
            "manifest_sha256": manifest_digest(manifest),
            "content_bytes": manifest["content_bytes"],
            "expires_at": expiry,
            "restart_after_expiry": prior is not None,
        },
    )
    return progress(manifest, 0, expiry)


def _load(conn, agent_id, command_id, artifact_id):
    row = conn.execute(
        "SELECT * FROM response_artifact_transfers WHERE artifact_id=? "
        "AND agent_id=? AND command_id=?",
        (artifact_id, agent_id, command_id),
    ).fetchone()
    if row is None:
        raise HTTPException(404, "owned artifact transfer unavailable")
    manifest = ArtifactManifest.model_validate(json.loads(row["manifest_json"]))
    store.validate_binding(conn, agent_id, command_id, manifest)
    keys.verify_manifest(conn, agent_id, manifest.model_dump(), admitted_at=row["admitted_at"])
    if row["state"] == "EXPIRED" or (
        row["state"] == "OPEN" and keys.server_time(row["expires_at"]) <= datetime.now(timezone.utc)
    ):
        raise HTTPException(409, "artifact session expired; readmit the original manifest")
    return row, manifest.model_dump()


def put_chunk(conn, agent_id, command_id, artifact_id, offset, digest, data):
    row, manifest = _load(conn, agent_id, command_id, artifact_id)
    if not data or len(data) > CHUNK_BYTES or hashlib.sha256(data).hexdigest() != digest:
        raise HTTPException(422, "artifact chunk size or digest disagrees")
    expected_length = min(CHUNK_BYTES, manifest["content_bytes"] - offset)
    if (
        offset < 0
        or offset % CHUNK_BYTES != 0
        or expected_length <= 0
        or len(data) != expected_length
    ):
        raise HTTPException(422, "artifact chunk boundary disagrees")
    if row["state"] == "COMPLETE":
        retained = conn.execute(
            "SELECT content FROM response_artifacts WHERE artifact_id=?", (artifact_id,)
        ).fetchone()
        if retained is None or bytes(retained[0])[offset : offset + len(data)] != data:
            raise HTTPException(409, "completed artifact chunk retry disagrees")
        return progress(manifest, manifest["content_bytes"], None, complete=True)
    previous = conn.execute(
        "SELECT sha256,content FROM response_artifact_chunks WHERE artifact_id=? AND offset=?",
        (artifact_id, offset),
    ).fetchone()
    if previous:
        if previous["sha256"] != digest or bytes(previous["content"]) != data:
            raise HTTPException(409, "artifact chunk retry changes accepted bytes")
        return progress(manifest, row["received_bytes"], row["expires_at"])
    if offset != row["received_bytes"]:
        raise HTTPException(409, "artifact chunk is out of order; resume from durable offset")
    conn.execute(
        "INSERT INTO response_artifact_chunks VALUES (?,?,?,?)", (artifact_id, offset, digest, data)
    )
    conn.execute(
        "UPDATE response_artifact_transfers SET received_bytes=? WHERE artifact_id=?",
        (offset + len(data), artifact_id),
    )
    _record(
        conn,
        row,
        "artifact_chunk_transferred",
        "agent:" + agent_id,
        {"offset": offset, "content_bytes": len(data), "chunk_sha256": digest},
    )
    return progress(manifest, offset + len(data), row["expires_at"])


def complete(conn, agent_id, command_id, artifact_id, request):
    row = conn.execute(
        "SELECT manifest_json FROM response_artifact_transfers WHERE artifact_id=?", (artifact_id,)
    ).fetchone()
    # A one-shot upload may already have retained this same manifest.
    if row is None:
        row = conn.execute(
            "SELECT manifest_json FROM artifact_manifest_attestations WHERE artifact_id=?",
            (artifact_id,),
        ).fetchone()
        if row is None:
            raise HTTPException(404, "artifact transfer unavailable")
        manifest = json.loads(row[0])
        if manifest_digest(manifest) != request.manifest_sha256:
            raise HTTPException(409, "artifact completion manifest disagrees")
        return _retained(conn, agent_id, command_id, manifest)
    row, manifest = _load(conn, agent_id, command_id, artifact_id)
    if manifest_digest(manifest) != request.manifest_sha256:
        raise HTTPException(409, "artifact completion manifest disagrees")
    if row["state"] == "COMPLETE":
        receipt = _retained(conn, agent_id, command_id, manifest)
        if receipt is None:
            raise HTTPException(503, "completed artifact retention is unavailable")
        return receipt
    if row["received_bytes"] != manifest["content_bytes"]:
        raise HTTPException(409, "artifact transfer is incomplete")
    content = b"".join(
        bytes(chunk[0])
        for chunk in conn.execute(
            "SELECT content FROM response_artifact_chunks WHERE artifact_id=? ORDER BY offset",
            (artifact_id,),
        )
    )
    # Release this reservation in the same transaction as retention. Any failure
    # rolls back status, quota and chunks together; readers never see half a commit.
    conn.execute(
        "UPDATE response_artifact_transfers SET state='COMPLETE' WHERE artifact_id=?",
        (artifact_id,),
    )
    value = store.SignedArtifactUpload.model_validate(
        {"manifest": manifest, "content_base64": base64.b64encode(content).decode()}
    )
    receipt = store.retain_signed(conn, agent_id, command_id, value, admitted_at=row["admitted_at"])
    conn.execute("DELETE FROM response_artifact_chunks WHERE artifact_id=?", (artifact_id,))
    _record(
        conn,
        row,
        "artifact_transfer_completed",
        "agent:" + agent_id,
        {"content_bytes": len(content), "sha256": manifest["sha256"]},
    )
    return receipt
