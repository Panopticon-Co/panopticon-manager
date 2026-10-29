"""Bounded exact-byte investigation evidence and command-bound local custody."""

import base64
import hashlib
import json
import math
import os
from typing import Literal

from fastapi import HTTPException
from pydantic import BaseModel, ConfigDict, Field, StrictInt
from response_engine.artifacts import ArtifactManifest

from manager.timeutil import iso_now
from manager.wire.linux_endpoint import strict_json

MAX_CONTENT = 1024 * 1024
MAX_BODY = 1500 * 1024
MAX_COMMAND_BYTES = 4 * MAX_CONTENT
MAX_COMMAND_COUNT = 8
MAX_GLOBAL_BYTES = 512 * MAX_CONTENT
MAX_GLOBAL_COUNT = 100000
KINDS = {
    "process_snapshot": "COLLECT_PROCESS_INFO",
    "network_snapshot": "COLLECT_NETWORK_CONNECTIONS",
    "file_metadata": "COLLECT_FILE",
}


class ArtifactUpload(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    schema_version: Literal["1"]
    artifact_id: str = Field(pattern=r"^art_[0-9a-f]{64}$")
    command_id: str = Field(min_length=1, max_length=128)
    correlation_id: str = Field(min_length=1, max_length=128)
    host_id: str = Field(min_length=1, max_length=256)
    kind: Literal["process_snapshot", "network_snapshot", "file_metadata", "execution_report"]
    media_type: Literal["application/json"]
    content_bytes: StrictInt = Field(ge=1, le=MAX_CONTENT)
    sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    content_base64: str = Field(min_length=4, max_length=1398104)


class SignedArtifactUpload(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    manifest: ArtifactManifest
    content_base64: str = Field(min_length=4, max_length=1398104)


def canonical(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":"))


def decoded_content(upload):
    try:
        content = base64.b64decode(upload.content_base64, validate=True)
        if (
            len(content) != upload.content_bytes
            or hashlib.sha256(content).hexdigest() != upload.sha256
        ):
            raise ValueError("artifact byte count or SHA-256 disagreement")
        value = strict_json(content.decode("utf-8"))
        if not isinstance(value, (dict, list)):
            raise ValueError("artifact must contain a JSON object or array")
        pending = [(value, 0)]
        while pending:
            item, depth = pending.pop()
            if depth > 32:
                raise ValueError("artifact JSON is too deep")
            if isinstance(item, float) and not math.isfinite(item):
                raise ValueError("artifact JSON contains a non-finite number")
            values = (
                item.values() if isinstance(item, dict) else item if isinstance(item, list) else ()
            )
            pending.extend((child, depth + 1) for child in values)
        return content
    except (ValueError, RecursionError) as exc:
        raise HTTPException(422, "invalid artifact bytes, digest or bounded JSON") from exc


def custody_event(conn, artifact_id, event, actor, detail):
    previous = conn.execute(
        "SELECT sequence,event_hash FROM response_artifact_custody WHERE artifact_id=? "
        "ORDER BY sequence DESC LIMIT 1",
        (artifact_id,),
    ).fetchone()
    record = {
        "artifact_id": artifact_id,
        "sequence": previous["sequence"] + 1 if previous else 1,
        "event": event,
        "actor": actor,
        "occurred_at": iso_now(),
        "detail": detail,
        "previous_hash": previous["event_hash"] if previous else "0" * 64,
    }
    digest = hashlib.sha256(canonical(record).encode()).hexdigest()
    conn.execute(
        "INSERT INTO response_artifact_custody VALUES (?,?,?,?,?,?,?,?)",
        (
            artifact_id,
            record["sequence"],
            event,
            actor,
            record["occurred_at"],
            canonical(detail),
            record["previous_hash"],
            digest,
        ),
    )


def retain(conn, agent_id, command_id, upload, content):
    row = conn.execute(
        "SELECT c.agent_id,c.command_json,c.delivered_at,e.host_id FROM commands c "
        "JOIN enrolled_agents e ON e.agent_id=c.agent_id AND e.revoked_at IS NULL "
        "WHERE c.command_id=?",
        (command_id,),
    ).fetchone()
    if row is None or row["agent_id"] != agent_id:
        raise HTTPException(404, "no owned dispatched command")
    command = json.loads(row["command_json"])
    if row["delivered_at"] is None:
        raise HTTPException(409, "command has not been dispatched")
    if upload.host_id != row["host_id"] or upload.host_id != command.get("host_id"):
        raise HTTPException(403, "artifact host disagrees with current command enrollment")
    if upload.command_id != command_id or upload.correlation_id != command["correlation_id"]:
        raise HTTPException(409, "artifact command correlation disagrees")
    expected = KINDS.get(upload.kind)
    if (expected and command["action"] != expected) or (
        upload.kind == "execution_report" and command["action"] not in KINDS.values()
    ):
        raise HTTPException(422, "artifact kind does not belong to this collection action")
    manifest = upload.model_dump(exclude={"content_base64"})
    manifest_digest = hashlib.sha256(canonical(manifest).encode()).hexdigest()
    prior = conn.execute(
        "SELECT manifest_digest,content FROM response_artifacts WHERE artifact_id=?",
        (upload.artifact_id,),
    ).fetchone()
    if prior:
        if prior["manifest_digest"] != manifest_digest or bytes(prior["content"]) != content:
            raise HTTPException(409, "artifact identifier already binds different evidence")
        # The manifest includes the command. Enrolled command ownership was already rechecked.
        return {"artifact_id": upload.artifact_id, "sha256": upload.sha256, "retained": True}
    totals = conn.execute(
        "SELECT artifacts AS n,content_bytes AS bytes FROM response_artifact_usage WHERE id=1"
    ).fetchone()
    local = conn.execute(
        "SELECT COUNT(*) AS n,COALESCE(SUM(content_bytes),0) AS bytes FROM response_artifacts "
        "WHERE command_id=?",
        (command_id,),
    ).fetchone()
    try:
        quota = int(os.environ.get("PANOPTICON_ARTIFACT_STORAGE_BYTES", MAX_GLOBAL_BYTES))
        if not 1 <= quota <= 16 * 1024**3:
            raise ValueError()
    except ValueError as exc:
        raise HTTPException(503, "artifact storage quota is invalid") from exc
    if (
        local["n"] >= MAX_COMMAND_COUNT
        or local["bytes"] + len(content) > MAX_COMMAND_BYTES
        or totals["n"] >= MAX_GLOBAL_COUNT
        or totals["bytes"] + len(content) > quota
    ):
        raise HTTPException(507, "artifact retention quota reached; existing evidence preserved")
    conn.execute(
        "INSERT INTO response_artifacts VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
        (
            upload.artifact_id,
            agent_id,
            command_id,
            upload.host_id,
            upload.correlation_id,
            upload.kind,
            upload.media_type,
            upload.content_bytes,
            upload.sha256,
            manifest_digest,
            content,
            iso_now(),
        ),
    )
    custody_event(
        conn,
        upload.artifact_id,
        "received",
        "agent:" + agent_id,
        {"command_id": command_id, "sha256": upload.sha256, "content_bytes": len(content)},
    )
    return {"artifact_id": upload.artifact_id, "sha256": upload.sha256, "retained": True}


def custody_rows(conn, artifact_id, *, after=0, limit=200):
    rows = conn.execute(
        "SELECT * FROM response_artifact_custody WHERE artifact_id=? AND sequence>? "
        "ORDER BY sequence LIMIT ?",
        (artifact_id, after, limit),
    ).fetchall()
    return [{**dict(row), "detail": json.loads(row["detail"])} for row in rows]


def retain_signed(conn, agent_id, command_id, upload):
    from manager.artifact_keys import verify_manifest

    manifest = upload.manifest.model_dump()
    previous = conn.execute(
        "SELECT manifest_json,verified_at FROM artifact_manifest_attestations WHERE artifact_id=?",
        (manifest["artifact_id"],),
    ).fetchone()
    if previous and previous["manifest_json"] != canonical(manifest):
        raise HTTPException(409, "artifact identity already binds another signed manifest")
    if (
        previous is None
        and conn.execute(
            "SELECT 1 FROM response_artifacts WHERE artifact_id=?", (manifest["artifact_id"],)
        ).fetchone()
    ):
        raise HTTPException(409, "unsigned legacy evidence cannot be promoted to signed provenance")
    key = verify_manifest(
        conn, agent_id, manifest, admitted_at=previous["verified_at"] if previous else None
    )
    fields = {
        k: v
        for k, v in manifest.items()
        if k not in {"agent_id", "produced_at_unix", "authorization"}
    }
    value = ArtifactUpload.model_validate(
        {**fields, "schema_version": "1", "content_base64": upload.content_base64}
    )
    content = decoded_content(value)
    receipt = retain(conn, agent_id, command_id, value, content)
    if previous:
        return receipt
    conn.execute(
        "INSERT INTO artifact_manifest_attestations VALUES (?,?,?,?,?,?)",
        (
            manifest["artifact_id"],
            agent_id,
            key["key_id"],
            key["key_version"],
            canonical(manifest),
            iso_now(),
        ),
    )
    for event, actor, detail in (
        (
            "artifact_produced",
            "agent:" + agent_id,
            {"produced_at_unix": manifest["produced_at_unix"], "time_source": "endpoint_claim"},
        ),
        ("artifact_transferred", "system:artifact-store", {"content_bytes": len(content)}),
        (
            "artifact_signature_verified",
            "system:artifact-verifier",
            {"key_id": key["key_id"], "key_version": key["key_version"]},
        ),
        ("artifact_hash_verified", "system:artifact-verifier", {"sha256": manifest["sha256"]}),
    ):
        custody_event(conn, manifest["artifact_id"], event, actor, detail)
    return receipt


def manifests(conn, command_id, *, full_history=False):
    rows = conn.execute(
        "SELECT artifact_id,kind,media_type,content_bytes,sha256,received_at "
        "FROM response_artifacts WHERE command_id=? ORDER BY received_at,artifact_id",
        (command_id,),
    ).fetchall()
    result = []
    for row in rows:
        item = dict(row)
        from manager.artifact_keys import retained_status

        item["signing"] = retained_status(conn, row["artifact_id"])
        head = conn.execute(
            "SELECT sequence,event_hash FROM response_artifact_custody WHERE artifact_id=? "
            "ORDER BY sequence DESC LIMIT 1",
            (row["artifact_id"],),
        ).fetchone()
        item["custody_count"] = head["sequence"] if head else 0
        item["custody_head"] = head["event_hash"] if head else None
        item["custody"] = custody_rows(
            conn, row["artifact_id"], limit=item["custody_count"] if full_history else 20
        )
        item["custody_truncated"] = len(item["custody"]) < item["custody_count"]
        result.append(item)
    return result
