"""POST /api/v2/linux-endpoint/records: authenticated Linux endpoint record 1.0 ingest.

Separate from the Windows canonical endpoint route on purpose (docs/adr/007-linux-endpoint.md):
the Linux wire contract is its own schema, validated here against the contracts repository's
``schema/linux-endpoint/1.0.schema.json``. Every record is validated individually; one bad record
rejects that line and not the batch. The response acknowledges per stream (``acked_through_seq``),
which is the only thing a sensor may use to discard its durable log.
"""

from __future__ import annotations

import hashlib
import json

from fastapi import APIRouter, Header, HTTPException, Request

from manager import db, linux_endpoint_store
from manager.auth import require_agent_token
from manager.timeutil import iso_now
from manager.wire import linux_endpoint as wire

router = APIRouter()

MAX_BATCH_RECORDS = 1000
MAX_BATCH_BYTES = 8 * 1024 * 1024
MAX_RECORD_BYTES = 1024 * 1024
PROTOCOL = "linux-endpoint/1.0"


@router.post("/api/v2/linux-endpoint/records")
async def records(
    request: Request,
    x_panopticon_agent_id: str = Header(...),
    x_panopticon_batch_id: str = Header(...),
    x_panopticon_protocol: str = Header(...),
    authorization: str | None = Header(default=None),
) -> dict:
    require_agent_token(x_panopticon_agent_id, authorization)
    if x_panopticon_protocol != PROTOCOL:
        raise HTTPException(422, f"protocol {PROTOCOL} required")
    if request.headers.get("content-type", "").split(";")[0] != "application/x-ndjson":
        raise HTTPException(422, "Content-Type must be application/x-ndjson")
    if not x_panopticon_batch_id or len(x_panopticon_batch_id) > 128:
        raise HTTPException(422, "invalid batch identifier")

    body = bytearray()
    async for chunk in request.stream():
        body.extend(chunk)
        if len(body) > MAX_BATCH_BYTES:
            raise HTTPException(413, f"batch exceeds {MAX_BATCH_BYTES} bytes")
    try:
        lines = [line for line in body.decode("utf-8").split("\n") if line.strip()]
    except UnicodeDecodeError as error:
        raise HTTPException(422, "batch is not UTF-8") from error
    if not lines or len(lines) > MAX_BATCH_RECORDS:
        raise HTTPException(413, f"batch must contain 1 to {MAX_BATCH_RECORDS} records")

    conn = db.connect()
    linux_endpoint_store.ensure_schema(conn)
    enrolled = conn.execute(
        "SELECT host_id FROM enrolled_agents WHERE agent_id=? AND revoked_at IS NULL",
        (x_panopticon_agent_id,),
    ).fetchone()
    if enrolled is None:
        raise HTTPException(401, "enrolled agent unavailable")

    rejected: list[dict] = []
    valid: list[linux_endpoint_store.StoredRecord] = []
    for number, line in enumerate(lines, 1):
        raw = None
        try:
            if len(line.encode("utf-8")) > MAX_RECORD_BYTES:
                raise ValueError("record exceeds 1 MiB")
            raw = wire.strict_json(line)
        except (ValueError, RecursionError) as error:
            rejected.append({"line": number, "record_id": None, "reason": "json_invalid",
                             "detail": str(error)[:512]})
            continue
        problem = wire.first_error(raw)
        record_id = raw.get("id") if isinstance(raw, dict) else None
        if problem is not None:
            rejected.append({"line": number, "record_id": record_id, "reason": "schema_invalid",
                             "detail": problem})
            continue
        if raw["id"] != wire.expected_id(raw):
            rejected.append({"line": number, "record_id": record_id, "reason": "id_mismatch",
                             "detail": "id is not derived from sensor, boot and seq"})
            continue
        if raw["host"]["id"] != enrolled["host_id"]:
            # Whole-request failure: a record naming another host is an identity violation, not a
            # formatting error, and must never be acknowledged.
            raise HTTPException(403, "record host disagrees with the authenticated enrollment")
        digest = hashlib.sha256(line.encode("utf-8")).hexdigest()
        valid.append(linux_endpoint_store.StoredRecord(raw, digest, line))

    now = iso_now()
    conn.execute("BEGIN IMMEDIATE")
    try:
        result = linux_endpoint_store.store(conn, x_panopticon_agent_id, valid, now)
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    for conflict in result["conflicts"]:
        rejected.append({"line": None, "record_id": conflict, "reason": "id_conflict",
                         "detail": "a different record already holds this id or sequence slot"})
    return {
        "batch_id": x_panopticon_batch_id,
        "received": len(lines),
        "accepted": result["accepted"],
        "duplicates": result["duplicates"],
        "rejected": rejected,
        "streams": result["streams"],
        "server_time": now,
    }


@router.get("/api/v2/linux-endpoint/hosts/{host_id}/health")
def host_health(host_id: str, x_panopticon_agent_id: str = Header(...),
                authorization: str | None = Header(default=None)) -> dict:
    """The latest health and coverage record a host reported, for the agent itself to read back."""
    require_agent_token(x_panopticon_agent_id, authorization)
    conn = db.connect()
    linux_endpoint_store.ensure_schema(conn)
    enrolled = conn.execute(
        "SELECT host_id FROM enrolled_agents WHERE agent_id=? AND revoked_at IS NULL",
        (x_panopticon_agent_id,),
    ).fetchone()
    if enrolled is None or enrolled["host_id"] != host_id:
        raise HTTPException(403, "an agent may read only its own host")
    row = conn.execute(
        "SELECT record_id, event_time, received_at, health_json FROM linux_endpoint_health "
        "WHERE host_id=?",
        (host_id,),
    ).fetchone()
    if row is None:
        raise HTTPException(404, "no health record received")
    return {"host_id": host_id, "record_id": row["record_id"], "time": row["event_time"],
            "received_at": row["received_at"], "health": json.loads(row["health_json"])}
