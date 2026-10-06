"""Authenticated, host-bound canonical record ingestion with per-record ACKs."""

from __future__ import annotations

import hashlib
import json

from fastapi import APIRouter, Header, HTTPException, Query, Request, Response
from pydantic import ValidationError

from manager import db, endpoint_freshness, process_snapshots
from manager.auth import require_agent_token
from manager.endpoint_state import observe_generation, project_state, projection_status
from manager.timeutil import iso_now
from manager.wire.endpoint import EndpointRecord

router = APIRouter()


def strict_json(line: str):
    def pairs(values):
        result = {}
        for key, value in values:
            if key in result:
                raise ValueError("duplicate JSON key")
            result[key] = value
        return result

    def constant(value):
        raise ValueError("non-finite JSON constant")

    return json.loads(line, object_pairs_hook=pairs, parse_constant=constant)


@router.post("/api/v2/endpoint/records")
async def records(
    request: Request,
    x_panopticon_agent_id: str = Header(...),
    x_panopticon_batch_id: str = Header(...),
    x_panopticon_protocol: str = Header(...),
    authorization: str | None = Header(default=None),
    x_panopticon_freshness_nonce: str | None = Header(default=None),
    x_panopticon_capture_context: str | None = Header(default=None),
) -> dict:
    require_agent_token(x_panopticon_agent_id, authorization)
    if (
        x_panopticon_protocol != "2"
        or request.headers.get("content-type", "").split(";")[0] != "application/x-ndjson"
    ):
        raise HTTPException(422, "canonical endpoint protocol 2/NDJSON required")
    if not x_panopticon_batch_id or len(x_panopticon_batch_id) > 128:
        raise HTTPException(422, "invalid batch identifier")
    body = bytearray()
    async for chunk in request.stream():
        body.extend(chunk)
        if len(body) > 8 * 1024 * 1024:
            raise HTTPException(413, "batch exceeds 8 MiB")
    try:
        lines = [line for line in body.decode("utf-8").split("\n") if line.strip()]
    except UnicodeDecodeError as error:
        raise HTTPException(422, "batch is not UTF-8") from error
    if not lines or len(lines) > 1000:
        raise HTTPException(413, "canonical batch must contain 1 to 1000 records")
    conn = db.connect()
    enrolled = conn.execute(
        "SELECT host_id FROM enrolled_agents WHERE agent_id=? AND revoked_at IS NULL",
        (x_panopticon_agent_id,),
    ).fetchone()
    if enrolled is None:
        raise HTTPException(401, "enrolled agent unavailable")
    rejected = []
    valid = []
    for number, line in enumerate(lines, 1):
        raw = None
        try:
            if len(line.encode("utf-8")) > 1024 * 1024:
                raise ValueError("endpoint record exceeds 1 MiB")
            raw = strict_json(line)
            claimed = raw.get("endpoint") if isinstance(raw, dict) else None
            if isinstance(claimed, dict) and (
                claimed.get("agent_id") != x_panopticon_agent_id
                or claimed.get("host_id") != enrolled["host_id"]
            ):
                raise HTTPException(
                    403, "canonical endpoint identity disagrees with authenticated enrollment"
                )
            record = EndpointRecord.model_validate(raw)
            if (
                record.endpoint.agent_id != x_panopticon_agent_id
                or record.endpoint.host_id != enrolled["host_id"]
            ):
                # Whole-request authorization failure must never retire a row.
                raise HTTPException(
                    403, "canonical endpoint identity disagrees with authenticated enrollment"
                )
            valid.append((record, line))
        except (ValueError, RecursionError) as error:
            rejected.append(
                {
                    "line": number,
                    "event_id": raw.get("record_id") if isinstance(raw, dict) else None,
                    "reason": "schema_invalid"
                    if isinstance(error, ValidationError)
                    else "json_invalid",
                    "detail": str(error)[:4096],
                }
            )
    accepted = duplicates = capture_age_records = 0
    conn.execute("BEGIN IMMEDIATE")
    try:
        proof = endpoint_freshness.consume(
            conn, x_panopticon_agent_id, x_panopticon_freshness_nonce, x_panopticon_capture_context
        )
        for record, line in valid:
            fingerprint = hashlib.sha256(line.encode()).hexdigest()
            existing = conn.execute(
                "SELECT payload_digest FROM endpoint_records WHERE agent_id=? AND record_id=?",
                (x_panopticon_agent_id, record.record_id),
            ).fetchone()
            if existing is not None:
                if existing["payload_digest"] != fingerprint:
                    raise HTTPException(
                        409, "record identity collision; existing evidence retained"
                    )
                duplicates += 1
                continue
            active = observe_generation(conn, record)
            if active is None:
                active = conn.execute(
                    "SELECT * FROM endpoint_active_streams WHERE agent_id=?",
                    (record.endpoint.agent_id,),
                ).fetchone()
            conn.execute(
                "INSERT INTO endpoint_records(agent_id,host_id,record_id,kind,category,"
                "observed_at,ingested_at,payload_digest,raw_json) VALUES (?,?,?,?,?,?,?,?,?)",
                (
                    record.endpoint.agent_id,
                    record.endpoint.host_id,
                    record.record_id,
                    record.kind,
                    record.category,
                    record.observed_at,
                    iso_now(),
                    fingerprint,
                    line,
                ),
            )
            accepted += 1
            process_snapshots.index_record(conn, strict_json(line))
            capture_age_records += bool(endpoint_freshness.record_age(conn, record, proof))
            project_state(conn, record, line, active)
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    return {
        "batch_id": x_panopticon_batch_id,
        "received": len(lines),
        "accepted": accepted,
        "duplicates": duplicates,
        "rejected": rejected,
        "server_time": iso_now(),
        "min_next_interval_ms": None,
        "capture_age_records": capture_age_records,
    }


@router.get("/api/v2/endpoint/{agent_id}/latest")
def latest(agent_id: str, authorization: str | None = Header(default=None)) -> dict:
    require_agent_token(agent_id, authorization)
    rows = (
        db.connect()
        .execute(
            "SELECT * FROM endpoint_latest WHERE agent_id=? ORDER BY kind,category",
            (agent_id,),
        )
        .fetchall()
    )
    active = (
        db.connect()
        .execute("SELECT * FROM endpoint_active_streams WHERE agent_id=?", (agent_id,))
        .fetchone()
    )
    return {
        "agent_id": agent_id,
        "records": [json.loads(row["raw_json"]) for row in rows],
        "projection_status": [
            {
                **projection_status(row, active),
                **endpoint_freshness.status(db.connect(), agent_id, row["record_id"]),
            }
            for row in rows
        ],
    }


@router.get("/api/v2/endpoint/{agent_id}/records/{record_id}")
def retained_record(
    agent_id: str, record_id: str, authorization: str | None = Header(default=None)
) -> Response:
    """Return one original retained body, without latest-category collapse."""
    require_agent_token(agent_id, authorization)
    row = db.connect().execute(
        "SELECT raw_json,payload_digest FROM endpoint_records WHERE agent_id=? AND record_id=?",
        (agent_id, record_id),
    ).fetchone()
    if row is None:
        raise HTTPException(404, "endpoint record not retained")
    return Response(
        content=row["raw_json"], media_type="application/json",
        headers={"X-Panopticon-Record-Digest": row["payload_digest"], "Cache-Control": "no-store"},
    )


@router.post("/api/v2/endpoint/freshness-challenge")
def freshness_challenge(
    x_panopticon_agent_id: str = Header(...), authorization: str | None = Header(default=None)
) -> dict:
    require_agent_token(x_panopticon_agent_id, authorization)
    return endpoint_freshness.issue(db.connect(), x_panopticon_agent_id)


@router.get("/api/v2/endpoint/{agent_id}/process-snapshots/{record_id}")
def process_snapshot(
    agent_id: str, record_id: str, authorization: str | None = Header(default=None)
) -> dict:
    require_agent_token(agent_id, authorization)
    return process_snapshots.overview(db.connect(), agent_id, record_id)


@router.get("/api/v2/endpoint/{agent_id}/process-captures/{capture_id}")
def process_capture(
    agent_id: str, capture_id: str, after: str | None = None,
    limit: int = Query(default=100, ge=1, le=256),
    authorization: str | None = Header(default=None),
) -> dict:
    require_agent_token(agent_id, authorization)
    return process_snapshots.capture(db.connect(), agent_id, capture_id, after, limit)


@router.get("/api/v2/endpoint/{agent_id}/process-snapshots/{record_id}/pages/{index}")
def process_snapshot_page(
    agent_id: str, record_id: str, index: int, authorization: str | None = Header(default=None)
) -> dict:
    require_agent_token(agent_id, authorization)
    manifest = process_snapshots.load_manifest(db.connect(), agent_id, record_id)
    page = process_snapshots.load_page(db.connect(), agent_id, manifest, index)
    if page is None:
        raise HTTPException(404, "process page not retained")
    return {
        "record": page,
        "scope": "one retained page; snapshot completeness requires manifest verification",
    }


@router.get("/api/v2/endpoint/{agent_id}/process-captures/{capture_id}/records/{record_id}")
def process_capture_record(
    agent_id: str, capture_id: str, record_id: str,
    authorization: str | None = Header(default=None),
) -> dict:
    require_agent_token(agent_id, authorization)
    return process_snapshots.capture_record(db.connect(), agent_id, capture_id, record_id)
