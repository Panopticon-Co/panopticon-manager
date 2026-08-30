"""POST /api/v1/ingest — see docs/adr/002-wire-protocol-ack-semantics.md.

Phase 1 tracer bullet: no auth (agent identity is trusted from the header
as-is), no batch-id idempotency table (nothing retries yet), no 429
backpressure. Event-level dedup (event_id PRIMARY KEY -> INSERT OR IGNORE)
is already real, since it's needed the moment two batches ever overlap.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone

from fastapi import APIRouter, Header, HTTPException, Request

from manager import db
from manager.timeutil import iso_now
from manager.wire.ingest import EventRejection, IngestResponse
from manager.wire.telemetry import TelemetryEvent

router = APIRouter()

MAX_BATCH_EVENTS = 1000
MAX_BATCH_BYTES = 8 * 1024 * 1024
CLOCK_SKEW_THRESHOLD_SECONDS = 24 * 3600
_SUPPORTED_SCHEMA_VERSIONS = ("0.1", "0.2", "0.3")


def _event_id_of(raw: object) -> str | None:
    if isinstance(raw, dict):
        event = raw.get("event")
        if isinstance(event, dict):
            value = event.get("id")
            if isinstance(value, str):
                return value
    return None


def is_clock_skewed(event_timestamp: str, now: datetime) -> bool:
    """True if event_timestamp is more than 24h away from ``now`` in either
    direction. A wrong endpoint clock must never cost telemetry — the event
    is still accepted, just flagged (see docs/adr/002)."""
    event_time = datetime.strptime(event_timestamp, "%Y-%m-%dT%H:%M:%S.%fZ").replace(
        tzinfo=timezone.utc
    )
    return abs((now - event_time).total_seconds()) > CLOCK_SKEW_THRESHOLD_SECONDS


@router.post("/api/v1/ingest", response_model=IngestResponse)
async def ingest(
    request: Request,
    x_panopticon_batch_id: str = Header(...),
    x_panopticon_agent_id: str = Header(...),
    x_panopticon_protocol: str = Header(...),
) -> IngestResponse:
    if x_panopticon_protocol != "1":
        detail = f"unsupported protocol {x_panopticon_protocol!r}"
        raise HTTPException(status_code=422, detail=detail)

    content_type = request.headers.get("content-type", "")
    if "application/x-ndjson" not in content_type:
        raise HTTPException(status_code=422, detail="Content-Type must be application/x-ndjson")

    body = await request.body()
    if len(body) > MAX_BATCH_BYTES:
        raise HTTPException(status_code=413, detail=f"body exceeds {MAX_BATCH_BYTES} bytes")

    try:
        text = body.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise HTTPException(status_code=422, detail=f"body is not valid UTF-8: {exc}") from exc

    lines = [line for line in text.split("\n") if line.strip()]
    if len(lines) > MAX_BATCH_EVENTS:
        raise HTTPException(status_code=413, detail=f"batch exceeds {MAX_BATCH_EVENTS} events")

    rejected: list[EventRejection] = []
    accepted_rows: list[tuple] = []
    now = datetime.now(timezone.utc)

    for idx, line in enumerate(lines, start=1):
        try:
            raw = json.loads(line)
        except json.JSONDecodeError as exc:
            rejected.append(EventRejection(line=idx, reason="json_invalid", detail=str(exc)))
            continue

        raw_schema_version = raw.get("schema_version") if isinstance(raw, dict) else None
        if raw_schema_version not in _SUPPORTED_SCHEMA_VERSIONS:
            rejected.append(
                EventRejection(
                    line=idx,
                    event_id=_event_id_of(raw),
                    reason="unsupported_schema_version",
                    detail=f"schema_version {raw_schema_version!r} is not supported",
                )
            )
            continue

        try:
            event = TelemetryEvent.model_validate(raw)
        except Exception as exc:  # pydantic.ValidationError, kept broad for the response detail
            rejected.append(
                EventRejection(
                    line=idx, event_id=_event_id_of(raw), reason="schema_invalid", detail=str(exc)
                )
            )
            continue

        skew = is_clock_skewed(event.event.timestamp, now)

        accepted_rows.append(
            (
                event.event.id,
                x_panopticon_agent_id,
                event.host.id,
                event.event.category,
                event.event.timestamp,
                iso_now(),
                event.schema_version,
                1 if skew else 0,
                line,
            )
        )

    accepted = 0
    duplicates = 0
    if accepted_rows:
        conn = db.connect()
        conn.execute("BEGIN IMMEDIATE")
        try:
            for row in accepted_rows:
                cur = conn.execute(
                    """
                    INSERT OR IGNORE INTO events
                        (event_id, agent_id, host_id, category, event_timestamp,
                         ingested_at, schema_version, clock_skew, raw_json)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    row,
                )
                if cur.rowcount:
                    accepted += 1
                else:
                    duplicates += 1
            conn.commit()
        except Exception:
            conn.rollback()
            raise

    return IngestResponse(
        batch_id=x_panopticon_batch_id,
        received=len(lines),
        accepted=accepted,
        duplicates=duplicates,
        rejected=rejected,
        server_time=now,
        min_next_interval_ms=None,
    )
