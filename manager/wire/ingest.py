"""Request/response shapes for POST /api/v1/ingest — see
docs/adr/002-wire-protocol-ack-semantics.md.
"""

from __future__ import annotations

from datetime import datetime
from typing import Literal, Optional

from pydantic import BaseModel


class EventRejection(BaseModel):
    line: int
    event_id: Optional[str] = None
    reason: Literal["schema_invalid", "unsupported_schema_version", "json_invalid"]
    detail: str


class IngestResponse(BaseModel):
    batch_id: str
    received: int
    accepted: int
    duplicates: int
    rejected: list[EventRejection]
    server_time: datetime
    min_next_interval_ms: Optional[int] = None
