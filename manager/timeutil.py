"""Timestamp formatting shared across the manager. Matches the millisecond-
precision ISO 8601 format panopticon-agent's schema requires for
event.timestamp, so ingested_at and event timestamps are directly comparable
strings.
"""

from __future__ import annotations

from datetime import datetime, timezone


def iso_now() -> str:
    now = datetime.now(timezone.utc)
    return now.strftime("%Y-%m-%dT%H:%M:%S.") + f"{now.microsecond // 1000:03d}Z"
