"""Timestamp formatting shared across the manager. Matches the millisecond-
precision ISO 8601 format panopticon-agent's schema requires for
event.timestamp, so ingested_at and event timestamps are directly comparable
strings.
"""

from __future__ import annotations

from datetime import datetime, timezone


def iso_at(moment: datetime) -> str:
    """Format a datetime as millisecond-precision ISO 8601 (``...mmmZ``)."""
    return moment.strftime("%Y-%m-%dT%H:%M:%S.") + f"{moment.microsecond // 1000:03d}Z"


def iso_now() -> str:
    return iso_at(datetime.now(timezone.utc))
