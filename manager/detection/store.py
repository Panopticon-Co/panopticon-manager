"""Alert persistence for the detection worker.

Handlers never write SQL directly (CLAUDE.md); this is the one place the
``alerts`` table is written. ``insert_alert`` is deliberately transaction-free —
the detection worker owns the ``BEGIN IMMEDIATE`` boundary so the alert row and
the ``events.detect_state='done'`` update commit together.
"""

from __future__ import annotations

import json
import sqlite3
from typing import Any

from manager.timeutil import iso_now

_COLUMNS = (
    "alert_id",
    "rule_id",
    "level",
    "severity",
    "host_id",
    "agent_id",
    "event_id",
    "alert_timestamp",
    "created_at",
    "mitre_tactic",
    "mitre_technique",
    "alert_json",
)

_INSERT = (
    f"INSERT OR IGNORE INTO alerts ({', '.join(_COLUMNS)}) "
    f"VALUES ({', '.join('?' * len(_COLUMNS))})"
)


def insert_alert(conn: sqlite3.Connection, alert: Any, *, agent_id: str | None = None) -> bool:
    """Persist one engine ``Alert`` (or its ``to_dict()``), keyed by ``alert_id``.

    Returns ``True`` if a new row was written, ``False`` if this ``alert_id`` was
    already present — the detection engine's ``_stable_alert_id`` is deterministic
    for atomic alerts, so a replayed or crash-recovered event collapses onto its
    existing row instead of producing a duplicate.
    """
    record = alert.to_dict() if hasattr(alert, "to_dict") else alert
    row = (
        record["alert_id"],
        record["rule_id"],
        record.get("level"),
        record.get("severity"),
        record.get("host_id"),
        agent_id,
        record.get("event_id"),
        record.get("timestamp"),
        iso_now(),
        record.get("mitre_tactic"),
        record.get("mitre_technique"),
        json.dumps(record, separators=(",", ":"), default=str),
    )
    return bool(conn.execute(_INSERT, row).rowcount)
