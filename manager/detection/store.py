"""Alert and incident persistence for the detection worker.

Handlers never write SQL directly (CLAUDE.md); this is the one place the
``alerts``, ``incidents``, ``incident_alerts`` and ``incident_audit`` tables
are written. Every function here is deliberately transaction-free -- the
caller owns the ``BEGIN IMMEDIATE`` boundary, so (in the detection worker) an
event's alert rows, incident upserts, response staging and its
``events.detect_state='done'`` update commit together (CONTRACT.md §5).
"""

from __future__ import annotations

import json
import sqlite3
from typing import Any
from uuid import uuid4

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
    "detection_source",
    "incident_id",
)

_INSERT = (
    f"INSERT OR IGNORE INTO alerts ({', '.join(_COLUMNS)}) "
    f"VALUES ({', '.join('?' * len(_COLUMNS))})"
)

# The engine's actor identity in incident_audit, distinct from any analyst.
SYSTEM_ACTOR = "system:detection"

INCIDENT_STATUSES = ("open", "investigating", "resolved", "false_positive")


def _record(alert: Any) -> dict:
    return alert.to_dict() if hasattr(alert, "to_dict") else alert


def insert_alert(conn: sqlite3.Connection, alert: Any, *, agent_id: str | None = None) -> bool:
    """Persist one engine ``Alert`` (or its ``to_dict()``), keyed by ``alert_id``.

    Returns ``True`` if a new row was written, ``False`` if this ``alert_id`` was
    already present — the detection engine's alert ids are deterministic (rule
    alerts hash the event, incident alerts carry their revision), so a replayed
    or crash-recovered event collapses onto its existing row instead of
    producing a duplicate.
    """
    record = _record(alert)
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
        record.get("detection_source"),
        record.get("incident_id"),
    )
    return bool(conn.execute(_INSERT, row).rowcount)


def _audit_incident(
    conn: sqlite3.Connection, incident_id: str, event: str, actor: str, detail: Any = None
) -> None:
    conn.execute(
        "INSERT INTO incident_audit (audit_id, incident_id, event, actor, detail, occurred_at) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        (
            str(uuid4()),
            incident_id,
            event,
            actor,
            None if detail is None else json.dumps(detail, separators=(",", ":"), default=str),
            iso_now(),
        ),
    )


def _as_int(value: Any) -> int | None:
    if isinstance(value, bool) or not isinstance(value, int):
        return None
    return value


def _as_float(value: Any) -> float | None:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    return float(value)


def _revision_of(record: dict, evidence: dict) -> int:
    """The incident revision: ``evidence.revision``, else the ``-R<n>`` suffix
    of the alert id. An unreadable revision is 0, which can open an incident
    but never overwrite one holding a real revision."""
    revision = _as_int(evidence.get("revision"))
    if revision is not None:
        return revision
    _, sep, suffix = str(record.get("alert_id") or "").rpartition("-R")
    if sep and suffix.isdigit():
        return int(suffix)
    return 0


def _seen_window(record: dict, evidence: dict) -> tuple[str | None, str | None]:
    times = [
        str(stage["time"])
        for stage in evidence.get("stages") or []
        if isinstance(stage, dict) and stage.get("time")
    ]
    if record.get("timestamp"):
        times.append(str(record["timestamp"]))
    if not times:
        return None, None
    # Engine timestamps are ISO-8601 UTC of one shape, so string order is time order.
    return min(times), max(times)


def _link_members(conn: sqlite3.Connection, incident_id: str, record: dict, evidence: dict) -> None:
    """``incident_alerts`` rows for this revision alert and every stage alert
    the evidence names that the manager actually holds. A stage whose
    ``alert_id`` is null (the detection was suppressed as a repeat) or was
    never persisted is skipped rather than linked to a row that does not
    exist."""
    conn.execute(
        "INSERT OR IGNORE INTO incident_alerts (incident_id, alert_id, role) "
        "VALUES (?, ?, 'revision')",
        (incident_id, record["alert_id"]),
    )
    stage_ids = {
        str(stage["alert_id"])
        for stage in evidence.get("stages") or []
        if isinstance(stage, dict) and stage.get("alert_id")
    }
    for stage_alert_id in sorted(stage_ids):
        if conn.execute(
            "SELECT 1 FROM alerts WHERE alert_id = ?", (stage_alert_id,)
        ).fetchone() is None:
            continue
        conn.execute(
            "INSERT OR IGNORE INTO incident_alerts (incident_id, alert_id, role) "
            "VALUES (?, ?, 'stage')",
            (incident_id, stage_alert_id),
        )


def upsert_incident(
    conn: sqlite3.Connection, alert: Any, *, agent_id: str | None = None
) -> str | None:
    """Fold one incident alert (``incident_id`` set) into ``incidents``.

    Returns ``"opened"``, ``"revised"``, ``"unchanged"`` (an equal or older
    revision: a replay or out-of-order delivery), or ``None`` for an alert that
    is not an incident alert.

    Invariants (CONTRACT.md §5):

    - ``revision`` only moves forward: an equal or older revision never
      overwrites the stored summary or evidence.
    - ``status`` is the analyst's: the engine sets ``open`` when it creates the
      row and never writes it again.
    - Member links are ``INSERT OR IGNORE`` and audit rows are written only on
      a real open or revise, so replaying the same events adds no rows.
    """
    record = _record(alert)
    incident_id = record.get("incident_id")
    if not incident_id:
        return None
    evidence = record.get("evidence")
    if not isinstance(evidence, dict):
        evidence = {}
    revision = _revision_of(record, evidence)
    first_seen, last_seen = _seen_window(record, evidence)
    tactics = list(evidence.get("tactics_covered") or [])
    stages = evidence.get("stages") or []
    stage_count = _as_int(evidence.get("stage_count"))
    if stage_count is None:
        stage_count = len(stages) if isinstance(stages, list) else 0
    summary = (
        record.get("host_id"),
        record.get("severity"),
        _as_int(record.get("level")),
        _as_float(evidence.get("incident_score")),
        _as_float(record.get("confidence")),
        json.dumps(tactics, separators=(",", ":")),
        stage_count,
        evidence.get("root_cause_process"),
        _as_int(evidence.get("root_pid")),
        revision,
        record["alert_id"],
        json.dumps(evidence, separators=(",", ":"), default=str),
    )
    now = iso_now()
    existing = conn.execute(
        "SELECT revision, first_seen, last_seen FROM incidents WHERE incident_id = ?",
        (incident_id,),
    ).fetchone()

    if existing is None:
        conn.execute(
            "INSERT INTO incidents (host_id, severity, level, score, confidence, tactics_json, "
            "stage_count, root_process, root_pid, revision, latest_alert_id, incident_json, "
            "incident_id, agent_id, status, first_seen, last_seen, created_at, updated_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'open', ?, ?, ?, ?)",
            (*summary, incident_id, agent_id, first_seen, last_seen, now, now),
        )
        _link_members(conn, incident_id, record, evidence)
        _audit_incident(
            conn,
            incident_id,
            "opened",
            SYSTEM_ACTOR,
            {"revision": revision, "alert_id": record["alert_id"], "tactics": tactics},
        )
        return "opened"

    # Membership only grows, whatever the revision: an older revision's stages
    # are a subset of a newer one's, so a late or replayed delivery converges.
    _link_members(conn, incident_id, record, evidence)
    previous = int(existing["revision"])
    if revision <= previous:
        return "unchanged"

    merged_first = min([t for t in (existing["first_seen"], first_seen) if t], default=None)
    merged_last = max([t for t in (existing["last_seen"], last_seen) if t], default=None)
    conn.execute(
        "UPDATE incidents SET host_id = ?, severity = ?, level = ?, score = ?, confidence = ?, "
        "tactics_json = ?, stage_count = ?, root_process = ?, root_pid = ?, revision = ?, "
        "latest_alert_id = ?, incident_json = ?, agent_id = COALESCE(agent_id, ?), "
        "first_seen = ?, last_seen = ?, updated_at = ? "
        "WHERE incident_id = ? AND revision < ?",
        (*summary, agent_id, merged_first, merged_last, now, incident_id, revision),
    )
    _audit_incident(
        conn,
        incident_id,
        "revised",
        SYSTEM_ACTOR,
        {
            "from_revision": previous,
            "revision": revision,
            "alert_id": record["alert_id"],
            "tactics": tactics,
        },
    )
    return "revised"


def set_incident_status(
    conn: sqlite3.Connection, incident_id: str, status: str, *, actor: str, note: str | None
) -> bool:
    """Analyst status change, audited with the analyst's identity. Returns
    ``False`` if the incident does not exist. Transaction-free: the router
    owns the transaction."""
    if status not in INCIDENT_STATUSES:
        raise ValueError(f"unknown incident status {status!r}")
    row = conn.execute(
        "SELECT status FROM incidents WHERE incident_id = ?", (incident_id,)
    ).fetchone()
    if row is None:
        return False
    conn.execute(
        "UPDATE incidents SET status = ?, updated_at = ? WHERE incident_id = ?",
        (status, iso_now(), incident_id),
    )
    detail = {"from": row["status"], "to": status, "note": note}
    _audit_incident(conn, incident_id, "status_changed", actor, detail)
    return True
