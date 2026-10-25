"""Incident persistence -- manager/detection/store.py ``upsert_incident``.

CONTRACT.md §5: an incident alert (``incident_id`` set) upserts ``incidents``;
``revision`` only moves forward; the analyst's ``status`` is never overwritten
by the engine; ``incident_alerts`` links the revision alert and every stage
alert the manager holds; ``incident_audit`` records opened/revised; replaying
the same alerts adds zero rows anywhere.
"""

from __future__ import annotations

import json
import sqlite3

from manager import migrations
from manager.detection.store import (
    SYSTEM_ACTOR,
    insert_alert,
    set_incident_status,
    upsert_incident,
)

_INC = "INC-ABCDEF0123"


def _conn() -> sqlite3.Connection:
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys=ON")
    migrations.migrate(conn)
    return conn


def _stage_alert(alert_id: str, rule_id: str, ts: str, source: str = "rule") -> dict:
    return {
        "alert_id": alert_id,
        "rule_id": rule_id,
        "level": 12,
        "severity": "high",
        "confidence": 0.8,
        "host_id": "WS-1",
        "timestamp": ts,
        "event_id": "evt_" + alert_id,
        "evidence": {},
        "detection_source": source,
        "incident_id": None,
    }


def _incident_alert(revision: int, stages: list[tuple[str | None, str, str]], tactics) -> dict:
    return {
        "alert_id": f"{_INC}-R{revision}",
        "rule_id": "PROV-CAMPAIGN",
        "title": "Incident",
        "level": 12 + revision,
        "severity": "critical" if revision > 1 else "high",
        "confidence": 0.7,
        "host_id": "WS-1",
        "timestamp": stages[-1][2],
        "event_id": "evt_x",
        "detection_source": "correlation",
        "incident_id": _INC,
        "active_response": None,
        "evidence": {
            "incident_id": _INC,
            "revision": revision,
            "stage_count": len(stages),
            "stages": [
                {"time": ts, "rule_id": rule, "alert_id": alert_id, "process": "p.exe"}
                for alert_id, rule, ts in stages
            ],
            "tactics_covered": tactics,
            "root_cause_process": "winword.exe",
            "root_pid": 3000,
            "incident_score": 0.5 + 0.1 * revision,
            "causal_path": ["winword.exe", "powershell.exe"],
            "why": ["because"],
        },
    }


def _counts(conn: sqlite3.Connection) -> dict[str, int]:
    return {
        table: conn.execute(f"SELECT COUNT(*) AS c FROM {table}").fetchone()["c"]
        for table in ("alerts", "incidents", "incident_alerts", "incident_audit")
    }


def _persist(conn: sqlite3.Connection, alert: dict) -> str | None:
    insert_alert(conn, alert, agent_id="agent-1")
    return upsert_incident(conn, alert, agent_id="agent-1")


_S1 = ("ALT-1", "DET-PROC-001", "2026-09-15T09:00:01.000Z")
_S2 = ("ALT-2", "DET-NET-007", "2026-09-15T09:00:05.000Z")
_S3 = ("ALT-3", "DET-PERS-001", "2026-09-15T09:00:09.000Z")


def _seed_stages(conn: sqlite3.Connection, *stages) -> None:
    for alert_id, rule, ts in stages:
        insert_alert(conn, _stage_alert(alert_id, rule, ts), agent_id="agent-1")


def test_insert_alert_stores_detection_source_and_incident_id() -> None:
    conn = _conn()
    _seed_stages(conn, _S1)
    insert_alert(conn, _incident_alert(1, [_S1], ["Execution"]), agent_id="agent-1")
    rows = {
        r["alert_id"]: (r["detection_source"], r["incident_id"])
        for r in conn.execute("SELECT alert_id, detection_source, incident_id FROM alerts")
    }
    assert rows == {"ALT-1": ("rule", None), f"{_INC}-R1": ("correlation", _INC)}


def test_non_incident_alert_is_not_an_incident() -> None:
    conn = _conn()
    assert upsert_incident(conn, _stage_alert("ALT-1", "DET-PROC-001", _S1[2])) is None
    assert _counts(conn)["incidents"] == 0


def test_open_links_revision_and_existing_stage_alerts_and_audits() -> None:
    conn = _conn()
    _seed_stages(conn, _S1, _S2)
    # A suppressed stage (alert_id null) and one the manager never stored.
    stages = [_S1, _S2, (None, "DET-X", _S2[2]), ("ALT-MISSING", "DET-Y", _S2[2])]
    assert _persist(conn, _incident_alert(1, stages, ["Execution", "C2"])) == "opened"

    inc = conn.execute("SELECT * FROM incidents").fetchone()
    assert inc["incident_id"] == _INC
    assert inc["status"] == "open"
    assert inc["revision"] == 1
    assert inc["latest_alert_id"] == f"{_INC}-R1"
    assert inc["host_id"] == "WS-1" and inc["agent_id"] == "agent-1"
    assert json.loads(inc["tactics_json"]) == ["Execution", "C2"]
    assert inc["root_process"] == "winword.exe" and inc["root_pid"] == 3000
    assert inc["stage_count"] == 4
    assert inc["first_seen"] == _S1[2] and inc["last_seen"] == _S2[2]
    assert json.loads(inc["incident_json"])["causal_path"] == ["winword.exe", "powershell.exe"]

    links = {
        (r["alert_id"], r["role"]) for r in conn.execute("SELECT * FROM incident_alerts")
    }
    assert links == {(f"{_INC}-R1", "revision"), ("ALT-1", "stage"), ("ALT-2", "stage")}

    audit = conn.execute("SELECT event, actor FROM incident_audit").fetchall()
    assert [(a["event"], a["actor"]) for a in audit] == [("opened", SYSTEM_ACTOR)]


def test_revision_moves_forward_and_never_back() -> None:
    conn = _conn()
    _seed_stages(conn, _S1, _S2, _S3)
    r1 = _incident_alert(1, [_S1, _S2], ["Execution", "C2"])
    r2 = _incident_alert(2, [_S1, _S2, _S3], ["Execution", "C2", "Persistence"])
    assert _persist(conn, r1) == "opened"
    assert _persist(conn, r2) == "revised"

    inc = conn.execute("SELECT * FROM incidents").fetchone()
    assert inc["revision"] == 2
    assert inc["latest_alert_id"] == f"{_INC}-R2"
    assert inc["severity"] == "critical"
    assert inc["last_seen"] == _S3[2]
    assert json.loads(inc["tactics_json"]) == ["Execution", "C2", "Persistence"]

    # A late/replayed R1 must not roll the incident back.
    before = _counts(conn)
    assert upsert_incident(conn, r1, agent_id="agent-1") == "unchanged"
    inc = conn.execute("SELECT revision, latest_alert_id, severity FROM incidents").fetchone()
    assert (inc["revision"], inc["latest_alert_id"], inc["severity"]) == (
        2,
        f"{_INC}-R2",
        "critical",
    )
    assert _counts(conn) == before
    events = [r["event"] for r in conn.execute("SELECT event FROM incident_audit")]
    assert sorted(events) == ["opened", "revised"]


def test_replaying_the_same_alerts_adds_zero_rows() -> None:
    conn = _conn()
    _seed_stages(conn, _S1, _S2, _S3)
    r1 = _incident_alert(1, [_S1, _S2], ["Execution", "C2"])
    r2 = _incident_alert(2, [_S1, _S2, _S3], ["Execution", "C2", "Persistence"])
    for alert in (r1, r2):
        _persist(conn, alert)
    before = _counts(conn)
    for alert in (r1, r2):
        assert _persist(conn, alert) == "unchanged"
    _seed_stages(conn, _S1, _S2, _S3)
    assert _counts(conn) == before


def test_engine_revision_never_overwrites_analyst_status() -> None:
    conn = _conn()
    _seed_stages(conn, _S1, _S2, _S3)
    _persist(conn, _incident_alert(1, [_S1, _S2], ["Execution", "C2"]))
    assert set_incident_status(
        conn, _INC, "investigating", actor="analyst:alice", note="looking"
    )
    _persist(conn, _incident_alert(2, [_S1, _S2, _S3], ["Execution", "C2", "Persistence"]))
    inc = conn.execute("SELECT status, revision FROM incidents").fetchone()
    assert (inc["status"], inc["revision"]) == ("investigating", 2)
    audit = conn.execute(
        "SELECT event, actor, detail FROM incident_audit WHERE event = 'status_changed'"
    ).fetchone()
    assert audit["actor"] == "analyst:alice"
    assert json.loads(audit["detail"]) == {"from": "open", "to": "investigating", "note": "looking"}


def test_set_status_unknown_incident_returns_false() -> None:
    conn = _conn()
    assert set_incident_status(conn, "INC-NOPE", "resolved", actor="analyst:a", note=None) is False
