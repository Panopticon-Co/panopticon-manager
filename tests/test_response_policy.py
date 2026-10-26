"""Capstone response policy -- manager/detection/response.py (CONTRACT.md §6).

- A disruptive (non-AUTO_SAFE) recommendation from a ``behavioral`` alert is
  recorded REJECTED, never staged for approval.
- A second recommendation for the same host + action + target while the first
  is still open (PENDING, or AUTHORIZED with a non-terminal command) is
  recorded REJECTED ``duplicate of <response_id>`` and produces no command, so
  incident revisions and repeat detections never stack KILL_PROCESS requests.
- A missing start_time_ticks fails closed with a reason that says so.
"""

from __future__ import annotations

import sqlite3
from datetime import datetime, timedelta, timezone

from manager import migrations
from manager.detection import response
from manager.detection.store import insert_alert

_TICKS = 133_500_000_000_000_001


def _conn() -> sqlite3.Connection:
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys=ON")
    migrations.migrate(conn)
    conn.execute(
        "INSERT INTO enrolled_agents (agent_id, host_id, token_digest, enrolled_at, revoked_at) "
        "VALUES ('agent-1', 'WS-1', 'digest', ?, NULL)",
        (datetime.now(timezone.utc).isoformat(),),
    )
    return conn


def _alert(
    alert_id: str,
    action: str | None,
    *,
    source: str = "rule",
    host_id: str = "WS-1",
    pid: int = 4100,
    ticks: int | None = _TICKS,
    path: str | None = None,
) -> dict:
    active_response = None
    if action is not None:
        active_response = {"action": action, "host_id": host_id, "target_pid": pid}
        if ticks is not None:
            active_response["target_start_time_ticks"] = ticks
        if path is not None:
            active_response["target_file"] = path
    return {
        "alert_id": alert_id,
        "rule_id": "DET-TEST",
        "level": 13,
        "severity": "high",
        "host_id": host_id,
        "timestamp": "2026-09-15T09:00:00.000Z",
        "event_id": "evt_" + alert_id,
        "evidence": {},
        "active_response": active_response,
        "detection_source": source,
        "incident_id": None,
    }


def _emit(conn: sqlite3.Connection, alert: dict) -> None:
    """What AlertSink.emit does for a new alert."""
    assert insert_alert(conn, alert, agent_id="agent-1")
    response.on_alert_created(conn, alert)


def _rows(conn: sqlite3.Connection) -> list[sqlite3.Row]:
    return conn.execute(
        "SELECT * FROM response_actions ORDER BY created_at, rowid"
    ).fetchall()


def test_behavioral_disruptive_recommendation_is_record_only() -> None:
    conn = _conn()
    _emit(conn, _alert("ALT-B1", "TERMINATE_PROCESS", source="behavioral"))
    (row,) = _rows(conn)
    assert row["action"] == "KILL_PROCESS"
    assert row["tier"] == "ANALYST_APPROVAL"
    assert row["lifecycle_state"] == "REJECTED"
    assert row["command_id"] is None
    assert "behavioral" in row["decided_reason"]
    assert "record only" in row["decided_reason"]
    assert conn.execute("SELECT COUNT(*) AS c FROM commands").fetchone()["c"] == 0


def test_behavioral_auto_safe_collection_still_runs() -> None:
    conn = _conn()
    _emit(conn, _alert("ALT-B2", "COLLECT_NETWORK_CONNECTIONS", source="behavioral"))
    (row,) = _rows(conn)
    assert row["tier"] == "AUTO_SAFE"
    assert row["lifecycle_state"] == "AUTHORIZED"
    assert row["authorized_by"] == "system:response-engine"


def test_same_rule_alert_is_still_staged_pending() -> None:
    conn = _conn()
    _emit(conn, _alert("ALT-R1", "TERMINATE_PROCESS", source="rule"))
    (row,) = _rows(conn)
    assert (row["action"], row["lifecycle_state"]) == ("KILL_PROCESS", "PENDING")


def test_missing_start_time_ticks_fails_closed_with_a_specific_reason() -> None:
    conn = _conn()
    _emit(conn, _alert("ALT-NT", "TERMINATE_PROCESS", ticks=None))
    (row,) = _rows(conn)
    assert row["lifecycle_state"] == "REJECTED"
    assert row["command_id"] is None
    assert "target_start_time_ticks" in row["decided_reason"]
    assert row["decided_reason"].startswith("fail closed")


def test_second_kill_for_the_same_process_is_a_recorded_duplicate() -> None:
    conn = _conn()
    _emit(conn, _alert("ALT-K1", "TERMINATE_PROCESS"))
    _emit(conn, _alert("ALT-K2", "TERMINATE_PROCESS"))
    first, second = _rows(conn)
    assert first["lifecycle_state"] == "PENDING"
    assert second["lifecycle_state"] == "REJECTED"
    assert second["decided_reason"] == f"duplicate of {first['response_id']}"
    assert second["command_id"] is None


def test_different_target_or_host_is_not_a_duplicate() -> None:
    conn = _conn()
    _emit(conn, _alert("ALT-T1", "TERMINATE_PROCESS", pid=4100))
    _emit(conn, _alert("ALT-T2", "TERMINATE_PROCESS", pid=4200))
    # Same pid but a different incarnation (start_time_ticks): a different process.
    _emit(conn, _alert("ALT-T3", "TERMINATE_PROCESS", pid=4100, ticks=_TICKS + 1))
    _emit(conn, _alert("ALT-T4", "TERMINATE_PROCESS", host_id="WS-2"))
    assert [r["lifecycle_state"] for r in _rows(conn)] == ["PENDING"] * 4


def test_quarantine_duplicates_compare_on_path() -> None:
    conn = _conn()
    _emit(conn, _alert("ALT-Q1", "QUARANTINE_FILE", path="C:\\Users\\a\\x.exe"))
    _emit(conn, _alert("ALT-Q2", "QUARANTINE_FILE", path="C:\\Users\\a\\x.exe"))
    _emit(conn, _alert("ALT-Q3", "QUARANTINE_FILE", path="C:\\Users\\a\\y.exe"))
    states = [(r["lifecycle_state"], r["decided_reason"]) for r in _rows(conn)]
    assert states[0][0] == "PENDING"
    assert states[1][0] == "REJECTED" and states[1][1].startswith("duplicate of ")
    assert states[2][0] == "PENDING"


def test_authorized_action_with_live_command_still_blocks_a_duplicate() -> None:
    conn = _conn()
    _emit(conn, _alert("ALT-A1", "TERMINATE_PROCESS"))
    first = _rows(conn)[0]
    response.authorize_response_action(conn, first["response_id"], actor="analyst:alice")
    conn.execute(
        "UPDATE commands SET lifecycle_state = 'DISPATCHED' WHERE command_id = ?",
        (f"resp-{first['response_id']}",),
    )
    _emit(conn, _alert("ALT-A2", "TERMINATE_PROCESS"))
    second = _rows(conn)[1]
    assert second["decided_reason"] == f"duplicate of {first['response_id']}"
    assert conn.execute("SELECT COUNT(*) AS c FROM commands").fetchone()["c"] == 1


def test_terminal_previous_action_does_not_block_a_new_one() -> None:
    conn = _conn()
    _emit(conn, _alert("ALT-F1", "TERMINATE_PROCESS"))
    first = _rows(conn)[0]
    response.authorize_response_action(conn, first["response_id"], actor="analyst:alice")
    conn.execute(
        "UPDATE commands SET lifecycle_state = 'FAILED' WHERE command_id = ?",
        (f"resp-{first['response_id']}",),
    )
    _emit(conn, _alert("ALT-F2", "TERMINATE_PROCESS"))
    assert _rows(conn)[1]["lifecycle_state"] == "PENDING"

    # An analyst-rejected action is terminal too.
    response.reject_response_action(
        conn, _rows(conn)[1]["response_id"], actor="analyst:alice", reason="benign"
    )
    _emit(conn, _alert("ALT-F3", "TERMINATE_PROCESS"))
    assert _rows(conn)[2]["lifecycle_state"] == "PENDING"


def test_pending_past_its_window_does_not_block() -> None:
    conn = _conn()
    _emit(conn, _alert("ALT-E1", "TERMINATE_PROCESS"))
    stale = (datetime.now(timezone.utc) - timedelta(minutes=30)).isoformat()
    conn.execute("UPDATE response_actions SET created_at = ?", (stale,))
    _emit(conn, _alert("ALT-E2", "TERMINATE_PROCESS"))
    assert _rows(conn)[-1]["lifecycle_state"] == "PENDING"


def test_incident_revisions_do_not_stack_kill_requests() -> None:
    """Even if incident revision alerts carried a recommendation, R2 and R3
    collapse onto R1's open action."""
    conn = _conn()
    for rev in (1, 2, 3):
        alert = _alert(f"INC-1-R{rev}", "TERMINATE_PROCESS", source="correlation")
        alert["incident_id"] = "INC-1"
        _emit(conn, alert)
    rows = _rows(conn)
    assert [r["lifecycle_state"] for r in rows] == ["PENDING", "REJECTED", "REJECTED"]
    assert {r["decided_reason"] for r in rows[1:]} == {f"duplicate of {rows[0]['response_id']}"}
