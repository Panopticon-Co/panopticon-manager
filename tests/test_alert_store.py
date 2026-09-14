"""Alert persistence — manager/detection/store.py.

The detection engine assigns each atomic alert a deterministic
``ALT-<sha1[:8]>`` id (see ``panopticon_detection/alerting/alert.py``,
``_stable_alert_id``),
so re-processing the same event after a crash produces the same id. ``INSERT OR
IGNORE`` on that id is what makes the worker's claim/lease loop safe to retry.
"""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import manager.vendor_path  # noqa: F401  (sys.path side effect before engine import)
from manager import migrations
from manager.detection.store import insert_alert
from panopticon_detection.alerting.alert import Alert


def _db(path: Path) -> sqlite3.Connection:
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    migrations.migrate(conn)
    return conn


def _alert() -> Alert:
    return Alert(
        alert_id="ALT-DEADBEEF",
        rule_id="DET-PROC-008",
        title="System Privileges and Account Discovery via Whoami",
        description="whoami /priv",
        level=7,
        severity="medium",
        confidence=0.8,
        host_id="OFFICER-WIN11-LAB",
        timestamp="2026-08-31T12:00:00.000Z",
        event_id="evt_" + "a" * 64,
        evidence={"process.name": "whoami.exe", "process.command_line": "whoami /priv"},
        mitre_tactic="Discovery",
        mitre_technique="T1033",
    )


def test_insert_alert_writes_one_row(tmp_path: Path) -> None:
    conn = _db(tmp_path / "p.db")

    assert insert_alert(conn, _alert(), agent_id="agent-1") is True
    conn.commit()

    row = conn.execute("SELECT * FROM alerts").fetchone()
    assert row["alert_id"] == "ALT-DEADBEEF"
    assert row["rule_id"] == "DET-PROC-008"
    assert row["agent_id"] == "agent-1"
    assert row["event_id"] == "evt_" + "a" * 64
    assert row["alert_timestamp"] == "2026-08-31T12:00:00.000Z"
    assert row["mitre_technique"] == "T1033"
    assert json.loads(row["alert_json"])["evidence"]["process.name"] == "whoami.exe"


def test_insert_alert_is_idempotent_on_alert_id(tmp_path: Path) -> None:
    conn = _db(tmp_path / "p.db")

    assert insert_alert(conn, _alert(), agent_id="agent-1") is True
    assert insert_alert(conn, _alert(), agent_id="agent-2") is False  # same alert_id
    conn.commit()

    assert conn.execute("SELECT COUNT(*) AS c FROM alerts").fetchone()["c"] == 1


def test_insert_alert_accepts_plain_dict(tmp_path: Path) -> None:
    conn = _db(tmp_path / "p.db")

    assert insert_alert(conn, _alert().to_dict()) is True
    conn.commit()

    assert conn.execute("SELECT COUNT(*) AS c FROM alerts").fetchone()["c"] == 1
