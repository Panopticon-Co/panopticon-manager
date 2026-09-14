"""manager/detection/factory.py — DetectionRun wired to manager storage.

One hand-built normalized ``whoami /priv`` event through the run must produce
exactly one alert row and one NDJSON line, tagged with the agent id the worker
bound onto the sink.
"""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import manager.vendor_path  # noqa: F401
from manager import migrations
from manager.config import _DEFAULT_RULES_DIR
from manager.detection.factory import build_detection_run

_WHOAMI_EVENT = {
    "schema_version": "0.3",
    "event_id": "evt_" + "a" * 64,
    "timestamp": "2026-08-31T12:00:00.000Z",
    "event_type": "process_create",
    "host_id": "OFFICER-WIN11-LAB",
    "process": {
        "entity_id": "proc_" + "1" * 64,
        "process_guid": "proc_" + "1" * 64,
        "pid": 4321,
        "name": "whoami.exe",
        "executable": "C:\\Windows\\System32\\whoami.exe",
        "command_line": "whoami /priv",
        "user": "LAB\\analyst",
    },
    "parent": {"pid": 1000, "name": "cmd.exe"},
}


def _db(path: Path) -> sqlite3.Connection:
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    migrations.migrate(conn)
    return conn


def test_one_event_one_alert_row_and_one_ndjson_line(tmp_path: Path) -> None:
    conn = _db(tmp_path / "p.db")
    alerts_path = tmp_path / "alerts.ndjson"

    run, sink, writer, _context = build_detection_run(
        conn, alerts_path=alerts_path, rules_dir=_DEFAULT_RULES_DIR
    )
    try:
        sink.agent_id = "officer-agent-007"
        produced = run.process_event(dict(_WHOAMI_EVENT))
        conn.commit()
    finally:
        writer.close()

    assert [a.rule_id for a in produced] == ["DET-PROC-008"]

    rows = conn.execute("SELECT * FROM alerts").fetchall()
    assert len(rows) == 1
    assert rows[0]["rule_id"] == "DET-PROC-008"
    assert rows[0]["agent_id"] == "officer-agent-007"
    assert rows[0]["host_id"] == "OFFICER-WIN11-LAB"
    assert rows[0]["alert_id"].startswith("ALT-")

    lines = [line for line in alerts_path.read_text().splitlines() if line.strip()]
    assert len(lines) == 1
    assert json.loads(lines[0])["rule_id"] == "DET-PROC-008"
    assert json.loads(lines[0])["alert_id"] == rows[0]["alert_id"]
    assert writer.count == 1


def test_full_rule_set_loads(tmp_path: Path) -> None:
    """The whole pinned rule directory parses and validates (no RuleValidationError)."""
    conn = _db(tmp_path / "p.db")
    run, _sink, writer, _context = build_detection_run(
        conn, alerts_path=tmp_path / "a.ndjson", rules_dir=_DEFAULT_RULES_DIR
    )
    writer.close()
    assert len(run.evaluator.rules) >= 80
