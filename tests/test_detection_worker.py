"""manager/detection/worker.py — the claim/lease/detect loop (ADR 003).

Required coverage: claim→done with an alert row; a rule that raises poisons
exactly one event and the loop continues; a stale ``claimed`` lease reverts to
``pending`` and is reprocessed without a duplicate alert; and — per ADR 003's
Consequences — concurrent ingest while the worker claims, and crash recovery.
"""

from __future__ import annotations

import json
import sqlite3
import threading
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

import manager.vendor_path  # noqa: F401
from manager import migrations
from manager.config import _DEFAULT_RULES_DIR
from manager.detection.factory import build_detection_run
from manager.detection.worker import DetectionWorker
from manager.timeutil import iso_at, iso_now


def _raw_whoami(event_id: str, *, pid: int = 4321, ts: str = "2026-08-31T12:00:00.000Z") -> dict:
    return {
        "schema_version": "0.3",
        "event": {"id": event_id, "category": "process", "type": "start", "timestamp": ts},
        "source": {
            "kind": "sysmon",
            "provider": "Microsoft-Windows-Sysmon",
            "channel": "Microsoft-Windows-Sysmon/Operational",
            "record_id": 1,
        },
        "agent": {"id": "officer-agent-001", "version": "0.3.0"},
        "host": {
            "id": "OFFICER-WIN11-LAB",
            "hostname": "OFFICER-WIN11-LAB",
            "os": {"name": "Windows 11 Pro", "build": "26100"},
        },
        "user": {"name": "analyst", "domain": "LAB", "sid": "S-1-5-21-1-2-3"},
        "process": {
            "entity_id": "proc_" + f"{pid:064d}",
            "pid": pid,
            "name": "whoami.exe",
            "executable": "C:\\Windows\\System32\\whoami.exe",
            "command_line": "whoami /priv",
            "parent": {"entity_id": None, "pid": 1000, "name": "cmd.exe"},
            "hash": {"sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"},
        },
    }


def _evt_id(tag: str) -> str:
    return "evt_" + (tag * 64)[:64]


def _open(db: Path) -> sqlite3.Connection:
    conn = sqlite3.connect(db)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA busy_timeout=5000")
    conn.row_factory = sqlite3.Row
    return conn


def _migrate(db: Path) -> None:
    conn = _open(db)
    migrations.migrate(conn)
    conn.close()


def _seed(conn: sqlite3.Connection, raw: dict, *, state: str = "pending", claimed_at=None) -> None:
    e = raw["event"]
    conn.execute(
        "INSERT INTO events (event_id, agent_id, host_id, category, event_timestamp, "
        "ingested_at, schema_version, clock_skew, raw_json, detect_state, "
        "detect_attempts, claimed_at) VALUES (?,?,?,?,?,?,?,?,?,?,0,?)",
        (
            e["id"],
            raw["agent"]["id"],
            raw["host"]["id"],
            e["category"],
            e["timestamp"],
            iso_now(),
            raw["schema_version"],
            0,
            json.dumps(raw),
            state,
            claimed_at,
        ),
    )
    conn.commit()


def _worker(tmp_path: Path, db: Path) -> DetectionWorker:
    return DetectionWorker(
        db_path=db, alerts_path=tmp_path / "alerts.ndjson", rules_dir=_DEFAULT_RULES_DIR
    )


# ---------------------------------------------------------------------------


def test_claim_process_done_writes_alert(tmp_path: Path) -> None:
    db = tmp_path / "p.db"
    _migrate(db)
    conn = _open(db)
    _seed(conn, _raw_whoami(_evt_id("a")))

    w = _worker(tmp_path, db)
    run, sink, writer, _context = build_detection_run(
        conn, alerts_path=tmp_path / "alerts.ndjson", rules_dir=_DEFAULT_RULES_DIR
    )
    try:
        w.revert_stale_claims(conn)
        claimed = w.run_once(conn, run, sink)
    finally:
        writer.close()

    assert claimed == 1
    assert conn.execute("SELECT detect_state FROM events").fetchone()["detect_state"] == "done"
    row = conn.execute("SELECT rule_id, agent_id FROM alerts").fetchone()
    assert row["rule_id"] == "DET-PROC-008"
    assert row["agent_id"] == "officer-agent-001"
    conn.close()


def test_one_poisoned_event_does_not_stop_the_loop(tmp_path: Path) -> None:
    db = tmp_path / "p.db"
    _migrate(db)
    conn = _open(db)
    _seed(conn, _raw_whoami(_evt_id("b"), pid=1), state="pending")  # poison
    _seed(conn, _raw_whoami(_evt_id("c"), pid=2), state="pending")  # healthy

    w = _worker(tmp_path, db)
    run, sink, writer, _context = build_detection_run(
        conn, alerts_path=tmp_path / "alerts.ndjson", rules_dir=_DEFAULT_RULES_DIR
    )
    real = run.process_event

    def flaky(event):
        if event.get("event_id") == _evt_id("b"):
            raise RuntimeError("simulated rule bug")
        return real(event)

    run.process_event = flaky  # type: ignore[method-assign]

    try:
        w.run_once(conn, run, sink)
    finally:
        writer.close()

    states = dict(conn.execute("SELECT event_id, detect_state FROM events"))
    assert states[_evt_id("b")] == "failed"
    assert states[_evt_id("c")] == "done"
    poisoned = conn.execute(
        "SELECT detect_attempts FROM events WHERE event_id=?", (_evt_id("b"),)
    ).fetchone()
    assert poisoned["detect_attempts"] == 1
    alert_count = conn.execute("SELECT COUNT(*) AS c FROM alerts").fetchone()["c"]
    assert alert_count == 1  # only the healthy event produced an alert
    conn.close()


def test_stale_claim_reverts_and_reprocesses_without_duplicate_alert(tmp_path: Path) -> None:
    db = tmp_path / "p.db"
    _migrate(db)
    conn = _open(db)
    stale = iso_at(datetime.now(timezone.utc) - timedelta(seconds=90))
    _seed(conn, _raw_whoami(_evt_id("d")), state="claimed", claimed_at=stale)

    w = _worker(tmp_path, db)
    run, sink, writer, _context = build_detection_run(
        conn, alerts_path=tmp_path / "alerts.ndjson", rules_dir=_DEFAULT_RULES_DIR
    )
    try:
        assert w.revert_stale_claims(conn) == 1
        state = conn.execute("SELECT detect_state FROM events").fetchone()["detect_state"]
        assert state == "pending"

        w.run_once(conn, run, sink)
        state = conn.execute("SELECT detect_state FROM events").fetchone()["detect_state"]
        assert state == "done"

        # Simulate the same event being offered again (crash between detect and mark):
        conn.execute("UPDATE events SET detect_state='pending' WHERE event_id=?", (_evt_id("d"),))
        conn.commit()
        w.run_once(conn, run, sink)
    finally:
        writer.close()

    # deterministic alert_id + INSERT OR IGNORE => reprocessing adds nothing
    assert conn.execute("SELECT COUNT(*) AS c FROM alerts").fetchone()["c"] == 1
    lines = [ln for ln in (tmp_path / "alerts.ndjson").read_text().splitlines() if ln.strip()]
    assert len(lines) == 1
    conn.close()


def test_concurrent_ingest_while_worker_claims(tmp_path: Path) -> None:
    db = tmp_path / "p.db"
    _migrate(db)

    w = _worker(tmp_path, db)
    w.start()

    errors: list[Exception] = []
    per_thread = 20

    def ingest(tag: str) -> None:
        try:
            c = _open(db)
            for i in range(per_thread):
                event_id = "evt_" + (f"{tag}{i:03d}".ljust(64, "0"))
                _seed(c, _raw_whoami(event_id, pid=1000 + i))
            c.close()
        except Exception as exc:  # noqa: BLE001 - recorded for the assertion
            errors.append(exc)

    threads = [threading.Thread(target=ingest, args=(t,)) for t in ("e", "f")]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    deadline = time.time() + 15
    while time.time() < deadline:
        c = _open(db)
        pending = c.execute(
            "SELECT COUNT(*) AS c FROM events WHERE detect_state != 'done'"
        ).fetchone()["c"]
        c.close()
        if pending == 0:
            break
        time.sleep(0.1)

    w.stop()

    assert errors == []  # no "database is locked"
    c = _open(db)
    assert c.execute("SELECT COUNT(*) AS c FROM events").fetchone()["c"] == 2 * per_thread
    assert (
        c.execute("SELECT COUNT(*) AS c FROM events WHERE detect_state='done'").fetchone()["c"]
        == 2 * per_thread
    )
    # every event processed exactly once -> exactly one DET-PROC-008 per event,
    # and no alert_id written twice (no double-processing).
    assert (
        c.execute("SELECT COUNT(*) AS c FROM alerts WHERE rule_id='DET-PROC-008'").fetchone()["c"]
        == 2 * per_thread
    )
    total = c.execute("SELECT COUNT(*) AS c FROM alerts").fetchone()["c"]
    distinct = c.execute("SELECT COUNT(DISTINCT alert_id) AS c FROM alerts").fetchone()["c"]
    assert total == distinct
    c.close()


def test_crash_recovery_reprocesses_claimed_rows_once(tmp_path: Path) -> None:
    db = tmp_path / "p.db"
    _migrate(db)
    conn = _open(db)
    # A previous worker died mid-flight: row left 'claimed' with an old lease.
    stale = iso_at(datetime.now(timezone.utc) - timedelta(seconds=120))
    _seed(conn, _raw_whoami(_evt_id("g")), state="claimed", claimed_at=stale)
    conn.close()

    w = _worker(tmp_path, db)
    w.start()
    deadline = time.time() + 15
    while time.time() < deadline:
        c = _open(db)
        state = c.execute("SELECT detect_state FROM events").fetchone()["detect_state"]
        c.close()
        if state == "done":
            break
        time.sleep(0.1)
    w.stop()

    c = _open(db)
    assert c.execute("SELECT detect_state FROM events").fetchone()["detect_state"] == "done"
    assert c.execute("SELECT COUNT(*) AS c FROM alerts").fetchone()["c"] == 1
    c.close()
