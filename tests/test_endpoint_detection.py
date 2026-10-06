"""Canonical queue isolation, crash recovery and native identity through detection."""

import copy
import json
import subprocess
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

from manager import db, migrations
from manager.config import _DEFAULT_RULES_DIR
from manager.detection.factory import build_detection_run
from manager.timeutil import iso_at, iso_now
from tests.test_detection_worker import _migrate, _open, _raw_whoami, _seed, _worker
from tests.test_endpoint_records import headers, post, records


def test_native_failure_evidence_reaches_worker_without_losing_facts(tmp_path):
    import pytest

    executable = (
        Path(__file__).resolve().parents[2]
        / "panopticon-agent/build-verify-x64/officer-source-facts-tests.exe"
    )
    if not executable.is_file():
        pytest.skip("native source-facts artifact unavailable")
    values = json.loads(subprocess.check_output([str(executable), "--emit-fixtures"], text=True))
    path = tmp_path / "manager.db"
    _migrate(path)
    conn = _open(path)
    for raw in values:
        seed_endpoint(conn, raw)
    run, sink, writer, context = build_detection_run(
        conn, alerts_path=tmp_path / "alerts.ndjson", rules_dir=_DEFAULT_RULES_DIR
    )
    try:
        assert _worker(tmp_path, path).run_once(conn, run, sink) == 6
        assert {row[0] for row in conn.execute("SELECT detect_state FROM endpoint_records")} == {
            "done"
        }
        assert [
            json.loads(row[0])
            for row in conn.execute("SELECT raw_json FROM endpoint_records ORDER BY rowid")
        ] == values
        assert (
            context.registry.get(values[0]["subject"]["entity_id"]).start_time_ticks
            == 133700000000000001
        )
        assert len(context.registry) == 2  # exact native instance and explicit file source GUID
    finally:
        writer.close()
        conn.close()


def seed_endpoint(conn, record):
    conn.execute(
        "INSERT INTO endpoint_records(agent_id,host_id,record_id,kind,category,observed_at,"
        "ingested_at,payload_digest,raw_json) VALUES (?,?,?,?,?,?,?,?,?)",
        (
            record["endpoint"]["agent_id"],
            record["endpoint"]["host_id"],
            record["record_id"],
            record["kind"],
            record["category"],
            record["observed_at"],
            iso_now(),
            "test-only",
            json.dumps(record),
        ),
    )
    conn.commit()


def test_migration_backfills_existing_canonical_evidence_without_rewriting(tmp_path, monkeypatch):
    conn = _open(tmp_path / "manager.db")
    all_migrations = migrations._MIGRATIONS
    monkeypatch.setattr(migrations, "_MIGRATIONS", all_migrations[:12])
    assert migrations.migrate(conn) == 12
    original = records()[0]
    seed_endpoint(conn, original)
    before = conn.execute("SELECT raw_json FROM endpoint_records").fetchone()[0]
    monkeypatch.setattr(migrations, "_MIGRATIONS", all_migrations)
    assert migrations.migrate(conn) == len(all_migrations)
    row = conn.execute(
        "SELECT raw_json,detect_state,detect_attempts FROM endpoint_records"
    ).fetchone()
    assert tuple(row) == (before, "pending", 0)
    conn.close()


def test_canonical_queue_reaches_rules_with_exact_identity(tmp_path):
    path = tmp_path / "manager.db"
    _migrate(path)
    conn = _open(path)
    values = records()
    values[0]["data"]["process"].update(name="whoami.exe", command_line="whoami /priv")
    for raw in values:
        seed_endpoint(conn, raw)
    run, sink, writer, context = build_detection_run(
        conn,
        alerts_path=tmp_path / "alerts.ndjson",
        rules_dir=_DEFAULT_RULES_DIR,
    )
    try:
        assert _worker(tmp_path, path).run_once(conn, run, sink) == 6
        assert {x[0] for x in conn.execute("SELECT detect_state FROM endpoint_records")} == {"done"}
        alert = conn.execute(
            "SELECT event_id,agent_id,alert_json FROM alerts WHERE rule_id='DET-PROC-008'"
        ).fetchone()
        assert alert["event_id"] == values[0]["record_id"]
        assert alert["agent_id"] == "agent-1"
        context_record = json.loads(alert["alert_json"])["endpoint_context"]
        assert context_record["subject"] == values[0]["subject"]
        assert context_record["provenance"] == values[0]["provenance"]
        assert (
            context.registry.get(values[0]["subject"]["entity_id"]).start_time_ticks
            == 133700000000000001
        )
        assert context.registry.get(values[1]["subject"]["entity_id"]).start_time_ticks is None
        assert len(context.registry) == 2  # unresolved network adds no guessed actor
    finally:
        writer.close()
        conn.close()


def test_poison_canonical_record_and_stale_claim_are_isolated(tmp_path):
    path = tmp_path / "manager.db"
    _migrate(path)
    conn = _open(path)
    values = records()
    values[0]["data"]["process"]["pid"] = 99  # adapter must independently fail closed
    for raw in values:
        seed_endpoint(conn, raw)
    worker = _worker(tmp_path, path)
    run, sink, writer, _context = build_detection_run(
        conn,
        alerts_path=tmp_path / "alerts.ndjson",
        rules_dir=_DEFAULT_RULES_DIR,
    )
    try:
        assert worker.run_once(conn, run, sink) == 6
        row = conn.execute(
            "SELECT detect_state,detect_attempts FROM endpoint_records WHERE record_id=?",
            (values[0]["record_id"],),
        ).fetchone()
        assert tuple(row) == ("failed", 1)
        assert (
            conn.execute(
                "SELECT COUNT(*) FROM endpoint_records WHERE detect_state='done'"
            ).fetchone()[0]
            == 5
        )
        conn.execute(
            "UPDATE endpoint_records SET detect_state='claimed',claimed_at=? WHERE record_id=?",
            (iso_at(datetime.now(timezone.utc) - timedelta(seconds=90)), values[1]["record_id"]),
        )
        conn.commit()
        assert worker.revert_stale_claims(conn) == 1
        assert worker.run_once(conn, run, sink) == 1
        assert conn.execute("SELECT COUNT(*) FROM endpoint_records").fetchone()[0] == 6
    finally:
        writer.close()
        conn.close()


def test_both_protocols_receive_bounded_claim_capacity(tmp_path):
    path = tmp_path / "manager.db"
    _migrate(path)
    conn = _open(path)
    for i in range(200):
        _seed(conn, _raw_whoami("evt_" + f"{i:064x}"))
        raw = copy.deepcopy(records()[4])
        raw["record_id"] = "rec_" + f"{i:064x}"
        seed_endpoint(conn, raw)
    rows = _worker(tmp_path, path).claim_batch(conn)
    assert len(rows) == 256
    assert sum(row["queue"] == "endpoint" for row in rows) == 128
    assert sum(row["queue"] == "legacy" for row in rows) == 128
    conn.close()


def test_canonical_disposition_uses_agent_and_record_primary_key(tmp_path):
    path = tmp_path / "manager.db"
    _migrate(path)
    conn = _open(path)
    first = records()[4]
    second = copy.deepcopy(first)
    second["endpoint"]["agent_id"] = "another-agent"
    for raw in (first, second):
        seed_endpoint(conn, raw)
    worker = _worker(tmp_path, path)
    rows = worker.claim_batch(conn)
    run, sink, writer, _context = build_detection_run(
        conn,
        alerts_path=tmp_path / "alerts.ndjson",
        rules_dir=_DEFAULT_RULES_DIR,
    )
    try:
        worker.process_claimed(conn, run, sink, rows[:1])
        states = dict(conn.execute("SELECT agent_id,detect_state FROM endpoint_records"))
        assert sorted(states.values()) == ["claimed", "done"]
    finally:
        writer.close()
        conn.close()


def test_authenticated_ingest_reaches_running_detection_worker(client):
    values = records()
    values[0]["data"]["process"].update(name="whoami.exe", command_line="whoami /priv")
    assert post(client, headers(client), values).json()["accepted"] == 6
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        if (
            db.connect()
            .execute("SELECT COUNT(*) FROM endpoint_records WHERE detect_state='done'")
            .fetchone()[0]
            == 6
        ):
            break
        time.sleep(0.02)
    assert (
        db.connect()
        .execute("SELECT COUNT(*) FROM endpoint_records WHERE detect_state='done'")
        .fetchone()[0]
        == 6
    )
    row = (
        db.connect().execute("SELECT event_id FROM alerts WHERE rule_id='DET-PROC-008'").fetchone()
    )
    assert row["event_id"] == values[0]["record_id"]
    metric = client.get("/metrics")
    assert "panopticon_endpoint_records_pending 0" in metric.text
