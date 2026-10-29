"""Focused durable-worker and response-domain regression checks; no native E2E."""

import copy
import hashlib
import json
import sqlite3
from pathlib import Path

import pytest
from fastapi import HTTPException

from manager import linux_endpoint_store, migrations
from manager.analyst_response import resolve_manual_target
from manager.detection.factory import build_detection_run
from manager.detection.response import authorize_response_action
from manager.detection.worker import CLAIM_LIMIT, DetectionWorker
from manager.routers.response_actions import ManualRequest, stage_manual_request
from manager.timeutil import iso_now
from tests.test_response_engine import _enroll_agent

RULES = Path(__file__).resolve().parents[1] / "vendor/eyedetect/rules/linux_process"
FIXTURE = Path(__file__).parent / "fixtures/linux_endpoint/process-exec.json"


def record(seq=1):
    raw = json.loads(FIXTURE.read_text(encoding="utf-8"))
    raw["seq"] = seq
    raw["id"] = hashlib.sha256(
        f"{raw['sensor']['id']}|{raw['host']['boot_id']}|{seq}".encode()
    ).hexdigest()[:32]
    raw["process"].update(name="bash", args=["bash", "-c", "LD_PRELOAD=/tmp/lab.so true"])
    return raw


def put(conn, raw, agent="agent-1"):
    text = json.dumps(raw)
    linux_endpoint_store.store(
        conn,
        agent,
        [linux_endpoint_store.StoredRecord(raw, hashlib.sha256(text.encode()).hexdigest(), text)],
        iso_now(),
    )
    conn.commit()


@pytest.fixture()
def rig(tmp_path):
    path = tmp_path / "manager.db"
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    migrations.migrate(conn)
    _enroll_agent(conn, host_id=record()["host"]["id"])
    worker = DetectionWorker(db_path=path, alerts_path=tmp_path / "alerts.ndjson", rules_dir=RULES)
    run, sink, writer, _ = build_detection_run(
        conn, alerts_path=tmp_path / "alerts.ndjson", rules_dir=RULES
    )
    yield conn, worker, run, sink
    writer.close()
    conn.close()


def test_linux_detection_retains_native_subject_and_manual_authorization(rig):
    conn, worker, run, sink = rig
    raw = record()
    put(conn, raw)
    assert worker.run_once(conn, run, sink) == 1
    alert = conn.execute("SELECT * FROM alerts WHERE rule_id='DET-LNX-003'").fetchone()
    context = json.loads(alert["alert_json"])["endpoint_context"]
    assert context["identity_model"] == "linux_endpoint_v1"
    assert context["endpoint"]["agent_id"] == "agent-1"
    assert context["subject"]["entity_id"] == raw["process"]["entity_id"]
    _, _, target = resolve_manual_target(conn, alert["alert_id"], "KILL_PROCESS", {})
    assert target["start_time_ticks"] == str(raw["process"]["start_ticks"])
    assert (
        target["boot_id"] == "boot_" + hashlib.sha256(raw["host"]["boot_id"].encode()).hexdigest()
    )
    conn.execute("BEGIN IMMEDIATE")
    staged = stage_manual_request(
        conn,
        ManualRequest(
            alert_id=alert["alert_id"],
            action="COLLECT_PROCESS_INFO",
            reason="Review retained lab process",
        ),
        "analyst:requester",
    )
    conn.commit()
    assert conn.execute("SELECT COUNT(*) FROM commands").fetchone()[0] == 0
    conn.execute("BEGIN IMMEDIATE")
    authorize_response_action(conn, staged["response_id"], "analyst:approver")
    conn.commit()
    command = json.loads(conn.execute("SELECT command_json FROM commands").fetchone()[0])
    assert command["schema_version"] == "2" and command["target"] == target
    assert worker.run_once(conn, run, sink) == 0
    # Simulate lease recovery after an alert already committed: scoped alert ID deduplicates.
    before = conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
    conn.execute("UPDATE linux_endpoint_detection SET state='pending'")
    conn.commit()
    worker.run_once(conn, run, sink)
    assert conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0] == before


def test_unverified_linux_identity_cannot_fall_back_to_legacy_pid(rig):
    conn, worker, run, sink = rig
    raw = record()
    raw["process"]["confidence"]["identity"] = "inferred"
    put(conn, raw)
    worker.run_once(conn, run, sink)
    alert = conn.execute("SELECT * FROM alerts WHERE rule_id='DET-LNX-003'").fetchone()
    assert json.loads(alert["alert_json"])["endpoint_context"]["subject"] == {}
    with pytest.raises(HTTPException, match="verified alert identity"):
        resolve_manual_target(conn, alert["alert_id"], "KILL_PROCESS", {})
    assert conn.execute("SELECT COUNT(*) FROM commands").fetchone()[0] == 0


def test_linux_queue_lease_recovery_and_single_event_poisoning(rig):
    conn, worker, run, sink = rig
    put(conn, record(1))
    put(conn, record(2))
    rows = worker.claim_batch(conn)
    conn.execute("UPDATE linux_endpoint_detection SET claimed_at='2000-01-01T00:00:00Z'")
    conn.commit()
    assert worker.revert_stale_claims(conn) == 2
    rows = worker.claim_batch(conn)
    original = run.process_event
    calls = []

    def process(event):
        calls.append(event["event_id"])
        if len(calls) == 1:
            raise RuntimeError("rule failure")
        return original(event)

    run.process_event = process
    worker.process_claimed(conn, run, sink, rows)
    states = conn.execute(
        "SELECT state,attempts FROM linux_endpoint_detection ORDER BY rowid"
    ).fetchall()
    assert [tuple(r) for r in states] == [("failed", 1), ("done", 0)]


def test_linux_queue_shares_capacity_with_legacy_backlog(rig):
    from tests.test_detection_worker import _raw_whoami, _seed

    conn, worker, _, _ = rig
    for seq in range(CLAIM_LIMIT):
        put(conn, record(seq + 1))
        raw = _raw_whoami("evt_" + f"{seq:064x}")
        _seed(conn, raw)
    rows = worker.claim_batch(conn)
    assert len(rows) == CLAIM_LIMIT
    assert sum(r["queue"] == "linux" for r in rows) == CLAIM_LIMIT // 2
    assert sum(r["queue"] == "legacy" for r in rows) == CLAIM_LIMIT // 2


def test_response_subject_does_not_leak_into_next_protocol(rig):
    from types import SimpleNamespace

    conn, worker, _, _ = rig
    put(conn, record())
    rows = worker.claim_batch(conn)
    contexts = []
    sink = SimpleNamespace()
    run = SimpleNamespace(
        process_event=lambda event: contexts.append(copy.deepcopy(sink.linux_context))
    )
    worker.process_claimed(conn, run, sink, rows)
    # A legacy event follows on the same worker and sink.
    from tests.test_detection_worker import _raw_whoami, _seed

    _seed(conn, _raw_whoami("evt_" + "a" * 64))
    worker.run_once(conn, run, sink)
    assert contexts[0]["identity_model"] == "linux_endpoint_v1"
    assert contexts[1] is None


def test_linux_queue_migration_backfills_retained_processes_once(rig):
    conn, _, _, _ = rig
    put(conn, record())
    conn.execute("DELETE FROM linux_endpoint_detection")
    conn.commit()
    migrations._migration_23(conn)
    conn.commit()
    conn.execute("UPDATE linux_endpoint_detection SET state='done'")
    conn.commit()
    migrations._migration_23(conn)
    assert conn.execute("SELECT state FROM linux_endpoint_detection").fetchone()[0] == "done"
