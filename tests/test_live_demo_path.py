"""The live demo path, end to end over HTTP with the full pinned rule set:
canonical agent records -> /api/v2/endpoint/records -> endpoint_records ->
detection worker -> alerts -> GET /api/v1/alerts and /api/v1/status.

Each harmless command here is one the Windows demo script runs on the VM;
benign commands must stay silent.
"""

from __future__ import annotations

import copy
import hashlib
import time

from manager import db
from tests.test_endpoint_records import headers, post, records
from tests.test_real_ingest_detection_reachability import real_rules_client  # noqa: F401
from tests.test_response_actions_route import _enroll_analyst

TRIGGERS = {
    "whoami.exe": ("whoami /priv", "DET-PROC-008"),
    "schtasks.exe": (
        "schtasks /create /tn PanopticonDemo /tr notepad.exe /sc once /st 23:59 /f",
        "DET-PERS-002",
    ),
    "cmdkey.exe": ("cmdkey /list", "DET-CRED-003"),
    "certutil.exe": (
        "certutil -urlcache -split -f http://www.msftconnecttest.com/connecttest.txt ct.txt",
        "DET-PROC-003",
    ),
}
BENIGN = {"notepad.exe": "notepad.exe", "whoami.exe": "whoami"}


def _process_start(base: dict, tag: str, pid: int, name: str, command_line: str) -> dict:
    """A distinct process-start record whose exact identity digest is the one
    ingest re-derives from (host, boot, pid, creation ticks)."""
    record = copy.deepcopy(base)
    endpoint = record["endpoint"]
    ticks = str(133_700_000_000_000_000 + pid)
    fields = [
        "native-process-instance-v1", endpoint["host_id"], endpoint["boot_id"], str(pid), ticks
    ]
    material = "".join(str(len(v.encode("utf-8"))) + ":" + v for v in fields)
    entity_id = "proc_" + hashlib.sha256(material.encode("utf-8")).hexdigest()
    digest = hashlib.sha256(tag.encode("utf-8")).hexdigest()

    record["record_id"] = "rec_" + digest
    record["subject"].update(observed_pid=pid, native_creation_ticks=ticks, entity_id=entity_id)
    process = record["data"]["process"]
    process.update(
        pid=pid, start_time_ticks=ticks, entity_id=entity_id, name=name, command_line=command_line
    )
    record["data"]["event"]["id"] = "evt_" + digest
    record["provenance"]["native_observation_id"] = "evt_" + digest
    facts = record["data"]["source_facts"]["process"]
    facts.update(pid=pid, start_time_ticks=ticks, command_line=command_line)
    return record


def _wait_until_detected(expected: int, timeout: float = 30.0) -> None:
    def done() -> int:
        return (
            db.connect()
            .execute("SELECT COUNT(*) FROM endpoint_records WHERE detect_state='done'")
            .fetchone()[0]
        )

    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline and done() < expected:
        time.sleep(0.05)
    assert done() == expected


def test_demo_triggers_reach_the_alert_api_and_benign_commands_stay_silent(
    real_rules_client,  # noqa: F811
) -> None:
    client = real_rules_client
    base = records()[0]
    triggers = {
        name: _process_start(base, f"trigger-{name}", 5000 + i, name, cmd)
        for i, (name, (cmd, _rule)) in enumerate(TRIGGERS.items())
    }
    benign = [
        _process_start(base, f"benign-{name}", 6000 + i, name, cmd)
        for i, (name, cmd) in enumerate(BENIGN.items())
    ]
    body = post(client, headers(client), [*triggers.values(), *benign]).json()
    assert body["accepted"] == len(triggers) + len(benign), body
    _wait_until_detected(len(triggers) + len(benign))

    analyst = {"Authorization": "Bearer " + _enroll_analyst(client, "demo-analyst")}
    resp = client.get("/api/v1/alerts", headers=analyst)
    assert resp.status_code == 200
    by_record: dict[str, list[dict]] = {}
    for row in resp.json()["alerts"]:
        by_record.setdefault(row["event_id"], []).append(row)

    for name, (command_line, rule_id) in TRIGGERS.items():
        rows = by_record.get(triggers[name]["record_id"], [])
        matching = [r for r in rows if r["rule_id"] == rule_id]
        assert matching, f"{name}: expected {rule_id}, got {[r['rule_id'] for r in rows]}"
        alert = matching[0]
        assert alert["host_id"] == "host-1"
        assert alert["agent_id"] == "agent-1"
        assert alert["severity"] and alert["alert_timestamp"]
        assert alert["alert"]["evidence"].get("process.command_line") == command_line

    for record in benign:
        assert record["record_id"] not in by_record, by_record[record["record_id"]]

    status = client.get("/api/v1/status", headers=analyst).json()
    assert status["endpoint_records"]["done"] == len(triggers) + len(benign)
    assert status["endpoint_records"]["failed"] == 0
    assert status["detection_worker"]["alive"] is True
    assert status["alerts"] >= len(triggers)
