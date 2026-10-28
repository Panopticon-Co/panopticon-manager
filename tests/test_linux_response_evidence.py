import copy
import hashlib
import json
from pathlib import Path

import pytest

from manager import db
from manager.linux_response_evidence import command_evidence
from manager.wire.linux_endpoint import expected_id
from tests.test_analyst_operations import create, setup
from tests.test_linux_endpoint import URL, body, headers

FIXTURES = (
    Path(__file__).resolve().parents[2] / "panopticon-contracts/fixtures/linux-endpoint/valid"
)


def report(command, seq=1):
    raw = json.loads((FIXTURES / "response_action_kill_dry_run.json").read_text())
    raw["host"]["id"] = "host-1"
    raw["seq"] = seq
    raw["id"] = expected_id(raw)
    raw["response"].update(
        command_id=command["command_id"],
        correlation_id=command["correlation_id"],
        action=command["action"],
    )
    raw["response"].pop("target", None)
    raw["response"].pop("mode", None)
    raw["response"]["path"] = command["target"]["path"]
    return raw


def authorized_file(client):
    analyst, agent = setup(client)
    response = create(client, analyst, "QUARANTINE_FILE", target={"path": "/tmp/lab"})
    assert response.status_code == 201
    rid = response.json()["response_id"]
    assert (
        client.post(f"/api/v1/response-actions/{rid}/authorize", headers=analyst).status_code == 200
    )
    command = json.loads(db.connect().execute("SELECT command_json FROM commands").fetchone()[0])
    return analyst, agent, rid, command


def send(client, agent, records):
    token = agent["Authorization"].removeprefix("Bearer ")
    result = client.post(URL, content=body(records), headers=headers(token, agent="agent-1"))
    assert result.status_code == 200, result.text
    return result.json()


def case(client, analyst, rid):
    rows = client.get("/api/v1/response-actions", headers=analyst).json()["response_actions"]
    return next(r for r in rows if r["response_id"] == rid)


def test_dry_run_report_is_retained_linked_and_exported_without_changing_command(client):
    analyst, agent, rid, command = authorized_file(client)
    raw = report(command)
    assert send(client, agent, [raw])["accepted"] == 1
    item = case(client, analyst, rid)
    assert item["command_lifecycle_state"] == "AUTHORIZED"
    assert item["results"] == []
    evidence = item["endpoint_evidence"][0]
    assert evidence["linkage"] == "matched_command"
    assert evidence["reported"]["dry_run"] is True
    assert evidence["reported"]["executed"] is True  # Native field does not override dry_run.
    assert "raw_record_json" not in evidence
    exported = client.get(f"/api/v1/response-actions/{rid}/export", headers=analyst).json()
    complete = exported["response_action"]["endpoint_evidence"][0]
    assert hashlib.sha256(complete["raw_record_json"].encode()).hexdigest() == complete["sha256"]
    assert client.get(f"/api/v1/response-actions/{rid}/export", headers=agent).status_code == 401


@pytest.mark.parametrize(
    "key,value",
    [("correlation_id", "other"), ("action", "COLLECT_FILE"), ("path", "/another/file")],
)
def test_disagreement_is_visible_and_never_becomes_completion(client, key, value):
    analyst, agent, rid, command = authorized_file(client)
    raw = report(command)
    raw["response"][key] = value
    send(client, agent, [raw])
    item = case(client, analyst, rid)
    assert item["endpoint_evidence"][0]["linkage"] == "mismatch"
    assert key in item["endpoint_evidence"][0]["mismatches"]
    assert item["command_lifecycle_state"] == "AUTHORIZED"


def test_evidence_preview_is_bounded_but_export_includes_all_records(client):
    analyst, agent, rid, command = authorized_file(client)
    send(client, agent, [report(command, seq) for seq in range(1, 23)])
    item = case(client, analyst, rid)
    assert len(item["endpoint_evidence"]) == 20 and item["evidence_truncated"]
    complete = client.get(f"/api/v1/response-actions/{rid}/export", headers=analyst).json()
    assert len(complete["response_action"]["endpoint_evidence"]) == 22
    assert not complete["response_action"]["evidence_truncated"]


def test_native_process_ticks_and_boot_are_checked_without_precision_loss(client):
    _, agent, _, command = authorized_file(client)
    raw = report(command)
    raw["response"].pop("path")
    raw["response"]["action"] = "KILL_PROCESS"
    raw["response"]["target"] = {"pid": 42, "start_time_ticks": 2**64 - 1}
    send(client, agent, [raw])
    command = copy.deepcopy(command)
    command["action"] = "KILL_PROCESS"
    command["target"] = {
        "pid": 42,
        "start_time_ticks": str(2**64 - 1),
        "boot_id": "boot_" + hashlib.sha256(raw["host"]["boot_id"].encode()).hexdigest(),
    }
    items, _ = command_evidence(db.connect(), command, "agent-1", "host-1")
    assert items[0]["linkage"] == "matched_command"
    assert items[0]["reported"]["target"]["start_time_ticks"] == str(2**64 - 1)
    command["target"]["boot_id"] = "boot_" + "0" * 64
    assert command_evidence(db.connect(), command, "agent-1", "host-1")[0][0]["mismatches"] == [
        "boot_id"
    ]
    assert command_evidence(db.connect(), command, "another-agent", "host-1")[0] == []


def test_old_health_snapshot_never_proves_current_enforcement(client):
    analyst, agent = setup(client)
    raw = json.loads((FIXTURES / "health.json").read_text())
    raw["host"]["id"] = "host-1"
    raw["id"] = expected_id(raw)
    raw["health"]["providers"].append(
        {
            "name": "command_channel",
            "state": "active",
            "reason": "",
            "capabilities": ["response.command", "response.collect_process_info"],
            "events": 0,
            "drops": 0,
        }
    )
    send(client, agent, [raw])
    state = client.get("/api/v1/agents/agent-1/response-readiness", headers=analyst).json()
    assert state["native_capabilities"] == "reported_snapshot"
    assert state["execution_mode"] == "unknown"
    assert state["sensor_report"]["freshness"] == "unverified"
    assert state["sensor_report"]["captured_at"] == raw["time"]
    assert state["sensor_report"]["response_providers"][0]["capabilities"] == [
        "response.command",
        "response.collect_process_info",
    ]
