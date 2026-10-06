import hashlib
import json
import subprocess
from datetime import datetime, timedelta, timezone
from pathlib import Path

import jsonschema
import pytest
from pydantic import ValidationError
from response_engine.contract import CommandResult

from manager import db
from tests.conftest import enroll_test_agent

ROOT = Path(__file__).resolve().parents[2]
NATIVE = ROOT / "panopticon-agent/build-verify-x64/officer-process-action-tests.exe"
SCHEMA = json.loads(
    (ROOT / "panopticon-contracts/schema/command-result-v2.schema.json").read_text()
)


def fields():
    return {
        "schema_version": "2", "result_id": "result-execution", "command_id": "cmd-execution",
        "correlation_id": "corr-native-execution", "outcome": "indeterminate",
        "execution": {
            "representation": "windows_process_termination_v1", "stage": "completion",
            "action_initiated": True, "completion_observed": False, "native_error": 6,
        },
    }


def queued(client, command_id="cmd-execution", action="KILL_PROCESS", auth=None):
    if auth is None:
        enrolled = enroll_test_agent(client, "agent-execution", "host-execution")
        assert enrolled.status_code == 200
        auth = {"Authorization": "Bearer " + enrolled.json()["access_token"]}
    command = {
        "command_id": command_id, "agent_id": "agent-execution", "action": action,
        "expires_at": (datetime.now(timezone.utc) + timedelta(minutes=5)).isoformat(),
        "correlation_id": "corr-native-execution",
    }
    if action == "KILL_PROCESS":
        command.update(schema_version="2", target={
            "pid": 42, "start_time_ticks": "133700000000000001", "boot_id": "boot_" + "a" * 64,
        })
    response = client.post("/api/v1/commands", json=command,
                           headers={"X-Panopticon-Command-Token": "test-command-token"})
    assert response.status_code == 200
    client.get("/api/v1/agents/agent-execution/commands?delivery_mode=durable", headers=auth)
    return auth


@pytest.mark.parametrize("patch", [
    {"native_error": True}, {"native_error": "6"}, {"native_error": -1},
    {"native_error": 4294967296}, {"action_initiated": "true"},
    {"action_initiated": False}, {"completion_observed": True}, {"stage": "open"},
    {"stage": "unknown"}, {"stdout": "smuggled"},
])
def test_python_and_published_schema_both_refuse_invalid_execution(patch):
    record = fields()
    record["execution"].update(patch)
    with pytest.raises(ValidationError):
        CommandResult(**record)
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(record, SCHEMA)


def test_execution_is_bound_to_queued_action_and_retained_immutably(client):
    auth = queued(client)
    endpoint = "/api/v1/agents/agent-execution/command-results"
    record = fields()
    jsonschema.validate(record, SCHEMA)
    assert client.post(endpoint, json=record, headers=auth).status_code == 200
    assert client.post(endpoint, json=record, headers=auth).status_code == 200
    stored = json.loads(db.connect().execute(
        "SELECT raw_json FROM command_result_receipts WHERE result_id=?", (record["result_id"],)
    ).fetchone()[0])
    assert stored["execution"] == record["execution"]
    record["execution"]["native_error"] = 5
    assert client.post(endpoint, json=record, headers=auth).status_code == 409
    auth = queued(client, "cmd-network-evidence", "COLLECT_NETWORK_CONNECTIONS", auth=auth)
    record.update(command_id="cmd-network-evidence", result_id="result-network-evidence")
    assert client.post(endpoint, json=record, headers=auth).status_code == 422
    assert db.connect().execute("SELECT COUNT(*) FROM command_result_receipts").fetchone()[0] == 1


def test_pre_extension_result_digest_remains_replayable(client):
    auth = queued(client)
    record = fields()
    del record["execution"]
    # Simulate the canonical shape stored before the execution field existed.
    old_shape = {**record, "detail": None}
    raw = json.dumps(old_shape, sort_keys=True, separators=(",", ":"))
    digest = hashlib.sha256(raw.encode()).hexdigest()
    connection = db.connect()
    connection.execute("INSERT INTO command_result_receipts VALUES (?,?,?,?,?,?)", (
        record["result_id"], "agent-execution", record["command_id"], digest, raw,
        datetime.now(timezone.utc).isoformat(),
    ))
    connection.commit()
    assert client.post("/api/v1/agents/agent-execution/command-results",
                       json=record, headers=auth).status_code == 200
    assert connection.execute("SELECT raw_json FROM command_result_receipts").fetchone()[0] == raw


def test_published_execution_fixtures_match_python_contract():
    fixtures = json.loads(
        (ROOT / "panopticon-contracts/fixtures/results/execution-v2.json").read_text()
    )
    for record in fixtures["valid"]:
        assert CommandResult(**record).model_dump(mode="json")["execution"] == record["execution"]
    for record in fixtures["invalid"]:
        with pytest.raises(ValidationError):
            CommandResult(**record)


@pytest.mark.skipif(not NATIVE.is_file(), reason="compiled Windows execution producer required")
def test_actual_native_execution_wire_passes_schema_and_manager_retention(client):
    completed = subprocess.run([str(NATIVE), "--emit-execution-fixtures"],
                               capture_output=True, text=True, timeout=5, check=True)
    records = json.loads(completed.stdout)
    assert [record["outcome"] for record in records] == [
        "succeeded", "indeterminate", "indeterminate",
    ]
    auth = None
    for record in records:
        jsonschema.validate(record, SCHEMA)
        auth = queued(client, record["command_id"], auth=auth)
        response = client.post("/api/v1/agents/agent-execution/command-results",
                               json=record, headers=auth)
        assert response.status_code == 200
        stored = json.loads(db.connect().execute(
            "SELECT raw_json FROM command_result_receipts WHERE result_id=?", (record["result_id"],)
        ).fetchone()[0])
        assert stored["execution"] == record["execution"]
