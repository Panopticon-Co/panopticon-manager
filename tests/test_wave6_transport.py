"""Synthetic transport round trip, independent of detection rules or live collectors."""

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import jsonschema
import pytest

from manager import db
from tests.conftest import enroll_test_agent

CONTRACTS = Path(__file__).resolve().parents[2] / "panopticon-contracts"


@pytest.mark.parametrize("family,source", [
    ("file_minifilter", "minifilter"),
    ("file_api_hook", "api_hook"),
    ("network_etw_kernel", "etw_kernel"),
])
def test_new_source_ingest_and_command_result_round_trip(client, family, source):
    fixture = json.loads((CONTRACTS / "fixtures/endpoint-record/1.0/families"
                          / f"{family}.json").read_text(encoding="utf-8"))
    assert fixture["fixture"]["real_capture"] is False
    record = fixture["records"][0]
    assert record["provenance"]["kind"] == source
    enrolled = enroll_test_agent(client, "agent-1", "host-1")
    assert enrolled.status_code == 200
    auth = {"Authorization": "Bearer " + enrolled.json()["access_token"]}
    headers = {**auth, "Content-Type": "application/x-ndjson",
               "X-Panopticon-Agent-Id": "agent-1", "X-Panopticon-Protocol": "2",
               "X-Panopticon-Batch-Id": "batch-wave6"}
    challenge = client.post("/api/v2/endpoint/freshness-challenge", json={}, headers=headers)
    assert challenge.status_code == 200, challenge.text
    headers["X-Panopticon-Freshness-Nonce"] = challenge.json()["nonce"]
    response = client.post("/api/v2/endpoint/records", headers=headers,
                           content=json.dumps(record) + "\n")
    assert response.status_code == 200, response.text
    assert response.json()["accepted"] == 1 and response.json()["rejected"] == []
    stored = client.get(f"/api/v2/endpoint/agent-1/records/{record['record_id']}", headers=auth)
    assert stored.status_code == 200 and stored.json() == record

    subject = stored.json()["subject"]
    assert subject["resolution"] == "native_exact"
    command = {
        "schema_version": "2", "command_id": "cmd-wave6", "agent_id": "agent-1",
        "correlation_id": "corr-wave6", "action": "KILL_PROCESS",
        "expires_at": (datetime.now(timezone.utc) + timedelta(minutes=5)).isoformat(),
        "target": {"pid": subject["observed_pid"], "boot_id": subject["boot_id"],
                   "start_time_ticks": subject["native_creation_ticks"]},
    }
    queued = client.post("/api/v1/commands", json=command,
                         headers={"X-Panopticon-Command-Token": "test-command-token"})
    assert queued.status_code == 200, queued.text
    polled = client.get("/api/v1/agents/agent-1/commands?delivery_mode=durable", headers=auth)
    assert polled.status_code == 200
    assert polled.json()["commands"][0]["target"] == command["target"]
    assert client.post("/api/v1/agents/agent-1/commands/cmd-wave6/accept",
                       headers=auth).status_code == 200
    result = {
        "schema_version": "2", "result_id": "result-wave6", "command_id": "cmd-wave6",
        "correlation_id": "corr-wave6", "outcome": "indeterminate",
        "execution": {"representation": "windows_process_termination_v1",
                      "stage": "completion", "action_initiated": True,
                      "completion_observed": False, "native_error": None},
    }
    schema = json.loads((CONTRACTS / "schema/command_result.schema.json").read_text())
    jsonschema.validate(result, schema)
    endpoint = "/api/v1/agents/agent-1/command-results"
    for _ in range(2):
        accepted = client.post(endpoint, json=result, headers=auth)
        assert accepted.status_code == 200 and accepted.json()["retained"] is True
    conn = db.connect()
    assert conn.execute("SELECT lifecycle_state FROM commands WHERE command_id='cmd-wave6'") \
        .fetchone()[0] == "INDETERMINATE"
    receipt = json.loads(conn.execute("SELECT raw_json FROM command_result_receipts")
                         .fetchone()[0])
    assert receipt["execution"] == result["execution"]
    result["execution"]["native_error"] = 6
    assert client.post(endpoint, json=result, headers=auth).status_code == 409


def test_acquire_file_remains_an_internal_agent_extension(client):
    command = {"command_id": "cmd-internal", "agent_id": "agent-1", "action": "ACQUIRE_FILE",
               "expires_at": (datetime.now(timezone.utc) + timedelta(minutes=5)).isoformat(),
               "target": {"path": "C:\\fixture.txt"}}
    response = client.post("/api/v1/commands", json=command,
                           headers={"X-Panopticon-Command-Token": "test-command-token"})
    assert response.status_code == 422
