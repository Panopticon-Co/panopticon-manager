import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import jsonschema
import pytest

from manager import db
from tests.conftest import enroll_test_agent


@pytest.mark.parametrize("expired", [False, True])
def test_version_two_result_is_retained_immutably_even_after_expiry(client, expired):
    enrolled = enroll_test_agent(client, "agent-results", "host-results")
    headers = {"Authorization": "Bearer " + enrolled.json()["access_token"]}
    command = {
        "command_id": "cmd-durable-result",
        "agent_id": "agent-results",
        "action": "COLLECT_NETWORK_CONNECTIONS",
        "expires_at": (datetime.now(timezone.utc) + timedelta(minutes=5)).isoformat(),
        "correlation_id": "corr-durable-result",
    }
    assert (
        client.post(
            "/api/v1/commands",
            json=command,
            headers={"X-Panopticon-Command-Token": "test-command-token"},
        ).status_code
        == 200
    )
    assert client.get("/api/v1/agents/agent-results/commands", headers=headers).status_code == 200
    if expired:
        db.connect().execute("UPDATE commands SET expires_at='2000-01-01T00:00:00+00:00'")
        db.connect().commit()
    result = {
        "schema_version": "2",
        "result_id": "durable-result-id",
        "command_id": command["command_id"],
        "correlation_id": command["correlation_id"],
        "outcome": "indeterminate",
        "detail": "execution completion could not be proven",
    }
    endpoint = "/api/v1/agents/agent-results/command-results"
    first = client.post(endpoint, json=result, headers=headers)
    schema = json.loads(
        (
            Path(__file__).resolve().parents[2]
            / "panopticon-contracts/schema/command-result-v2.schema.json"
        ).read_text()
    )
    jsonschema.validate(result, schema)
    assert first.status_code == 200
    assert first.json() == {"result_id": result["result_id"], "accepted": True, "retained": True}
    assert client.post(endpoint, json=result, headers=headers).status_code == 200
    assert db.connect().execute("SELECT COUNT(*) FROM command_result_receipts").fetchone()[0] == 1
    collision = {**result, "outcome": "succeeded"}
    assert client.post(endpoint, json=collision, headers=headers).status_code == 409
    row = db.connect().execute("SELECT raw_json FROM command_result_receipts").fetchone()[0]
    assert '"outcome":"indeterminate"' in row
    state = db.connect().execute("SELECT lifecycle_state FROM commands").fetchone()[0]
    assert state == ("EXPIRED" if expired else "INDETERMINATE")
