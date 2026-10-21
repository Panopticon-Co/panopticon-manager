"""Linux's empty-body accept request must record validation, not execution."""

from datetime import datetime, timedelta, timezone

import pytest

from manager import db
from tests.conftest import enroll_test_agent


def prepare(client):
    enrolled = enroll_test_agent(client, "lab-linux", "lab-host")
    assert enrolled.status_code == 200
    headers = {"Authorization": f"Bearer {enrolled.json()['access_token']}"}
    queued = client.post(
        "/api/v1/commands",
        json={
            "command_id": "lab-command",
            "agent_id": "lab-linux",
            "action": "COLLECT_NETWORK_CONNECTIONS",
            "expires_at": (datetime.now(timezone.utc) + timedelta(minutes=5)).isoformat(),
        },
        headers={"X-Panopticon-Command-Token": "test-command-token"},
    )
    assert queued.status_code == 200
    return headers


URL = "/api/v1/agents/lab-linux/commands/lab-command/accept"


def test_acceptance_is_authenticated_idempotent_and_precedes_result(client):
    headers = prepare(client)
    assert client.post(URL).status_code == 401
    assert client.post(URL, headers=headers).status_code == 200
    assert client.get("/api/v1/agents/lab-linux/commands", headers=headers).status_code == 200
    for _ in range(2):
        response = client.post(URL, headers=headers)
        assert response.status_code == 200
        assert response.json() == {"command_id": "lab-command", "accepted": True}
    conn = db.connect()
    assert conn.execute("SELECT lifecycle_state FROM commands").fetchone()[0] == "ACCEPTED"
    assert conn.execute("SELECT COUNT(*) FROM command_results").fetchone()[0] == 0
    assert conn.execute(
        "SELECT COUNT(*) FROM command_audit WHERE event = 'accepted' AND actor = 'agent:lab-linux'"
    ).fetchone()[0] == 1
    result = client.post(
        "/api/v1/agents/lab-linux/command-results",
        json={"result_id": "lab-result", "command_id": "lab-command", "outcome": "succeeded"},
        headers=headers,
    )
    assert result.status_code == 200
    assert client.post(URL, headers=headers).status_code == 200
    assert conn.execute("SELECT lifecycle_state FROM commands").fetchone()[0] == "SUCCEEDED"


@pytest.mark.parametrize("state", ["AUTHORIZED", "SUCCEEDED", "FAILED", "REJECTED"])
def test_acceptance_cannot_skip_dispatch_or_resurrect_terminal_state(client, state):
    headers = prepare(client)
    conn = db.connect()
    conn.execute("UPDATE commands SET lifecycle_state = ?", (state,))
    conn.commit()
    assert client.post(URL, headers=headers).status_code == 200
    assert conn.execute("SELECT lifecycle_state FROM commands").fetchone()[0] == state
    assert conn.execute(
        "SELECT COUNT(*) FROM command_audit WHERE event = 'accepted'"
    ).fetchone()[0] == 0


def test_acceptance_rejects_foreign_missing_and_expired_commands(client):
    headers = prepare(client)
    assert client.post(URL.replace("lab-command", "missing"), headers=headers).status_code == 422
    other = enroll_test_agent(client, "other", "other-host")
    other_headers = {"Authorization": f"Bearer {other.json()['access_token']}"}
    assert client.post(URL, headers=other_headers).status_code == 401
    assert client.post(
        URL.replace("lab-linux", "other"), headers=other_headers
    ).status_code == 422
    client.get("/api/v1/agents/lab-linux/commands", headers=headers)
    conn = db.connect()
    conn.execute(
        "UPDATE commands SET expires_at = ?",
        ((datetime.now(timezone.utc) - timedelta(seconds=1)).isoformat(),),
    )
    conn.commit()
    assert client.post(URL, headers=headers).status_code == 200
    assert conn.execute("SELECT lifecycle_state FROM commands").fetchone()[0] == "EXPIRED"
