from datetime import datetime, timedelta, timezone

from tests.conftest import enroll_test_agent


def test_durable_poll_redelivers_until_acceptance_without_changing_legacy_poll(client):
    enrolled = enroll_test_agent(client, "agent-durable-poll", "host-durable-poll")
    auth = {"Authorization": "Bearer " + enrolled.json()["access_token"]}
    command = {
        "command_id": "cmd-durable-poll",
        "agent_id": "agent-durable-poll",
        "action": "COLLECT_NETWORK_CONNECTIONS",
        "expires_at": (datetime.now(timezone.utc) + timedelta(minutes=5)).isoformat(),
    }
    assert (
        client.post(
            "/api/v1/commands",
            json=command,
            headers={"X-Panopticon-Command-Token": "test-command-token"},
        ).status_code
        == 200
    )
    route = "/api/v1/agents/agent-durable-poll/commands"
    first = client.get(route + "?delivery_mode=durable", headers=auth)
    second = client.get(route + "?delivery_mode=durable", headers=auth)
    assert first.status_code == second.status_code == 200
    assert first.json() == second.json() and len(first.json()["commands"]) == 1
    assert client.get(route, headers=auth).json() == {"commands": []}
    assert client.post(route + "/cmd-durable-poll/accept", headers=auth).status_code == 200
    assert client.get(route + "?delivery_mode=durable", headers=auth).json() == {"commands": []}
