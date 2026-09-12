from datetime import datetime, timedelta, timezone

from fastapi.testclient import TestClient


def test_closed_command_queue_requires_authorization_and_scopes_polling(client: TestClient) -> None:
    enrollment = client.post(
        "/api/v1/agents/enroll", json={"agent_id": "agent-1", "host_id": "host-1"},
        headers={"X-Panopticon-Enrollment-Token": "test-bootstrap-token"},
    )
    assert enrollment.status_code == 200
    command = {"command_id": "cmd-1", "agent_id": "agent-1", "action": "COLLECT_PROCESS_INFO", "expires_at": (datetime.now(timezone.utc) + timedelta(minutes=5)).isoformat(), "target": {}}
    assert client.post("/api/v1/commands", json=command).status_code == 422
    queued = client.post("/api/v1/commands", json=command, headers={"X-Panopticon-Command-Token": "test-command-token"})
    assert queued.status_code == 200
    polled = client.get("/api/v1/agents/agent-1/commands", headers={"Authorization": f"Bearer {enrollment.json()['access_token']}"})
    assert polled.status_code == 200
    assert polled.json()["commands"][0]["action"] == "COLLECT_PROCESS_INFO"
