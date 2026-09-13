from datetime import datetime, timedelta, timezone

from fastapi.testclient import TestClient


def _enroll(client: TestClient, agent_id: str, host_id: str) -> str:
    response = client.post(
        "/api/v1/agents/enroll",
        json={"agent_id": agent_id, "host_id": host_id},
        headers={"X-Panopticon-Enrollment-Token": "test-bootstrap-token"},
    )
    assert response.status_code == 200
    return str(response.json()["access_token"])


def _queue(client: TestClient, command: dict) -> None:
    response = client.post(
        "/api/v1/commands",
        json=command,
        headers={"X-Panopticon-Command-Token": "test-command-token"},
    )
    assert response.status_code == 200


def test_closed_command_queue_requires_authorization_and_scopes_polling(client: TestClient) -> None:
    enrollment = client.post(
        "/api/v1/agents/enroll",
        json={"agent_id": "agent-1", "host_id": "host-1"},
        headers={"X-Panopticon-Enrollment-Token": "test-bootstrap-token"},
    )
    assert enrollment.status_code == 200
    command = {
        "command_id": "cmd-1",
        "agent_id": "agent-1",
        "action": "COLLECT_PROCESS_INFO",
        "expires_at": (datetime.now(timezone.utc) + timedelta(minutes=5)).isoformat(),
        "target": {"pid": 42, "start_time_ticks": 99},
    }
    assert client.post("/api/v1/commands", json=command).status_code == 422
    queued = client.post(
        "/api/v1/commands",
        json=command,
        headers={"X-Panopticon-Command-Token": "test-command-token"},
    )
    assert queued.status_code == 200
    polled = client.get(
        "/api/v1/agents/agent-1/commands",
        headers={"Authorization": f"Bearer {enrollment.json()['access_token']}"},
    )
    assert polled.status_code == 200
    assert polled.json()["commands"][0]["action"] == "COLLECT_PROCESS_INFO"
    assert polled.json()["commands"][0]["host_id"] == "host-1"
    assert polled.json()["commands"][0]["schema_version"] == "1"
    result = client.post(
        "/api/v1/agents/agent-1/command-results",
        json={
            "result_id": "result-1",
            "command_id": "cmd-1",
            "outcome": "succeeded",
            "detail": "bounded",
            "correlation_id": polled.json()["commands"][0]["correlation_id"],
        },
        headers={"Authorization": f"Bearer {enrollment.json()['access_token']}"},
    )
    assert result.status_code == 200


def test_delivered_command_is_not_repolled(client: TestClient) -> None:
    token = _enroll(client, "agent-1", "host-1")
    _queue(
        client,
        {
            "command_id": "cmd-delivered",
            "agent_id": "agent-1",
            "action": "COLLECT_NETWORK_CONNECTIONS",
            "expires_at": (datetime.now(timezone.utc) + timedelta(minutes=5)).isoformat(),
        },
    )
    headers = {"Authorization": f"Bearer {token}"}
    first = client.get("/api/v1/agents/agent-1/commands", headers=headers)
    assert len(first.json()["commands"]) == 1
    second = client.get("/api/v1/agents/agent-1/commands", headers=headers)
    assert second.json()["commands"] == []


def test_expired_command_is_not_polled(client: TestClient) -> None:
    token = _enroll(client, "agent-1", "host-1")
    # A command can't be created already-expired (rejected at creation), so queue
    # one that expires almost immediately and let it lapse before polling.
    _queue(
        client,
        {
            "command_id": "cmd-expiring",
            "agent_id": "agent-1",
            "action": "COLLECT_NETWORK_CONNECTIONS",
            "expires_at": (datetime.now(timezone.utc) + timedelta(milliseconds=200)).isoformat(),
        },
    )
    import time

    time.sleep(0.3)
    polled = client.get(
        "/api/v1/agents/agent-1/commands", headers={"Authorization": f"Bearer {token}"}
    )
    assert polled.json()["commands"] == []


def test_expired_command_result_is_rejected(client: TestClient) -> None:
    token = _enroll(client, "agent-1", "host-1")
    _queue(
        client,
        {
            "command_id": "cmd-expires-before-result",
            "agent_id": "agent-1",
            "action": "COLLECT_NETWORK_CONNECTIONS",
            "expires_at": (datetime.now(timezone.utc) + timedelta(minutes=5)).isoformat(),
        },
    )
    headers = {"Authorization": f"Bearer {token}"}
    polled = client.get("/api/v1/agents/agent-1/commands", headers=headers)
    assert len(polled.json()["commands"]) == 1
    # Directly expire the already-delivered command to simulate time passing
    # past its expiry before the agent reports back.
    import manager.db as db_module

    conn = db_module.connect()
    lapsed = (datetime.now(timezone.utc) - timedelta(seconds=1)).isoformat()
    conn.execute(
        "UPDATE commands SET expires_at = ? WHERE command_id = ?",
        (lapsed, "cmd-expires-before-result"),
    )
    conn.commit()
    result = client.post(
        "/api/v1/agents/agent-1/command-results",
        json={
            "result_id": "result-expired",
            "command_id": "cmd-expires-before-result",
            "outcome": "succeeded",
        },
        headers=headers,
    )
    assert result.status_code == 422


def test_duplicate_command_id_is_rejected_cleanly(client: TestClient) -> None:
    _enroll(client, "agent-1", "host-1")
    command = {
        "command_id": "cmd-dup",
        "agent_id": "agent-1",
        "action": "COLLECT_NETWORK_CONNECTIONS",
        "expires_at": (datetime.now(timezone.utc) + timedelta(minutes=5)).isoformat(),
    }
    _queue(client, command)
    replay = client.post(
        "/api/v1/commands",
        json=command,
        headers={"X-Panopticon-Command-Token": "test-command-token"},
    )
    assert replay.status_code == 409


def test_agent_cannot_poll_another_agents_commands(client: TestClient) -> None:
    token_a = _enroll(client, "agent-a", "host-a")
    token_b = _enroll(client, "agent-b", "host-b")
    _queue(
        client,
        {
            "command_id": "cmd-for-a",
            "agent_id": "agent-a",
            "action": "COLLECT_NETWORK_CONNECTIONS",
            "expires_at": (datetime.now(timezone.utc) + timedelta(minutes=5)).isoformat(),
        },
    )
    # agent-b's own valid token must never surface agent-a's queued command.
    polled_by_b = client.get(
        "/api/v1/agents/agent-a/commands", headers={"Authorization": f"Bearer {token_b}"}
    )
    assert polled_by_b.status_code == 401
    polled_by_a = client.get(
        "/api/v1/agents/agent-a/commands", headers={"Authorization": f"Bearer {token_a}"}
    )
    assert len(polled_by_a.json()["commands"]) == 1


def test_result_cannot_be_submitted_for_another_agents_command(client: TestClient) -> None:
    _enroll(client, "agent-a", "host-a")
    token_b = _enroll(client, "agent-b", "host-b")
    _queue(
        client,
        {
            "command_id": "cmd-owned-by-a",
            "agent_id": "agent-a",
            "action": "COLLECT_NETWORK_CONNECTIONS",
            "expires_at": (datetime.now(timezone.utc) + timedelta(minutes=5)).isoformat(),
        },
    )
    spoofed = client.post(
        "/api/v1/agents/agent-b/command-results",
        json={
            "result_id": "result-spoof",
            "command_id": "cmd-owned-by-a",
            "outcome": "succeeded",
        },
        headers={"Authorization": f"Bearer {token_b}"},
    )
    assert spoofed.status_code == 422


def test_expired_command_transitions_to_expired_lifecycle_state(client: TestClient) -> None:
    _enroll(client, "agent-1", "host-1")
    _queue(
        client,
        {
            "command_id": "cmd-lifecycle-expiry",
            "agent_id": "agent-1",
            "action": "COLLECT_NETWORK_CONNECTIONS",
            "expires_at": (datetime.now(timezone.utc) + timedelta(milliseconds=200)).isoformat(),
        },
    )
    import time

    time.sleep(0.3)
    # Any authenticated poll (even for a different, unrelated agent) sweeps
    # every stale command, since there is no separate scheduler.
    other_token = _enroll(client, "agent-2", "host-2")
    client.get(
        "/api/v1/agents/agent-2/commands", headers={"Authorization": f"Bearer {other_token}"}
    )
    import manager.db as db_module

    row = db_module.connect().execute(
        "SELECT lifecycle_state FROM commands WHERE command_id = ?", ("cmd-lifecycle-expiry",)
    ).fetchone()
    assert row["lifecycle_state"] == "EXPIRED"


def test_second_distinct_result_never_overwrites_a_terminal_outcome(client: TestClient) -> None:
    token = _enroll(client, "agent-1", "host-1")
    _queue(
        client,
        {
            "command_id": "cmd-replayed-result",
            "agent_id": "agent-1",
            "action": "COLLECT_NETWORK_CONNECTIONS",
            "expires_at": (datetime.now(timezone.utc) + timedelta(minutes=5)).isoformat(),
        },
    )
    headers = {"Authorization": f"Bearer {token}"}
    client.get("/api/v1/agents/agent-1/commands", headers=headers)
    first = client.post(
        "/api/v1/agents/agent-1/command-results",
        json={
            "result_id": "result-real",
            "command_id": "cmd-replayed-result",
            "outcome": "succeeded",
        },
        headers=headers,
    )
    assert first.status_code == 200
    # A second, distinct result_id for the same command (a forged/replayed or
    # buggy duplicate submission) must be accepted (not error the caller) but
    # must never flip the already-terminal lifecycle_state.
    second = client.post(
        "/api/v1/agents/agent-1/command-results",
        json={
            "result_id": "result-forged",
            "command_id": "cmd-replayed-result",
            "outcome": "failed",
        },
        headers=headers,
    )
    assert second.status_code == 200
    import manager.db as db_module

    row = db_module.connect().execute(
        "SELECT lifecycle_state FROM commands WHERE command_id = ?", ("cmd-replayed-result",)
    ).fetchone()
    assert row["lifecycle_state"] == "SUCCEEDED"
    count = db_module.connect().execute(
        "SELECT COUNT(*) AS c FROM command_results WHERE command_id = ?",
        ("cmd-replayed-result",),
    ).fetchone()["c"]
    # The forged/duplicate result_id is not persisted as a second result row.
    assert count == 1


def test_accept_transitions_dispatched_to_accepted_and_result_still_lands(
    client: TestClient,
) -> None:
    token = _enroll(client, "agent-1", "host-1")
    _queue(
        client,
        {
            "command_id": "cmd-accept-then-result",
            "agent_id": "agent-1",
            "action": "COLLECT_NETWORK_CONNECTIONS",
            "expires_at": (datetime.now(timezone.utc) + timedelta(minutes=5)).isoformat(),
        },
    )
    headers = {"Authorization": f"Bearer {token}"}
    client.get("/api/v1/agents/agent-1/commands", headers=headers)
    accepted = client.post(
        "/api/v1/agents/agent-1/commands/cmd-accept-then-result/accept", headers=headers
    )
    assert accepted.status_code == 200
    import manager.db as db_module

    row = db_module.connect().execute(
        "SELECT lifecycle_state FROM commands WHERE command_id = ?",
        ("cmd-accept-then-result",),
    ).fetchone()
    assert row["lifecycle_state"] == "ACCEPTED"
    result = client.post(
        "/api/v1/agents/agent-1/command-results",
        json={
            "result_id": "result-after-accept",
            "command_id": "cmd-accept-then-result",
            "outcome": "succeeded",
        },
        headers=headers,
    )
    assert result.status_code == 200
    row = db_module.connect().execute(
        "SELECT lifecycle_state FROM commands WHERE command_id = ?",
        ("cmd-accept-then-result",),
    ).fetchone()
    assert row["lifecycle_state"] == "SUCCEEDED"


def test_result_without_prior_accept_still_works(client: TestClient) -> None:
    token = _enroll(client, "agent-1", "host-1")
    _queue(
        client,
        {
            "command_id": "cmd-no-accept",
            "agent_id": "agent-1",
            "action": "COLLECT_NETWORK_CONNECTIONS",
            "expires_at": (datetime.now(timezone.utc) + timedelta(minutes=5)).isoformat(),
        },
    )
    headers = {"Authorization": f"Bearer {token}"}
    client.get("/api/v1/agents/agent-1/commands", headers=headers)
    # An agent that never calls accept() (the old, still-supported protocol)
    # must still be able to submit a result straight from DISPATCHED.
    result = client.post(
        "/api/v1/agents/agent-1/command-results",
        json={"result_id": "result-no-accept", "command_id": "cmd-no-accept", "outcome": "failed"},
        headers=headers,
    )
    assert result.status_code == 200


def test_duplicate_accept_is_idempotent(client: TestClient) -> None:
    token = _enroll(client, "agent-1", "host-1")
    _queue(
        client,
        {
            "command_id": "cmd-dup-accept",
            "agent_id": "agent-1",
            "action": "COLLECT_NETWORK_CONNECTIONS",
            "expires_at": (datetime.now(timezone.utc) + timedelta(minutes=5)).isoformat(),
        },
    )
    headers = {"Authorization": f"Bearer {token}"}
    client.get("/api/v1/agents/agent-1/commands", headers=headers)
    first = client.post(
        "/api/v1/agents/agent-1/commands/cmd-dup-accept/accept", headers=headers
    )
    second = client.post(
        "/api/v1/agents/agent-1/commands/cmd-dup-accept/accept", headers=headers
    )
    assert first.status_code == 200
    assert second.status_code == 200


def test_late_accept_after_terminal_result_does_not_revert_state(client: TestClient) -> None:
    token = _enroll(client, "agent-1", "host-1")
    _queue(
        client,
        {
            "command_id": "cmd-late-accept",
            "agent_id": "agent-1",
            "action": "COLLECT_NETWORK_CONNECTIONS",
            "expires_at": (datetime.now(timezone.utc) + timedelta(minutes=5)).isoformat(),
        },
    )
    headers = {"Authorization": f"Bearer {token}"}
    client.get("/api/v1/agents/agent-1/commands", headers=headers)
    client.post(
        "/api/v1/agents/agent-1/command-results",
        json={"result_id": "result-first", "command_id": "cmd-late-accept", "outcome": "succeeded"},
        headers=headers,
    )
    # A late/replayed accept() arriving after the result must never move a
    # terminal command backwards into ACCEPTED.
    late_accept = client.post(
        "/api/v1/agents/agent-1/commands/cmd-late-accept/accept", headers=headers
    )
    assert late_accept.status_code == 200
    import manager.db as db_module

    row = db_module.connect().execute(
        "SELECT lifecycle_state FROM commands WHERE command_id = ?", ("cmd-late-accept",)
    ).fetchone()
    assert row["lifecycle_state"] == "SUCCEEDED"


def test_accept_rejected_for_wrong_agent(client: TestClient) -> None:
    _enroll(client, "agent-a", "host-a")
    token_b = _enroll(client, "agent-b", "host-b")
    _queue(
        client,
        {
            "command_id": "cmd-accept-owned-by-a",
            "agent_id": "agent-a",
            "action": "COLLECT_NETWORK_CONNECTIONS",
            "expires_at": (datetime.now(timezone.utc) + timedelta(minutes=5)).isoformat(),
        },
    )
    spoofed = client.post(
        "/api/v1/agents/agent-b/commands/cmd-accept-owned-by-a/accept",
        headers={"Authorization": f"Bearer {token_b}"},
    )
    assert spoofed.status_code == 422


def test_duplicate_result_submission_is_idempotent(client: TestClient) -> None:
    token = _enroll(client, "agent-1", "host-1")
    _queue(
        client,
        {
            "command_id": "cmd-dup-result",
            "agent_id": "agent-1",
            "action": "COLLECT_NETWORK_CONNECTIONS",
            "expires_at": (datetime.now(timezone.utc) + timedelta(minutes=5)).isoformat(),
        },
    )
    headers = {"Authorization": f"Bearer {token}"}
    client.get("/api/v1/agents/agent-1/commands", headers=headers)
    payload = {
        "result_id": "result-dup",
        "command_id": "cmd-dup-result",
        "outcome": "succeeded",
    }
    first = client.post("/api/v1/agents/agent-1/command-results", json=payload, headers=headers)
    second = client.post("/api/v1/agents/agent-1/command-results", json=payload, headers=headers)
    assert first.status_code == 200
    assert second.status_code == 200
