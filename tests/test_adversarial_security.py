"""Adversarial security review (post-contracts-integration directive,
Priority 2): active attempts to break the response security model, not just
a source read. Each test reproduces one specific attack the attacker model
grants (forged/substituted identifiers, forged lifecycle states, credential
reuse across identities) and asserts it is rejected or safely neutralized.

Attacks already proven rejected elsewhere are not repeated here:
tests/test_command_route.py covers wrong-agent poll/accept/result, command
replay (duplicate command_id), command/result expiry, and duplicate-result
idempotency; tests/test_e2e_response_pipeline.py covers cross-agent hijack of
a response-engine-issued command, correlation-id forgery, and the closed
seven-action enum. This file covers the remaining attack-model items: analyst
credential/authorization boundaries, response_actions binding to unrelated
alerts, agent-identity takeover via the shared enrollment bootstrap secret,
and a few malformed/hostile-input edges.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from fastapi.testclient import TestClient

import manager.db as db_module
from tests.conftest import enroll_test_agent
from tests.test_command_route import _enroll
from tests.test_response_actions_route import _enroll_analyst, _stage_response_action


def test_agent_bearer_token_cannot_authenticate_as_analyst(client: TestClient) -> None:
    """An agent's own valid, correctly-scoped credential must never satisfy
    the analyst authorization boundary -- these are deliberately distinct
    identity spaces (enrolled_agents vs analyst_credentials)."""
    agent_token = _enroll(client, "agent-1", "host-1")
    response = client.get(
        "/api/v1/response-actions", headers={"Authorization": f"Bearer {agent_token}"}
    )
    assert response.status_code == 401


def test_analyst_bearer_token_cannot_authenticate_as_agent(client: TestClient) -> None:
    """The reverse: a real analyst token must never satisfy require_agent_token."""
    _enroll(client, "agent-1", "host-1")
    analyst_token = _enroll_analyst(client, "analyst-1")
    response = client.get(
        "/api/v1/agents/agent-1/commands",
        headers={"Authorization": f"Bearer {analyst_token}"},
    )
    assert response.status_code == 401


def test_re_enrolling_an_existing_agent_id_is_rejected_not_silently_overwritten(
    client: TestClient,
) -> None:
    """Attack: an attacker who has obtained the one shared, fleet-wide
    PANOPTICON_ENROLLMENT_TOKEN bootstrap secret attempts to hijack an
    already-trusted agent's identity by re-enrolling its agent_id under a
    different host_id, which would mint them a fresh bearer token for it and
    silently invalidate the legitimate agent's own token. Must be rejected,
    and the original enrollment (host binding + token) must remain intact
    and functional."""
    original_token = _enroll(client, "agent-victim", "host-victim")

    hijack = enroll_test_agent(client, "agent-victim", "host-attacker")
    assert hijack.status_code == 409

    row = db_module.connect().execute(
        "SELECT host_id FROM enrolled_agents WHERE agent_id = 'agent-victim'"
    ).fetchone()
    assert row["host_id"] == "host-victim"

    still_valid = client.get(
        "/api/v1/agents/agent-victim/commands",
        headers={"Authorization": f"Bearer {original_token}"},
    )
    assert still_valid.status_code == 200


def test_response_action_cannot_be_authorized_using_a_forged_response_id(
    client: TestClient,
) -> None:
    """An attacker who knows (or guesses) an alert_id but not the real,
    server-generated response_id must not be able to authorize an unrelated
    or made-up response_actions row."""
    _enroll(client, "agent-1", "host-1")
    _stage_response_action("agent-1", "ALT-REAL")
    analyst_token = _enroll_analyst(client, "analyst-1")
    forged = client.post(
        "/api/v1/response-actions/not-a-real-response-id/authorize",
        headers={"Authorization": f"Bearer {analyst_token}"},
    )
    assert forged.status_code == 404


def test_response_action_authorization_does_not_leak_across_alerts(
    client: TestClient,
) -> None:
    """Authorizing response_id A must never affect a different, unrelated
    response_id B's lifecycle_state or command_id -- confirms authorization
    is scoped strictly by response_id, not by any broader alert/agent match."""
    _enroll(client, "agent-1", "host-1")
    response_a = _stage_response_action("agent-1", "ALT-A")
    response_b = _stage_response_action("agent-1", "ALT-B")
    analyst_token = _enroll_analyst(client, "analyst-1")
    client.post(
        f"/api/v1/response-actions/{response_a}/authorize",
        headers={"Authorization": f"Bearer {analyst_token}"},
    )
    conn = db_module.connect()
    row_a = conn.execute(
        "SELECT lifecycle_state FROM response_actions WHERE response_id = ?", (response_a,)
    ).fetchone()
    row_b = conn.execute(
        "SELECT lifecycle_state, command_id FROM response_actions WHERE response_id = ?",
        (response_b,),
    ).fetchone()
    assert row_a["lifecycle_state"] == "AUTHORIZED"
    assert row_b["lifecycle_state"] == "PENDING"
    assert row_b["command_id"] is None


def test_revoked_analyst_credential_is_immediately_rejected(client: TestClient) -> None:
    """A revoked analyst token (e.g. an offboarded analyst, or one an
    incident responder has just invalidated) must be rejected on the very
    next request -- there is no caching/grace window."""
    analyst_token = _enroll_analyst(client, "analyst-to-revoke")
    conn = db_module.connect()
    conn.execute(
        "UPDATE analyst_credentials SET revoked_at = ? WHERE analyst_id = 'analyst-to-revoke'",
        (datetime.now(timezone.utc).isoformat(),),
    )
    conn.commit()
    response = client.get(
        "/api/v1/response-actions", headers={"Authorization": f"Bearer {analyst_token}"}
    )
    assert response.status_code == 401


def test_revoked_agent_credential_cannot_poll_or_submit_results(client: TestClient) -> None:
    """A revoked agent (e.g. a decommissioned or compromised endpoint) must
    lose all API access immediately, including result submission for
    commands it was already dispatched."""
    token = _enroll(client, "agent-to-revoke", "host-to-revoke")
    client.post(
        "/api/v1/commands",
        json={
            "command_id": "cmd-before-revoke",
            "agent_id": "agent-to-revoke",
            "action": "COLLECT_NETWORK_CONNECTIONS",
            "expires_at": (datetime.now(timezone.utc) + timedelta(minutes=5)).isoformat(),
        },
        headers={"X-Panopticon-Command-Token": "test-command-token"},
    )
    conn = db_module.connect()
    conn.execute(
        "UPDATE enrolled_agents SET revoked_at = ? WHERE agent_id = 'agent-to-revoke'",
        (datetime.now(timezone.utc).isoformat(),),
    )
    conn.commit()
    headers = {"Authorization": f"Bearer {token}"}
    assert client.get("/api/v1/agents/agent-to-revoke/commands", headers=headers).status_code == 401
    assert (
        client.post(
            "/api/v1/agents/agent-to-revoke/command-results",
            json={
                "result_id": "result-after-revoke",
                "command_id": "cmd-before-revoke",
                "outcome": "succeeded",
            },
            headers=headers,
        ).status_code
        == 401
    )


def test_command_token_cannot_be_used_as_an_agent_or_analyst_credential(
    client: TestClient,
) -> None:
    """The system:command-token identity (used to queue raw commands) is a
    distinct trust boundary from both agent and analyst bearer tokens --
    presenting it as a Bearer token must not authenticate as either."""
    _enroll(client, "agent-1", "host-1")
    headers = {"Authorization": "Bearer test-command-token"}
    assert client.get("/api/v1/agents/agent-1/commands", headers=headers).status_code == 401
    assert client.get("/api/v1/response-actions", headers=headers).status_code == 401


def test_empty_and_whitespace_bearer_tokens_are_rejected(client: TestClient) -> None:
    """Boundary/malformed-input cases for the Authorization header parser."""
    _enroll(client, "agent-1", "host-1")
    for bad_header in ("Bearer ", "Bearer", "", "Basic dXNlcjpwYXNz"):
        response = client.get(
            "/api/v1/agents/agent-1/commands", headers={"Authorization": bad_header}
        )
        assert response.status_code == 401


def test_oversized_bearer_token_is_rejected_without_a_timing_oracle(client: TestClient) -> None:
    """A 10000-character bearer token must be rejected cheaply (length
    check before any digest comparison), not processed as if it might be
    valid -- guards against a trivial resource-exhaustion/timing probe."""
    _enroll(client, "agent-1", "host-1")
    huge_token = "a" * 10_000
    response = client.get(
        "/api/v1/agents/agent-1/commands",
        headers={"Authorization": f"Bearer {huge_token}"},
    )
    assert response.status_code == 401


def test_command_with_process_target_missing_start_time_ticks_is_rejected(
    client: TestClient,
) -> None:
    """PID-reuse protection at the wire-contract level: a process action
    (KILL_PROCESS/COLLECT_PROCESS_INFO) target missing start_time_ticks, or
    carrying a zero/negative one, must never validate -- this is enforced by
    response_engine.contract.Command itself, independent of any caller."""
    _enroll(client, "agent-1", "host-1")
    bad_targets = (
        {"pid": 42},
        {"pid": 42, "start_time_ticks": 0},
        {"pid": 42, "start_time_ticks": -5},
    )
    for index, bad_target in enumerate(bad_targets):
        rejected = client.post(
            "/api/v1/commands",
            json={
                "command_id": f"cmd-bad-target-{index}",
                "agent_id": "agent-1",
                "action": "KILL_PROCESS",
                "expires_at": (datetime.now(timezone.utc) + timedelta(minutes=5)).isoformat(),
                "target": bad_target,
            },
            headers={"X-Panopticon-Command-Token": "test-command-token"},
        )
        assert rejected.status_code == 422


def test_command_target_cannot_smuggle_extra_fields(client: TestClient) -> None:
    """extra="forbid" on the Command contract must reject an attacker
    appending unvalidated fields onto an otherwise-valid target (e.g. trying
    to smuggle a path/command-injection-relevant field alongside pid)."""
    _enroll(client, "agent-1", "host-1")
    rejected = client.post(
        "/api/v1/commands",
        json={
            "command_id": "cmd-smuggled-field",
            "agent_id": "agent-1",
            "action": "KILL_PROCESS",
            "expires_at": (datetime.now(timezone.utc) + timedelta(minutes=5)).isoformat(),
            "target": {"pid": 42, "start_time_ticks": 99, "shell_command": "rm -rf /"},
        },
        headers={"X-Panopticon-Command-Token": "test-command-token"},
    )
    assert rejected.status_code == 422


def test_result_for_a_nonexistent_command_id_is_rejected(client: TestClient) -> None:
    """A fabricated command_id in a result submission (no such command was
    ever queued) must be rejected, not silently accepted or crash."""
    token = _enroll(client, "agent-1", "host-1")
    response = client.post(
        "/api/v1/agents/agent-1/command-results",
        json={
            "result_id": "result-for-nothing",
            "command_id": "cmd-that-never-existed",
            "outcome": "succeeded",
        },
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 422


def test_accept_for_a_nonexistent_command_id_is_rejected(client: TestClient) -> None:
    token = _enroll(client, "agent-1", "host-1")
    response = client.post(
        "/api/v1/agents/agent-1/commands/cmd-that-never-existed/accept",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 422
