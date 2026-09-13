from datetime import datetime, timezone
from uuid import uuid4

from fastapi.testclient import TestClient

from tests.test_command_route import _enroll


def _enroll_analyst(client: TestClient, analyst_id: str) -> str:
    response = client.post(
        "/api/v1/analysts/enroll",
        json={"analyst_id": analyst_id},
        headers={"X-Panopticon-Analyst-Enrollment-Token": "test-analyst-bootstrap-token"},
    )
    assert response.status_code == 200
    return str(response.json()["access_token"])


def _stage_response_action(agent_id: str, alert_id: str, action: str = "ISOLATE_HOST") -> str:
    """Directly stages a PENDING response_actions row (bypassing detection)
    so the authorize/reject HTTP surface can be tested independently of the
    vendored detection engine -- manager/detection/response.py's own
    translation/tiering logic is covered in tests/test_response_engine.py."""
    import manager.db as db_module

    conn = db_module.connect()
    now = datetime.now(timezone.utc).isoformat()
    conn.execute(
        "INSERT INTO alerts (alert_id, rule_id, agent_id, created_at, alert_json) "
        "VALUES (?, 'rule-1', ?, ?, '{}')",
        (alert_id, agent_id, now),
    )
    response_id = str(uuid4())
    conn.execute(
        "INSERT INTO response_actions "
        "(response_id, alert_id, action, tier, lifecycle_state, target_json, command_id, "
        "created_at, authorized_at, authorized_by, decided_reason) "
        "VALUES (?, ?, ?, 'ANALYST_APPROVAL', 'PENDING', '{}', NULL, ?, NULL, NULL, "
        "'test fixture')",
        (response_id, alert_id, action, now),
    )
    conn.commit()
    return response_id


def test_response_actions_endpoints_require_analyst_token(client: TestClient) -> None:
    assert client.get("/api/v1/response-actions").status_code == 401
    assert client.post("/api/v1/response-actions/does-not-exist/authorize").status_code == 401
    rejected = client.post("/api/v1/response-actions/does-not-exist/reject", json={"reason": "x"})
    assert rejected.status_code == 401


def test_analyst_enroll_rejects_wrong_bootstrap_token(client: TestClient) -> None:
    resp = client.post(
        "/api/v1/analysts/enroll",
        json={"analyst_id": "alice"},
        headers={"X-Panopticon-Analyst-Enrollment-Token": "wrong-token"},
    )
    assert resp.status_code == 401


def test_analyst_token_does_not_authenticate_as_an_agent_or_vice_versa(client: TestClient) -> None:
    agent_token = _enroll(client, "agent-1", "host-1")
    analyst_token = _enroll_analyst(client, "alice")
    # An agent bearer token must never satisfy the analyst-gated surface.
    assert client.get(
        "/api/v1/response-actions", headers={"Authorization": f"Bearer {agent_token}"}
    ).status_code == 401
    # An analyst bearer token must never satisfy the agent-gated surface.
    assert client.get(
        "/api/v1/agents/agent-1/commands", headers={"Authorization": f"Bearer {analyst_token}"}
    ).status_code == 401


def test_authorize_pending_response_action_creates_a_dispatchable_command(
    client: TestClient,
) -> None:
    agent_token = _enroll(client, "agent-1", "host-1")
    analyst_token = _enroll_analyst(client, "alice")
    response_id = _stage_response_action("agent-1", "ALT-int-1")

    analyst_headers = {"Authorization": f"Bearer {analyst_token}"}
    listed = client.get("/api/v1/response-actions", headers=analyst_headers)
    assert listed.status_code == 200
    assert any(row["response_id"] == response_id for row in listed.json()["response_actions"])

    authorized = client.post(
        f"/api/v1/response-actions/{response_id}/authorize", headers=analyst_headers
    )
    assert authorized.status_code == 200

    polled = client.get(
        "/api/v1/agents/agent-1/commands", headers={"Authorization": f"Bearer {agent_token}"}
    )
    commands = polled.json()["commands"]
    assert len(commands) == 1
    assert commands[0]["action"] == "ISOLATE_HOST"

    listed_again = client.get("/api/v1/response-actions?state=AUTHORIZED", headers=analyst_headers)
    response_actions = listed_again.json()["response_actions"]
    rows = [row for row in response_actions if row["response_id"] == response_id]
    assert len(rows) == 1
    assert rows[0]["authorized_by"] == "analyst:alice"
    assert rows[0]["command_id"] is not None


def test_authorizing_the_same_response_action_twice_is_rejected(client: TestClient) -> None:
    _enroll(client, "agent-1", "host-1")
    analyst_token = _enroll_analyst(client, "alice")
    response_id = _stage_response_action("agent-1", "ALT-int-2")
    headers = {"Authorization": f"Bearer {analyst_token}"}
    first = client.post(f"/api/v1/response-actions/{response_id}/authorize", headers=headers)
    assert first.status_code == 200
    second = client.post(f"/api/v1/response-actions/{response_id}/authorize", headers=headers)
    assert second.status_code == 404


def test_authorize_unknown_response_action_is_404(client: TestClient) -> None:
    analyst_token = _enroll_analyst(client, "alice")
    resp = client.post(
        "/api/v1/response-actions/does-not-exist/authorize",
        headers={"Authorization": f"Bearer {analyst_token}"},
    )
    assert resp.status_code == 404


def test_reject_pending_response_action_never_creates_a_command(client: TestClient) -> None:
    _enroll(client, "agent-1", "host-1")
    analyst_token = _enroll_analyst(client, "alice")
    response_id = _stage_response_action("agent-1", "ALT-int-3")

    rejected = client.post(
        f"/api/v1/response-actions/{response_id}/reject",
        json={"reason": "confirmed benign"},
        headers={"Authorization": f"Bearer {analyst_token}"},
    )
    assert rejected.status_code == 200

    analyst_headers = {"Authorization": f"Bearer {analyst_token}"}
    listed = client.get("/api/v1/response-actions?state=REJECTED", headers=analyst_headers)
    response_actions = listed.json()["response_actions"]
    rows = [row for row in response_actions if row["response_id"] == response_id]
    assert len(rows) == 1
    assert rows[0]["command_id"] is None
    assert rows[0]["decided_reason"] == "confirmed benign"


def test_stale_pending_response_action_expires_and_cannot_be_authorized(
    client: TestClient,
) -> None:
    _enroll(client, "agent-1", "host-1")
    analyst_token = _enroll_analyst(client, "alice")
    response_id = _stage_response_action("agent-1", "ALT-int-expiry")

    from datetime import timedelta

    import manager.db as db_module

    conn = db_module.connect()
    stale = (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()
    conn.execute(
        "UPDATE response_actions SET created_at = ? WHERE response_id = ?",
        (stale, response_id),
    )
    conn.commit()

    headers = {"Authorization": f"Bearer {analyst_token}"}
    # Listing sweeps stale PENDING rows to EXPIRED as a side effect of the read.
    listed = client.get("/api/v1/response-actions?state=EXPIRED", headers=headers)
    rows = [row for row in listed.json()["response_actions"] if row["response_id"] == response_id]
    assert len(rows) == 1

    authorized = client.post(f"/api/v1/response-actions/{response_id}/authorize", headers=headers)
    assert authorized.status_code == 404


def test_kill_process_isolate_host_and_release_always_require_analyst_approval(
    client: TestClient,
) -> None:
    # Direct confirmation of the locked tier decisions via the same module
    # the authorize/reject endpoints call -- a regression here would silently
    # let one of these three auto-fire from a detection.
    from manager.detection.response import classify_tier

    assert classify_tier("KILL_PROCESS") == "ANALYST_APPROVAL"
    assert classify_tier("ISOLATE_HOST") == "ANALYST_APPROVAL"
    assert classify_tier("RELEASE_HOST_ISOLATION") == "ANALYST_APPROVAL"
