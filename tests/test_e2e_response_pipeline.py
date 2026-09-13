"""True vertical-slice tests: real vendor/eyedetect detection engine -> real
Alert -> manager.detection.response (translation + tiering) -> response_actions
authorization -> commands router (dispatch/accept/result) -> command_audit,
exercised through the same public HTTP surface a Linux/Windows agent uses.

Detection Engine -> Manager alert -> Response Engine -> authorization/policy ->
typed command -> endpoint dispatch -> ACCEPTED -> execution -> typed result ->
lifecycle update -> audit.

Two gaps in the *real* detector's active-response vocabulary make two of the
directive's named scenarios impossible to trigger from genuine eyedetect
output today, both already documented and accepted at this exact boundary by
tests/test_response_engine.py's test_on_alert_created_auto_safe_action_is_
enqueued_immediately and test_on_alert_created_terminate_process_with_start_
time_stages_kill_process_pending:

  * eyedetect's ActiveResponseEngine.resolve_action only ever emits
    TERMINATE_PROCESS / BLOCK_FIREWALL_IP / ISOLATE_HOST -- there is no rule
    or code path anywhere in vendor/eyedetect that recommends
    COLLECT_PROCESS_INFO or COLLECT_NETWORK_CONNECTIONS, so the AUTO_SAFE
    "safe collection" scenario can never be produced by the real detector.
  * ActiveResponseAction (vendor/eyedetect/src/alerting/active_response.py)
    has no target_start_time_ticks field at all, so translate_recommendation's
    PID-reuse-safety gate (response_engine/recommendation.py) can never be
    satisfied by real eyedetect output either -- every real TERMINATE_PROCESS
    recommendation fails closed today (see test_kill_process_real_detector_
    recommendation_fails_closed_without_start_time below, which proves this
    against genuine engine output rather than assuming it).

Per the operating directive, these are pre-existing eyedetect limitations,
not this test's bug to fix by touching vendor/eyedetect -- both are recorded
in docs/RESPONSE_ENGINE_STATE.md. The two scenarios plug in at the
translate_recommendation boundary the existing unit tests already established
as legitimate. Everything else here -- the DET-FREQ-001 threshold detection,
the Alert, the response_actions row, the command, and the full dispatch/
accept/result/audit lifecycle -- is the real, unmodified production path.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient

import manager.db as db_module
from manager.detection.factory import build_detection_run
from tests.test_command_route import _enroll
from tests.test_response_actions_route import _enroll_analyst

_HOST_ID = "HOST-E2E"
_GUID = "proc_" + "e" * 64


def _ransomware_burst_events(count: int = 5) -> list[dict]:
    """Five file_create events, same host/process, inside DET-FREQ-001's
    10s window -- deterministically trips the real ThresholdEngine default
    rule (frequency=5) without depending on vendor/eyedetect's YAML rule set
    or the CORR-003-affected correlation engine at all."""
    return [
        {
            "event_type": "file_create",
            "event_id": f"evt_e2e_burst_{index:03d}",
            "host_id": _HOST_ID,
            "timestamp": f"2026-09-13T12:00:0{index}.000Z",
            "process": {"name": "ransom.exe", "pid": 9999, "process_guid": _GUID},
            "file": {"path": f"C:\\Users\\victim\\Documents\\file{index}.locked"},
        }
        for index in range(count)
    ]


def _run_real_detector_burst(tmp_path, agent_id: str) -> None:
    """Feeds the burst through the real, unmodified DetectionRun/AlertSink
    pipeline (manager/detection/factory.py) against the same DB file the
    test's TestClient is using -- exactly the path manager/detection/worker.py
    exercises in production, minus the async queue."""
    conn = db_module.connect()
    run, sink, writer = build_detection_run(
        conn, alerts_path=tmp_path / "e2e-alerts.ndjson", rules_dir=tmp_path
    )
    try:
        sink.agent_id = agent_id
        for event in _ransomware_burst_events():
            run.process_event(event)
        conn.commit()
    finally:
        writer.close()


def test_kill_process_real_detector_recommendation_fails_closed_without_start_time(
    client: TestClient,
) -> None:
    """Proves the documented gap against genuine engine output: a real
    Level-13 TERMINATE_PROCESS-eligible detection never carries
    target_start_time_ticks, so translate_recommendation must reject it --
    the same fail-closed behavior test_on_alert_created_terminate_process_is_
    rejected_with_no_command exercises with a synthetic active_response, now
    proven against vendor/eyedetect's real ActiveResponseEngine output."""
    from src.alerting.active_response import ActiveResponseEngine

    action = ActiveResponseEngine.resolve_action(
        level=13,
        event={"host_id": _HOST_ID, "process": {"pid": 4242}},
    )
    assert action is not None and action.action == "TERMINATE_PROCESS"
    assert "target_start_time_ticks" not in action.to_dict()

    _enroll(client, "agent-kill-real", "host-kill-real")
    conn = db_module.connect()
    conn.execute(
        "INSERT INTO alerts (alert_id, rule_id, agent_id, created_at, alert_json) "
        "VALUES ('ALT-KILL-REAL', 'DET-INJ-001', 'agent-kill-real', ?, '{}')",
        (datetime.now(timezone.utc).isoformat(),),
    )
    conn.commit()
    from manager.detection import response

    class _RealAlert:
        def to_dict(self) -> dict:
            return {"alert_id": "ALT-KILL-REAL", "active_response": action.to_dict()}

    response.on_alert_created(conn, _RealAlert())
    conn.commit()
    row = conn.execute(
        "SELECT lifecycle_state, command_id FROM response_actions WHERE alert_id = 'ALT-KILL-REAL'"
    ).fetchone()
    assert row["lifecycle_state"] == "REJECTED"
    assert row["command_id"] is None


def test_safe_collection_auto_dispatches_without_analyst_action_and_succeeds(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Scenario A: recommendation -> response -> COLLECT_PROCESS_INFO ->
    dispatch -> ACCEPTED -> result -> SUCCEEDED -> audit, with no analyst
    action anywhere in the path (AUTO_SAFE tier)."""
    from manager.detection import response

    token = _enroll(client, "agent-collect", "host-collect")
    conn = db_module.connect()
    conn.execute(
        "INSERT INTO alerts (alert_id, rule_id, agent_id, created_at, alert_json) "
        "VALUES ('ALT-COLLECT', 'DET-PROC-999', 'agent-collect', ?, '{}')",
        (datetime.now(timezone.utc).isoformat(),),
    )
    conn.commit()

    def _fake_translate(action: str, active_response: dict) -> tuple[str, dict, str]:
        return "COLLECT_PROCESS_INFO", {"pid": 4242, "start_time_ticks": 133012345670000000}, "e2e"

    monkeypatch.setattr(response, "translate_recommendation", _fake_translate)

    class _Alert:
        def to_dict(self) -> dict:
            return {"alert_id": "ALT-COLLECT", "active_response": {"action": "SOMETHING"}}

    response.on_alert_created(conn, _Alert())
    conn.commit()

    row = conn.execute(
        "SELECT lifecycle_state, command_id FROM response_actions WHERE alert_id = 'ALT-COLLECT'"
    ).fetchone()
    assert row["lifecycle_state"] == "AUTHORIZED"
    command_id = str(row["command_id"])
    command_row = conn.execute(
        "SELECT command_json, lifecycle_state FROM commands WHERE command_id = ?", (command_id,)
    ).fetchone()
    queued = json.loads(str(command_row["command_json"]))
    assert queued["action"] == "COLLECT_PROCESS_INFO"
    assert command_row["lifecycle_state"] == "AUTHORIZED"

    headers = {"Authorization": f"Bearer {token}"}
    polled = client.get("/api/v1/agents/agent-collect/commands", headers=headers)
    assert polled.status_code == 200
    dispatched = polled.json()["commands"]
    assert len(dispatched) == 1 and dispatched[0]["command_id"] == command_id

    accepted = client.post(
        f"/api/v1/agents/agent-collect/commands/{command_id}/accept", headers=headers
    )
    assert accepted.status_code == 200

    result = client.post(
        "/api/v1/agents/agent-collect/command-results",
        json={
            "result_id": "result-collect",
            "command_id": command_id,
            "outcome": "succeeded",
            "detail": "3 processes enumerated",
        },
        headers=headers,
    )
    assert result.status_code == 200

    final = conn.execute(
        "SELECT lifecycle_state FROM commands WHERE command_id = ?", (command_id,)
    ).fetchone()
    assert final["lifecycle_state"] == "SUCCEEDED"

    audit_events = [
        row["event"]
        for row in conn.execute(
            "SELECT event FROM command_audit WHERE command_id = ? ORDER BY occurred_at",
            (command_id,),
        ).fetchall()
    ]
    assert audit_events == ["created", "dispatched", "accepted", "result_received"]


def test_isolate_host_from_real_detector_requires_analyst_approval_then_succeeds(
    client: TestClient, tmp_path
) -> None:
    """Scenario B, run against real detector output: a genuine DET-FREQ-001
    ransomware-burst detection recommends ISOLATE_HOST (ANALYST_APPROVAL,
    same locked tier as KILL_PROCESS) -> an unauthorized attempt to approve
    it is rejected -> a real analyst authorizes it -> dispatch -> ACCEPTED ->
    execution result -> SUCCEEDED -> full audit trail."""
    agent_token = _enroll(client, "agent-isolate", _HOST_ID)
    _run_real_detector_burst(tmp_path, "agent-isolate")

    conn = db_module.connect()
    response_row = conn.execute(
        "SELECT response_id, lifecycle_state, action, tier FROM response_actions "
        "WHERE alert_id = 'ALT-TH-DET-FREQ-001'"
    ).fetchone()
    assert response_row is not None, "the real ThresholdEngine did not fire DET-FREQ-001"
    assert response_row["action"] == "ISOLATE_HOST"
    assert response_row["tier"] == "ANALYST_APPROVAL"
    assert response_row["lifecycle_state"] == "PENDING"
    response_id = str(response_row["response_id"])

    # Unauthorized attempt: no analyst bearer token at all.
    unauthorized = client.post(f"/api/v1/response-actions/{response_id}/authorize")
    assert unauthorized.status_code == 401
    # Unauthorized attempt: a forged/garbage analyst token.
    forged = client.post(
        f"/api/v1/response-actions/{response_id}/authorize",
        headers={"Authorization": "Bearer not-a-real-analyst-token"},
    )
    assert forged.status_code == 401
    still_pending = conn.execute(
        "SELECT lifecycle_state, command_id FROM response_actions WHERE response_id = ?",
        (response_id,),
    ).fetchone()
    assert still_pending["lifecycle_state"] == "PENDING"
    assert still_pending["command_id"] is None

    analyst_token = _enroll_analyst(client, "analyst-e2e")
    authorized = client.post(
        f"/api/v1/response-actions/{response_id}/authorize",
        headers={"Authorization": f"Bearer {analyst_token}"},
    )
    assert authorized.status_code == 200

    authorized_row = conn.execute(
        "SELECT lifecycle_state, command_id, authorized_by FROM response_actions "
        "WHERE response_id = ?",
        (response_id,),
    ).fetchone()
    assert authorized_row["lifecycle_state"] == "AUTHORIZED"
    assert authorized_row["authorized_by"] == "analyst:analyst-e2e"
    command_id = str(authorized_row["command_id"])

    headers = {"Authorization": f"Bearer {agent_token}"}
    polled = client.get("/api/v1/agents/agent-isolate/commands", headers=headers)
    dispatched = polled.json()["commands"]
    assert len(dispatched) == 1
    assert dispatched[0]["action"] == "ISOLATE_HOST"
    assert dispatched[0]["command_id"] == command_id

    accepted = client.post(
        f"/api/v1/agents/agent-isolate/commands/{command_id}/accept", headers=headers
    )
    assert accepted.status_code == 200

    result = client.post(
        "/api/v1/agents/agent-isolate/command-results",
        json={
            "result_id": "result-isolate",
            "command_id": command_id,
            "outcome": "succeeded",
            "detail": "host network-namespace isolated",
            "correlation_id": dispatched[0]["correlation_id"],
        },
        headers=headers,
    )
    assert result.status_code == 200

    final = conn.execute(
        "SELECT lifecycle_state FROM commands WHERE command_id = ?", (command_id,)
    ).fetchone()
    assert final["lifecycle_state"] == "SUCCEEDED"

    audit_events = [
        row["event"]
        for row in conn.execute(
            "SELECT event FROM command_audit WHERE command_id = ? ORDER BY occurred_at",
            (command_id,),
        ).fetchall()
    ]
    assert audit_events == ["created", "dispatched", "accepted", "result_received"]


def test_isolate_host_command_cannot_be_hijacked_by_a_different_agent(
    client: TestClient, tmp_path
) -> None:
    """Cross-agent isolation, exercised against a response-engine-issued
    command rather than a hand-crafted /api/v1/commands POST: an attacker
    controlling a second, legitimately enrolled agent must never be able to
    poll, accept, or resolve another host's ISOLATE_HOST command."""
    _enroll(client, "agent-victim", _HOST_ID)
    attacker_token = _enroll(client, "agent-attacker", "HOST-ATTACKER")
    _run_real_detector_burst(tmp_path, "agent-victim")

    conn = db_module.connect()
    response_row = conn.execute(
        "SELECT response_id FROM response_actions WHERE alert_id = 'ALT-TH-DET-FREQ-001'"
    ).fetchone()
    analyst_token = _enroll_analyst(client, "analyst-hijack-check")
    client.post(
        f"/api/v1/response-actions/{response_row['response_id']}/authorize",
        headers={"Authorization": f"Bearer {analyst_token}"},
    )
    command_id = str(
        conn.execute(
            "SELECT command_id FROM response_actions WHERE response_id = ?",
            (response_row["response_id"],),
        ).fetchone()["command_id"]
    )

    attacker_headers = {"Authorization": f"Bearer {attacker_token}"}
    hijack_poll = client.get(
        "/api/v1/agents/agent-attacker/commands", headers=attacker_headers
    )
    assert hijack_poll.json()["commands"] == []

    hijack_accept = client.post(
        f"/api/v1/agents/agent-attacker/commands/{command_id}/accept", headers=attacker_headers
    )
    assert hijack_accept.status_code == 422

    hijack_result = client.post(
        "/api/v1/agents/agent-attacker/command-results",
        json={"result_id": "hijack-result", "command_id": command_id, "outcome": "succeeded"},
        headers=attacker_headers,
    )
    assert hijack_result.status_code == 422

    untouched = conn.execute(
        "SELECT lifecycle_state FROM commands WHERE command_id = ?", (command_id,)
    ).fetchone()
    assert untouched["lifecycle_state"] == "AUTHORIZED"


def test_result_correlation_id_mismatch_is_rejected(client: TestClient) -> None:
    """A result whose correlation_id doesn't match the dispatched command's
    (forged, replayed from a different command, or simply buggy) must never
    be accepted as that command's outcome."""
    token = _enroll(client, "agent-corr", "host-corr")
    client.post(
        "/api/v1/commands",
        json={
            "command_id": "cmd-corr-mismatch",
            "agent_id": "agent-corr",
            "action": "COLLECT_NETWORK_CONNECTIONS",
            "expires_at": (datetime.now(timezone.utc) + timedelta(minutes=5)).isoformat(),
            "correlation_id": "corr-real",
        },
        headers={"X-Panopticon-Command-Token": "test-command-token"},
    )
    headers = {"Authorization": f"Bearer {token}"}
    client.get("/api/v1/agents/agent-corr/commands", headers=headers)
    forged = client.post(
        "/api/v1/agents/agent-corr/command-results",
        json={
            "result_id": "result-corr-forged",
            "command_id": "cmd-corr-mismatch",
            "outcome": "succeeded",
            "correlation_id": "corr-forged-from-elsewhere",
        },
        headers=headers,
    )
    assert forged.status_code == 422
    row = db_module.connect().execute(
        "SELECT lifecycle_state FROM commands WHERE command_id = ?", ("cmd-corr-mismatch",)
    ).fetchone()
    assert row["lifecycle_state"] == "DISPATCHED"


def test_raw_command_with_an_action_outside_the_closed_seven_is_rejected(
    client: TestClient,
) -> None:
    """The wire Command model's Action enum is the sole gate against an
    eighth action ever existing -- an attacker (or a buggy caller) posting
    EXECUTE_COMMAND/RUN_SCRIPT/SHELL must fail validation before a row is
    ever written, not be silently coerced into a known action."""
    _enroll(client, "agent-bad-action", "host-bad-action")
    for bogus_action in ("EXECUTE_COMMAND", "RUN_SCRIPT", "SHELL", "FIREWALL_RULE"):
        rejected = client.post(
            "/api/v1/commands",
            json={
                "command_id": f"cmd-bad-{bogus_action}",
                "agent_id": "agent-bad-action",
                "action": bogus_action,
                "expires_at": (datetime.now(timezone.utc) + timedelta(minutes=5)).isoformat(),
            },
            headers={"X-Panopticon-Command-Token": "test-command-token"},
        )
        assert rejected.status_code == 422
    count = db_module.connect().execute("SELECT COUNT(*) AS c FROM commands").fetchone()["c"]
    assert count == 0
