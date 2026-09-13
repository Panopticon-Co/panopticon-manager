"""Unit tests for manager/detection/response.py against a bare in-memory
sqlite3 connection (migrated schema, no FastAPI) -- these exercise the
translation/tiering/lifecycle logic directly, independent of HTTP transport
or the vendored detection engine. tests/test_response_actions_route.py covers
the HTTP surface."""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone

from manager import migrations
from manager.detection import response


class _Alert:
    """Minimal stand-in for vendor/eyedetect's Alert dataclass: anything with
    a to_dict() is accepted by on_alert_created."""

    def __init__(self, **fields):
        self._fields = fields

    def to_dict(self) -> dict:
        return self._fields


def _conn() -> sqlite3.Connection:
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys=ON")
    migrations.migrate(conn)
    return conn


def _enroll_agent(
    conn: sqlite3.Connection, agent_id: str = "agent-1", host_id: str = "host-1"
) -> None:
    conn.execute(
        "INSERT INTO enrolled_agents (agent_id, host_id, token_digest, enrolled_at, revoked_at) "
        "VALUES (?, ?, 'digest', ?, NULL)",
        (agent_id, host_id, datetime.now(timezone.utc).isoformat()),
    )
    conn.commit()


def _insert_bare_alert(
    conn: sqlite3.Connection, alert_id: str, agent_id: str | None = "agent-1"
) -> None:
    conn.execute(
        "INSERT INTO alerts (alert_id, rule_id, agent_id, created_at, alert_json) "
        "VALUES (?, 'rule-1', ?, ?, '{}')",
        (alert_id, agent_id, datetime.now(timezone.utc).isoformat()),
    )
    conn.commit()


def _response_id_for_alert(conn: sqlite3.Connection, alert_id: str) -> str:
    row = conn.execute(
        "SELECT response_id FROM response_actions WHERE alert_id = ?", (alert_id,)
    ).fetchone()
    return str(row["response_id"])


def _response_row(conn: sqlite3.Connection, response_id: str) -> sqlite3.Row:
    row = conn.execute(
        "SELECT * FROM response_actions WHERE response_id = ?", (response_id,)
    ).fetchone()
    assert row is not None
    return row


def _command_row(conn: sqlite3.Connection, command_id: str) -> sqlite3.Row:
    row = conn.execute("SELECT * FROM commands WHERE command_id = ?", (command_id,)).fetchone()
    assert row is not None
    return row


def test_classify_tier_matches_locked_decisions() -> None:
    assert response.classify_tier("KILL_PROCESS") == "ANALYST_APPROVAL"
    assert response.classify_tier("ISOLATE_HOST") == "ANALYST_APPROVAL"
    assert response.classify_tier("RELEASE_HOST_ISOLATION") == "ANALYST_APPROVAL"
    assert response.classify_tier("COLLECT_PROCESS_INFO") == "AUTO_SAFE"
    assert response.classify_tier("COLLECT_NETWORK_CONNECTIONS") == "AUTO_SAFE"
    assert response.classify_tier("COLLECT_FILE") == "ANALYST_APPROVAL"
    assert response.classify_tier("QUARANTINE_FILE") == "ANALYST_APPROVAL"
    # Unknown actions must never default to auto-fire.
    assert response.classify_tier("SOMETHING_UNKNOWN") == "ANALYST_APPROVAL"


def test_translate_recommendation_terminate_process_fails_closed() -> None:
    # Without target_start_time_ticks (e.g. an older agent build, or an event
    # that never carried process.start_time_ticks) this must never guess.
    assert response.translate_recommendation("TERMINATE_PROCESS", {"target_pid": 123}) is None


def test_translate_recommendation_isolate_host_is_a_direct_mapping() -> None:
    mapped = response.translate_recommendation("ISOLATE_HOST", {})
    assert mapped == ("ISOLATE_HOST", {}, "direct mapping")


def test_translate_recommendation_block_firewall_ip_downgrades_to_isolate_host() -> None:
    active_response = {"target_ip": "1.2.3.4"}
    action, target, reason = response.translate_recommendation("BLOCK_FIREWALL_IP", active_response)
    assert action == "ISOLATE_HOST"
    assert target == {}
    assert "downgraded" in reason


def test_translate_recommendation_unknown_action_returns_none() -> None:
    assert response.translate_recommendation("SOMETHING_ELSE", {}) is None


def test_on_alert_created_with_no_active_response_produces_no_row() -> None:
    conn = _conn()
    response.on_alert_created(conn, _Alert(alert_id="ALT-1", active_response=None))
    assert conn.execute("SELECT COUNT(*) AS c FROM response_actions").fetchone()["c"] == 0


def test_on_alert_created_analyst_approval_action_stays_pending_with_no_command() -> None:
    conn = _conn()
    _enroll_agent(conn)
    _insert_bare_alert(conn, "ALT-2")
    alert = _Alert(alert_id="ALT-2", active_response={"action": "ISOLATE_HOST"})
    response.on_alert_created(conn, alert)
    row = _response_row(conn, _response_id_for_alert(conn, "ALT-2"))
    assert row["action"] == "ISOLATE_HOST"
    assert row["tier"] == "ANALYST_APPROVAL"
    assert row["lifecycle_state"] == "PENDING"
    assert row["command_id"] is None


def test_on_alert_created_terminate_process_is_rejected_with_no_command() -> None:
    conn = _conn()
    _enroll_agent(conn)
    _insert_bare_alert(conn, "ALT-3")
    active_response = {"action": "TERMINATE_PROCESS", "target_pid": 555}
    response.on_alert_created(conn, _Alert(alert_id="ALT-3", active_response=active_response))
    row = _response_row(conn, _response_id_for_alert(conn, "ALT-3"))
    assert row["lifecycle_state"] == "REJECTED"
    assert row["command_id"] is None


def test_on_alert_created_terminate_process_with_start_time_stages_kill_process_pending() -> None:
    # Once the detection engine can prove a PID-reuse-safe start time
    # (panopticon-response-engine ADR 002), TERMINATE_PROCESS must translate
    # into a real, staged KILL_PROCESS response_actions row -- still PENDING
    # analyst approval, never auto-enqueued, since KILL_PROCESS is hard-coded
    # ANALYST_APPROVAL regardless of how the target was resolved.
    conn = _conn()
    _enroll_agent(conn)
    _insert_bare_alert(conn, "ALT-3B")
    active_response = {
        "action": "TERMINATE_PROCESS",
        "target_pid": 555,
        "target_start_time_ticks": 987654,
    }
    response.on_alert_created(conn, _Alert(alert_id="ALT-3B", active_response=active_response))
    row = _response_row(conn, _response_id_for_alert(conn, "ALT-3B"))
    assert row["action"] == "KILL_PROCESS"
    assert row["tier"] == "ANALYST_APPROVAL"
    assert row["lifecycle_state"] == "PENDING"
    assert row["command_id"] is None
    assert json.loads(row["target_json"]) == {"pid": 555, "start_time_ticks": 987654}


def test_on_alert_created_auto_safe_action_is_enqueued_immediately(monkeypatch) -> None:
    conn = _conn()
    _enroll_agent(conn)
    _insert_bare_alert(conn, "ALT-4")
    # A synthetic mapping exercised directly against the closed action-to-tier
    # table, independent of translate_recommendation's actual vocabulary --
    # see test_on_alert_created_collect_process_info_is_enqueued_immediately
    # below for the real (non-monkeypatched) equivalent now that eyedetect's
    # vocabulary genuinely produces COLLECT_PROCESS_INFO.
    def _fake_translate(action, active_response):
        return "COLLECT_PROCESS_INFO", {"pid": 1, "start_time_ticks": 2}, "test mapping"

    monkeypatch.setattr(response, "translate_recommendation", _fake_translate)
    alert = _Alert(alert_id="ALT-4", active_response={"action": "FAKE_ACTION"})
    response.on_alert_created(conn, alert)
    row = _response_row(conn, _response_id_for_alert(conn, "ALT-4"))
    assert row["tier"] == "AUTO_SAFE"
    assert row["lifecycle_state"] == "AUTHORIZED"
    assert row["command_id"] is not None
    command = _command_row(conn, row["command_id"])
    assert json.loads(command["command_json"])["action"] == "COLLECT_PROCESS_INFO"
    assert command["alert_id"] == "ALT-4"


def test_on_alert_created_collect_process_info_is_enqueued_immediately() -> None:
    # Real (non-monkeypatched) path: eyedetect's ActiveResponseAction can now
    # genuinely carry action="COLLECT_PROCESS_INFO", and
    # response_engine.translate_recommendation genuinely maps it -- this
    # proves the whole chain without faking any layer.
    conn = _conn()
    _enroll_agent(conn)
    _insert_bare_alert(conn, "ALT-4B")
    active_response = {
        "action": "COLLECT_PROCESS_INFO",
        "target_pid": 4242,
        "target_start_time_ticks": 123456789,
    }
    response.on_alert_created(conn, _Alert(alert_id="ALT-4B", active_response=active_response))
    row = _response_row(conn, _response_id_for_alert(conn, "ALT-4B"))
    assert row["tier"] == "AUTO_SAFE"
    assert row["lifecycle_state"] == "AUTHORIZED"
    assert row["command_id"] is not None
    command = _command_row(conn, row["command_id"])
    command_json = json.loads(command["command_json"])
    assert command_json["action"] == "COLLECT_PROCESS_INFO"
    assert command_json["target"] == {"pid": 4242, "start_time_ticks": 123456789}
    assert command["alert_id"] == "ALT-4B"


def test_on_alert_created_collect_network_connections_is_enqueued_immediately() -> None:
    conn = _conn()
    _enroll_agent(conn)
    _insert_bare_alert(conn, "ALT-4C")
    active_response = {"action": "COLLECT_NETWORK_CONNECTIONS"}
    response.on_alert_created(conn, _Alert(alert_id="ALT-4C", active_response=active_response))
    row = _response_row(conn, _response_id_for_alert(conn, "ALT-4C"))
    assert row["tier"] == "AUTO_SAFE"
    assert row["lifecycle_state"] == "AUTHORIZED"
    assert row["command_id"] is not None
    command = _command_row(conn, row["command_id"])
    command_json = json.loads(command["command_json"])
    assert command_json["action"] == "COLLECT_NETWORK_CONNECTIONS"
    assert command_json["target"] == {}
    assert command["alert_id"] == "ALT-4C"


def test_on_alert_created_never_raises_on_internal_failure(monkeypatch) -> None:
    conn = _conn()

    def _boom(*_args, **_kwargs):
        raise RuntimeError("simulated Response Engine bug")

    monkeypatch.setattr(response, "translate_recommendation", _boom)
    # Must not raise -- a Response Engine bug must never take detection down
    # or roll back the alert that was already durably written.
    alert = _Alert(alert_id="ALT-5", active_response={"action": "ISOLATE_HOST"})
    response.on_alert_created(conn, alert)
    assert conn.execute("SELECT COUNT(*) AS c FROM response_actions").fetchone()["c"] == 0


def test_authorize_response_action_creates_a_dispatchable_command() -> None:
    conn = _conn()
    _enroll_agent(conn)
    _insert_bare_alert(conn, "ALT-6")
    alert = _Alert(alert_id="ALT-6", active_response={"action": "ISOLATE_HOST"})
    response.on_alert_created(conn, alert)
    response_id = _response_id_for_alert(conn, "ALT-6")
    response.authorize_response_action(conn, response_id, actor="analyst:alice")
    row = _response_row(conn, response_id)
    assert row["lifecycle_state"] == "AUTHORIZED"
    assert row["authorized_by"] == "analyst:alice"
    assert row["command_id"] is not None
    command = _command_row(conn, row["command_id"])
    assert json.loads(command["command_json"])["action"] == "ISOLATE_HOST"
    assert command["agent_id"] == "agent-1"
    assert command["alert_id"] == "ALT-6"
    assert command["lifecycle_state"] == "AUTHORIZED"


def test_authorize_response_action_rejects_when_alert_has_no_agent() -> None:
    conn = _conn()
    _insert_bare_alert(conn, "ALT-7", agent_id=None)
    alert = _Alert(alert_id="ALT-7", active_response={"action": "ISOLATE_HOST"})
    response.on_alert_created(conn, alert)
    response_id = _response_id_for_alert(conn, "ALT-7")
    response.authorize_response_action(conn, response_id, actor="analyst:alice")
    row = _response_row(conn, response_id)
    assert row["lifecycle_state"] == "REJECTED"
    assert row["command_id"] is None


def test_authorize_response_action_is_a_no_op_when_not_pending() -> None:
    conn = _conn()
    _enroll_agent(conn)
    _insert_bare_alert(conn, "ALT-8")
    alert = _Alert(alert_id="ALT-8", active_response={"action": "ISOLATE_HOST"})
    response.on_alert_created(conn, alert)
    response_id = _response_id_for_alert(conn, "ALT-8")
    response.reject_response_action(conn, response_id, actor="analyst:bob", reason="benign")
    # Already REJECTED -- must not resurrect it into an AUTHORIZED command.
    response.authorize_response_action(conn, response_id, actor="analyst:alice")
    row = _response_row(conn, response_id)
    assert row["lifecycle_state"] == "REJECTED"
    assert row["command_id"] is None


def test_reject_response_action_never_creates_a_command() -> None:
    conn = _conn()
    _enroll_agent(conn)
    _insert_bare_alert(conn, "ALT-9")
    alert = _Alert(alert_id="ALT-9", active_response={"action": "ISOLATE_HOST"})
    response.on_alert_created(conn, alert)
    response_id = _response_id_for_alert(conn, "ALT-9")
    response.reject_response_action(
        conn, response_id, actor="analyst:bob", reason="confirmed benign"
    )
    row = _response_row(conn, response_id)
    assert row["lifecycle_state"] == "REJECTED"
    assert row["command_id"] is None
    assert row["authorized_by"] == "analyst:bob"
    assert row["decided_reason"] == "confirmed benign"
    assert conn.execute("SELECT COUNT(*) AS c FROM commands").fetchone()["c"] == 0
