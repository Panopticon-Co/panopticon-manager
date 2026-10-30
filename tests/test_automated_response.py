"""Automated response, end to end (docs/AUTOMATED_RESPONSE.md).

Real app + real production rules + the detection worker's own ``run_once``
(the capstone harness), with tools/lab_responder.py's endpoint as the
containment adapter. The payload is a real, harmless child process this test
launches; KILL_PROCESS really terminates it and the result is verified by
observing /proc, not asserted.
"""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import pytest

from manager.detection import response
from tests.test_capstone_e2e import _Harness, harness  # noqa: F401 (fixture)

pytestmark = pytest.mark.skipif(sys.platform != "linux", reason="lab endpoint reads /proc")

_TOOL = Path(__file__).resolve().parents[1] / "tools" / "lab_responder.py"
_spec = importlib.util.spec_from_file_location("lab_responder", _TOOL)
lab_responder = importlib.util.module_from_spec(_spec)
sys.modules.setdefault("lab_responder", lab_responder)
_spec.loader.exec_module(lab_responder)

_AGENT, _HOST = "lab-responder-01", "LAB-RESPONDER-01"


class _Client:
    """lab_responder's HTTP surface over the test client, as the agent."""

    def __init__(self, h: _Harness, agent_id: str) -> None:
        self.h, self.agent_id = h, agent_id

    def get(self, path: str) -> dict:
        resp = self.h.client.get(path, headers=self.h.agent_headers(self.agent_id))
        assert resp.status_code == 200, resp.text
        return resp.json()

    def post(self, path: str, body: dict) -> dict:
        resp = self.h.client.post(path, json=body, headers=self.h.agent_headers(self.agent_id))
        assert resp.status_code == 200, resp.text
        return resp.json()


@pytest.fixture()
def lab(harness: _Harness):  # noqa: F811
    harness.enroll(_AGENT, _HOST)
    endpoint = lab_responder.LabEndpoint(_AGENT, _HOST)
    try:
        yield harness, endpoint, _Client(harness, _AGENT)
    finally:
        endpoint.cleanup()


def _attack(h: _Harness, endpoint) -> tuple[object, dict]:
    payload = endpoint.launch_payload()
    event = endpoint.observe(payload)
    h.ingest(_AGENT, [json.dumps(event)], f"batch-{payload.pid}")
    h.drain()
    return payload, _policy_action(h, payload.pid)


def _policy_action(h: _Harness, pid: int) -> dict:
    """The DET-LNX-001 response for this pid. Running as root, the payload may
    also trip other rules (e.g. DET-PRIV-007); those are recorded as duplicates
    (or, in simulate mode, cooldown repeats) of this one."""
    actions = h.get(f"/api/v1/response-actions?host_id={_HOST}")["response_actions"]
    return next(
        a for a in actions
        if a["target"].get("pid") == pid
        and (a["policy_decision"] or {}).get("policy_id") == "contain-reverse-shell"
    )


def _decision_count(h: _Harness) -> int:
    return h.conn.execute("SELECT COUNT(*) AS c FROM response_policy_decisions").fetchone()["c"]


def _incident_status(h: _Harness, alert_id: str) -> str:
    """Alert-level status (a lone DET-LNX-001 alert forms no incident); the
    incident route derives its status from the same function."""
    return h.get(f"/api/v1/alerts/{alert_id}")["response_status"]


def test_attack_to_verified_containment(lab) -> None:
    h, endpoint, client = lab
    payload, action = _attack(h, endpoint)

    # Detection -> persisted alert with its evidence.
    alert = h.get(f"/api/v1/alerts/{action['alert_id']}")
    alert_body = alert.get("alert", alert)
    if isinstance(alert_body, str):
        alert_body = json.loads(alert_body)
    assert "/dev/tcp/" in json.dumps(alert_body)

    # Policy decision: matched, previewed by the simulation adapter, staged.
    decision = action["policy_decision"]
    assert decision["policy_id"] == "contain-reverse-shell"
    assert decision["mode"] == "approval" and decision["global_mode"] == "enforce"
    assert decision["simulation_status"] == "simulated"
    assert decision["simulation"]["host_effect"] == "none"
    assert f"pid={payload.pid}" in decision["simulation"]["would"]
    assert action["lifecycle_state"] == "PENDING" and action["command_id"] is None
    assert action["execution"]["kind"] == "simulated"
    assert _incident_status(h, action["alert_id"]) == "awaiting_approval"

    # Unapproved: the endpoint is offered nothing, and the payload lives on.
    assert endpoint.poll_once(client) == []
    assert lab_responder.proc_start_ticks(payload.pid) == payload.start_ticks

    authorized = h.client.post(
        f"/api/v1/response-actions/{action['response_id']}/authorize", headers=h.analyst
    )
    assert authorized.status_code == 200, authorized.text

    results = endpoint.poll_once(client)
    assert [r["outcome"] for r in results] == ["succeeded"]
    assert results[0]["detail"].startswith("verified:")
    # Independently confirm the containment the endpoint reported.
    assert lab_responder.proc_start_ticks(payload.pid) is None
    assert payload.popen.returncode is not None

    action = _policy_action(h, payload.pid)
    assert action["command_lifecycle_state"] == "SUCCEEDED"
    assert action["execution"] == {
        "kind": "endpoint", "outcome": "succeeded", "verified": True,
        "detail": results[0]["detail"],
    }
    events = [e["event"] for e in action["decision_audit"]]
    assert events[:3] == ["staged", "policy_evaluated", "authorized"]
    assert _incident_status(h, action["alert_id"]) == "contained"

    # A redelivered/retried command neither re-executes nor changes state.
    assert endpoint.handle(client, {"command_id": action["command_id"]}) == results[0]


def test_default_simulate_mode_previews_without_any_command(lab, monkeypatch) -> None:
    monkeypatch.delenv("PANOPTICON_RESPONSE_MODE")
    h, endpoint, client = lab
    payload, action = _attack(h, endpoint)
    decision = action["policy_decision"]
    assert decision["global_mode"] == "simulate" and decision["mode"] == "simulate"
    assert action["lifecycle_state"] == "REJECTED"
    assert action["decided_reason"].startswith("simulated only (contain-reverse-shell")
    assert action["execution"]["kind"] == "simulated"
    assert h.conn.execute("SELECT COUNT(*) AS c FROM commands").fetchone()["c"] == 0
    # Nothing can be authorized; the host was not touched.
    refused = h.client.post(
        f"/api/v1/response-actions/{action['response_id']}/authorize", headers=h.analyst
    )
    assert refused.status_code in (404, 409)
    assert endpoint.poll_once(client) == []
    assert lab_responder.proc_start_ticks(payload.pid) == payload.start_ticks
    assert _incident_status(h, action["alert_id"]) == "simulated_containment"
    # Other rules firing on the same process are cooldown repeats, never staged.
    others = [
        a for a in h.get(f"/api/v1/response-actions?host_id={_HOST}")["response_actions"]
        if a["response_id"] != action["response_id"]
    ]
    assert all(a["decided_reason"].startswith("cooldown: equivalent response") for a in others)


def test_duplicate_alert_and_reingest_do_not_stack_responses(lab) -> None:
    h, endpoint, _client = lab
    payload, action = _attack(h, endpoint)
    before = _decision_count(h)
    event = endpoint.observe(payload)
    h.ingest(_AGENT, [json.dumps(event)], "replayed-batch")
    h.drain()
    assert _decision_count(h) == before
    actions = h.get(f"/api/v1/response-actions?host_id={_HOST}")["response_actions"]
    assert [a["lifecycle_state"] for a in actions].count("PENDING") == 1
    assert all(
        a["decided_reason"] == f"duplicate of {action['response_id']}"
        for a in actions if a["response_id"] != action["response_id"]
    )


def test_endpoint_refuses_targets_it_does_not_own(lab) -> None:
    h, endpoint, client = lab
    payload, action = _attack(h, endpoint)
    # A same-pid target from another process lifetime (PID reuse) is refused.
    endpoint.payloads[payload.pid].start_ticks += 1
    assert h.client.post(
        f"/api/v1/response-actions/{action['response_id']}/authorize", headers=h.analyst
    ).status_code == 200
    results = endpoint.poll_once(client)
    assert results[0]["outcome"] == "rejected"
    assert "does not match" in results[0]["detail"]
    assert lab_responder.proc_start_ticks(payload.pid) is not None
    assert _incident_status(h, action["alert_id"]) == "containment_failed"


@pytest.mark.parametrize(
    "command",
    [
        {"action": "KILL_PROCESS", "target": {"pid": 1, "start_time_ticks": 1}},
        {"action": "KILL_PROCESS", "target": {"pid": "1", "start_time_ticks": 1}},
        {"action": "ISOLATE_HOST", "target": {}},
        {"action": "QUARANTINE_FILE", "target": {"path": "/etc/passwd"}},
        {"action": "RUN_SHELL", "target": {"cmd": "rm -rf /"}},
    ],
)
def test_lab_adapter_rejects_out_of_scope_commands(command) -> None:
    outcome, detail = lab_responder.LabEndpoint("a", "h").execute(command)
    assert outcome == "rejected" and detail.startswith("refused:")


def _stage(conn, alert: dict) -> None:
    conn.execute(
        "INSERT INTO alerts (alert_id, rule_id, agent_id, host_id, created_at, alert_json) "
        "VALUES (?, ?, NULL, ?, '2026-10-30T00:00:00Z', '{}')",
        (alert["alert_id"], alert.get("rule_id") or "x", alert.get("host_id")),
    )
    response.on_alert_created(conn, alert)


def _kill_alert(**overrides) -> dict:
    alert = {
        "alert_id": "ALT-K", "rule_id": "DET-LNX-001", "host_id": "H", "level": 14,
        "confidence": 0.9, "detection_source": "rule",
        "evidence": {"process.command_line": "bash -c 'echo /dev/tcp/x'"},
        "active_response": {
            "action": "TERMINATE_PROCESS", "target_pid": 42, "target_start_time_ticks": 7,
        },
    }
    alert.update(overrides)
    return alert


def _row(conn, alert_id: str):
    return conn.execute(
        "SELECT ra.lifecycle_state, ra.decided_reason, ra.command_id, d.mode, d.policy_id "
        "FROM response_actions ra LEFT JOIN response_policy_decisions d "
        "ON d.response_id = ra.response_id WHERE ra.alert_id = ?",
        (alert_id,),
    ).fetchone()


@pytest.fixture()
def conn():
    import sqlite3

    from manager import migrations

    c = sqlite3.connect(":memory:")
    c.row_factory = sqlite3.Row
    migrations.migrate(c)
    yield c
    c.close()


def test_low_confidence_alert_is_recorded_not_staged(conn) -> None:
    _stage(conn, _kill_alert(confidence=0.5))
    row = _row(conn, "ALT-K")
    assert row["lifecycle_state"] == "REJECTED" and row["mode"] == "record"
    assert "confidence 0.5 below 0.85" in row["decided_reason"]
    assert row["command_id"] is None


def test_malformed_alert_is_denied_and_never_commands(conn) -> None:
    _stage(conn, _kill_alert(level="high"))
    row = _row(conn, "ALT-K")
    assert row["lifecycle_state"] == "REJECTED" and row["mode"] == "denied"
    assert row["decided_reason"].startswith("policy denied (validation)")
    assert conn.execute("SELECT COUNT(*) AS c FROM commands").fetchone()["c"] == 0


def test_response_loop_guard(conn) -> None:
    marker = "python lab_responder.py panopticon-response-executor"
    _stage(conn, _kill_alert(evidence={"process.command_line": marker}))
    assert _row(conn, "ALT-K")["policy_id"] == "loop-guard"
    assert _row(conn, "ALT-K")["lifecycle_state"] == "REJECTED"


def test_simulated_preview_has_a_cooldown(conn, monkeypatch) -> None:
    monkeypatch.setenv("PANOPTICON_RESPONSE_MODE", "simulate")
    _stage(conn, _kill_alert())
    _stage(conn, _kill_alert(alert_id="ALT-K2"))
    assert _row(conn, "ALT-K")["mode"] == "simulate"
    assert _row(conn, "ALT-K2")["decided_reason"].startswith("cooldown: equivalent response")


def test_invalid_response_mode_fails_closed_to_simulate(conn, monkeypatch) -> None:
    monkeypatch.setenv("PANOPTICON_RESPONSE_MODE", "yolo")
    _stage(conn, _kill_alert())
    assert _row(conn, "ALT-K")["mode"] == "simulate"


def test_policy_decisions_are_immutable(conn) -> None:
    import sqlite3

    _stage(conn, _kill_alert())
    with pytest.raises(sqlite3.IntegrityError):
        conn.execute("UPDATE response_policy_decisions SET mode = 'auto'")
    with pytest.raises(sqlite3.IntegrityError):
        conn.execute("DELETE FROM response_policy_decisions")


def test_response_policies_route(lab) -> None:
    h, _endpoint, _client = lab
    body = h.get("/api/v1/response-policies")
    assert body["response_mode"] == "enforce"
    assert {p["policy_id"] for p in body["policies"]} >= {"contain-reverse-shell"}
    assert h.client.get("/api/v1/response-policies").status_code == 401
