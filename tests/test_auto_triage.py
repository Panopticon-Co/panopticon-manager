import base64
import hashlib
import json
from datetime import datetime, timedelta, timezone

import pytest
from response_engine.triage import COLLECT_ACTIONS, default_policy

from manager import audit_chain, db
from manager.detection.response import on_alert_created
from manager.detection.store import insert_alert
from tests.conftest import enroll_test_agent
from tests.test_response_governance import identity

BASE = "/api/v1/triage"
BOOT = "boot_" + "a" * 64


def administrator(client, monkeypatch):
    monkeypatch.setenv("PANOPTICON_TRIAGE_ADMIN_ENROLLMENT_TOKEN", "separate-triage-bootstrap")
    result = client.post("/api/v1/analysts/enroll", json={
        "analyst_id": "triage-admin", "role": "triage_admin",
    }, headers={"X-Panopticon-Analyst-Enrollment-Token": "separate-triage-bootstrap"})
    assert result.status_code == 200, result.text
    return {"Authorization": "Bearer " + result.json()["access_token"]}


def profile(platform="windows", **changes):
    return {"schema_version": "2", "platform": platform, "host_id": "host-1",
            "boot_id": BOOT, "mode": "enforce", "implemented_actions": list(COLLECT_ACTIONS),
            "allowed_actions": list(COLLECT_ACTIONS), "require_boot_binding": True,
            "require_signature": False, "require_collection_acceptance": True,
            "artifact_protocol": "signed-json-v2-resume-v1", **changes}


def poll(client, agent, report=None):
    return client.get("/api/v1/agents/agent-1/commands?delivery_mode=durable", headers={
        **agent, "X-Panopticon-Response-Profile": base64.b64encode(
            json.dumps(report or profile()).encode()).decode(),
    })


def configure(client, admin, **changes):
    configuration = {**default_policy("RULE-1").model_dump(), "enabled": True, **changes}
    result = client.post(BASE + "/policies", headers=admin, json={
        "request_id": "policy-" + str(configuration["version"]),
        "expected_version": configuration["version"] - 1, "policy": configuration,
    })
    assert result.status_code == 200, result.text
    return result


def prepare(client, monkeypatch, *, asset="standard", report=None, **policy_changes):
    enrollment = enroll_test_agent(client, "agent-1", "host-1")
    agent = {"Authorization": "Bearer " + enrollment.json()["access_token"]}
    admin = administrator(client, monkeypatch)
    analyst = identity(client, "operator", "analyst")
    assert client.post(BASE + "/assets", headers=admin, json={
        "request_id": "asset-1", "expected_version": 0, "host_id": "host-1",
        "asset_class": asset, "reason": "Authoritative lab asset classification",
    }).status_code == 200
    configure(client, admin, **policy_changes)
    assert poll(client, agent, report).status_code == 200
    return agent, admin, analyst


def alert(alert_id="alert-1", **changes):
    fields = ["native-process-instance-v1", "host-1", BOOT, "42", "123"]
    material = "".join(str(len(f.encode())) + ":" + f for f in fields)
    context = {"endpoint": {"agent_id": "agent-1", "host_id": "host-1", "boot_id": BOOT},
               "subject": {"observed_pid": 42, "native_creation_ticks": "123", "boot_id": BOOT,
                           "resolution": "native_exact",
                           "entity_id": "proc_" + hashlib.sha256(material.encode()).hexdigest()}}
    return {"alert_id": alert_id, "rule_id": "RULE-1", "host_id": "host-1",
            "event_id": "original-event", "timestamp": datetime.now(timezone.utc).isoformat(),
            "endpoint_context": context, "evidence": {"file": {"path": r"C:\Lab\sample.txt"}},
            **changes}


def emit(value):
    conn = db.connect()
    conn.execute("BEGIN IMMEDIATE")
    insert_alert(conn, value, agent_id="agent-1")
    on_alert_created(conn, value)
    conn.commit()
    return [dict(r) for r in conn.execute("SELECT * FROM triage_items WHERE alert_id=?",
                                        (value["alert_id"],))]


@pytest.mark.parametrize("platform", ["windows", "linux"])
def test_alert_hook_is_idempotent_and_collects_only_supported_policy_actions(
    client, monkeypatch, platform,
):
    agent, _, analyst = prepare(client, monkeypatch, report=profile(platform=platform))
    value = alert(evidence={})
    items = emit(value)
    assert len(items) == 3
    assert sum(i["decision"] == "auto_dispatch" for i in items) == 2
    count = audit_chain.verify(db.connect())["sequence"]
    assert emit(value) == items
    assert audit_chain.verify(db.connect())["sequence"] == count
    assert db.connect().execute("SELECT COUNT(*) FROM commands").fetchone()[0] == 2
    commands = poll(client, agent, profile(platform=platform)).json()["commands"]
    assert len(commands) == 1
    command = commands[0]
    assert command["action"] in COLLECT_ACTIONS
    accepted = client.post(f"/api/v1/agents/agent-1/commands/{command['command_id']}/accept",
                           headers=agent)
    assert accepted.status_code == 200
    assert client.post("/api/v1/agents/agent-1/command-results", headers=agent, json={
        "schema_version": "2", "result_id": "triage-result", "outcome": "succeeded",
        "command_id": command["command_id"], "correlation_id": command["correlation_id"],
    }).status_code == 200
    assert len(poll(client, agent, profile(platform=platform)).json()["commands"]) == 1
    run = client.get(BASE + "/runs", headers=analyst).json()["runs"][0]
    assert run["policy_version"] == 1 and len(run["items"]) == 3
    events = client.get("/api/v1/response-audit?actor=system/auto-triage", headers=analyst).json()
    names = {e["event"] for e in events["events"]}
    assert {"auto_triage_created", "auto_triage_authorized", "auto_triage_dispatched",
            "auto_triage_accepted", "auto_triage_result_received", "auto_triage_audited"} <= names
    query = client.get("/api/v1/response-audit", headers=analyst, params={
        "actor": "system/auto-triage", "asset_id": "host-1",
        "request_id": command["command_id"][5:], "since": "2020-01-01T00:00:00Z",
    }).json()["events"]
    assert query and all(e["request_id"] == command["command_id"][5:] for e in query)
    phases = [e["event"] for e in query]
    assert phases.index("auto_triage_result_received") < phases.index("auto_triage_audited")
    assert audit_chain.verify(db.connect())["complete_history_verified"]


@pytest.mark.parametrize("asset", ["critical", "unknown"])
def test_critical_or_unclassified_asset_never_auto_executes(client, monkeypatch, asset):
    agent, _, analyst = prepare(client, monkeypatch, asset=asset)
    items = emit(alert())
    assert all(i["decision"] == "require_approval" for i in items)
    assert not poll(client, agent).json()["commands"]
    rid = items[0]["response_id"]
    assert client.post(f"/api/v1/response-actions/{rid}/authorize", headers=analyst).json()[
        "authorized"]
    assert len(poll(client, agent).json()["commands"]) == 1


@pytest.mark.parametrize("changes,reason", [
    ({"mode": "dry_run"}, "endpoint_not_enforcing"),
    ({"require_collection_acceptance": False}, "execution_policy_gate_required"),
    ({"artifact_protocol": None}, "signed_artifact_delivery_not_supported"),
    ({"allowed_actions": []}, "endpoint_policy_denied"),
    ({"implemented_actions": [], "allowed_actions": []}, "action_not_supported"),
])
def test_capability_denials_are_audited_skips(client, monkeypatch, changes, reason):
    prepare(client, monkeypatch, report=profile(**changes))
    items = emit(alert())
    assert all(i["decision"] == "skip" and i["reason"] == reason for i in items)
    assert not db.connect().execute("SELECT 1 FROM commands").fetchone()


def test_disabled_rule_cannot_fall_through_legacy_auto_safe_path(client, monkeypatch):
    prepare(client, monkeypatch, enabled=False)
    items = emit(alert(active_response={"action": "COLLECT_NETWORK_CONNECTIONS"}))
    assert all(i["reason"] == "rule_disabled" for i in items)
    assert not db.connect().execute("SELECT 1 FROM commands").fetchone()


@pytest.mark.parametrize("platform,path", [
    ("windows", r"C:\Lab\sample.txt"), ("linux", "/tmp/sample.txt"),
])
def test_file_automation_requires_exact_platform_path_and_preserves_metadata_semantics(
    client, monkeypatch, platform, path,
):
    configuration = default_policy("RULE-1").model_dump()
    for entry in configuration["entries"]:
        if entry["action"] == "COLLECT_FILE" and entry["asset_class"] == "standard":
            entry.update(decision="auto_dispatch",
                         file_paths=[{"platform": platform, "path": path}])
    prepare(client, monkeypatch, report=profile(platform=platform),
            entries=configuration["entries"])
    items = emit(alert(detection_source="rule", evidence={"file": {"path": path}}))
    file = next(i for i in items if i["action"] == "COLLECT_FILE")
    assert file["decision"] == "auto_dispatch"
    command = json.loads(db.connect().execute(
        "SELECT command_json FROM commands WHERE command_id=?", ("resp-" + file["response_id"],),
    ).fetchone()[0])
    assert command["action"] == "COLLECT_FILE" and command["target"] == {"path": path}
    assert "acquire_bytes" not in command
    changed = emit(alert("alert-2", evidence={"file": {"path": path + ".different"}}))
    assert next(i for i in changed if i["action"] == "COLLECT_FILE")[
        "reason"] == "alert_file_target_not_allowlisted"


@pytest.mark.parametrize("stage", ["dispatch", "acceptance", "approval"])
@pytest.mark.parametrize("change", ["policy", "asset", "boot", "key"])
def test_live_policy_class_boot_and_key_are_rechecked(client, monkeypatch, stage, change):
    agent, admin, analyst = prepare(client, monkeypatch,
                                    asset="critical" if stage == "approval" else "standard")
    items = emit(alert())
    process = next(i for i in items if i["action"] == "COLLECT_PROCESS_INFO")
    if stage == "acceptance":
        # Restrict the fixture to the specific process command to exercise boot binding.
        conn = db.connect()
        conn.execute("UPDATE commands SET created_at='2000' WHERE command_id=?",
                     ("resp-" + process["response_id"],))
        conn.commit()
        poll(client, agent)
    if change == "policy":
        configure(client, admin, version=2, enabled=False)
    elif change == "asset":
        assert client.post(BASE + "/assets", headers=admin, json={
            "request_id": "asset-2", "expected_version": 1, "host_id": "host-1",
            "asset_class": "critical", "reason": "Reclassified",
        }).status_code == 200
    elif change == "boot":
        poll(client, agent, profile(boot_id="boot_" + "b" * 64))
    else:
        db.connect().execute("UPDATE artifact_signing_keys SET compromised_at=?",
                             (datetime.now(timezone.utc).isoformat(),))
        db.connect().commit()
    if stage == "approval":
        assert client.post(f"/api/v1/response-actions/{process['response_id']}/authorize",
                           headers=analyst).status_code == 409
    elif stage == "acceptance":
        result = client.post(
            f"/api/v1/agents/agent-1/commands/resp-{process['response_id']}/accept", headers=agent)
        assert result.status_code == 409
    else:
        commands = poll(client, agent, profile(boot_id="boot_" + "b" * 64)
                        if change == "boot" else None).json()["commands"]
        assert all(c["action"] != "COLLECT_PROCESS_INFO" for c in commands)


def test_cancellation_reuses_queue_path_and_is_idempotent_mid_flight(client, monkeypatch):
    agent, _, analyst = prepare(client, monkeypatch)
    emit(alert())
    dispatched = poll(client, agent).json()["commands"][0]
    url = BASE + "/runs/alert-1/cancel"
    result = client.post(url, headers=analyst, json={"reason": "Analyst stopped triage"})
    assert result.status_code == 200
    count = audit_chain.verify(db.connect())["sequence"]
    assert client.post(url, headers=analyst, json={"reason": "Retry"}).json() == result.json()
    assert audit_chain.verify(db.connect())["sequence"] == count
    assert not poll(client, agent).json()["commands"]
    states = [r[0] for r in db.connect().execute("SELECT lifecycle_state FROM commands")]
    assert sorted(states) == ["CANCELLED", "DISPATCHED"]
    assert client.post("/api/v1/agents/agent-1/command-results", headers=agent, json={
        "schema_version": "2", "result_id": "late", "command_id": dispatched["command_id"],
        "correlation_id": dispatched["correlation_id"], "outcome": "succeeded",
    }).status_code == 200


def test_endpoint_budget_is_shared_across_rules_and_replays(client, monkeypatch):
    agent, admin, _ = prepare(client, monkeypatch, budget={
        **default_policy("RULE-1").budget.model_dump(), "max_actions_per_endpoint_window": 2,
    })
    emit(alert())
    emit(alert())
    configuration = default_policy("RULE-2").model_dump()
    configuration.update(enabled=True, budget={
        **configuration["budget"], "max_actions_per_endpoint_window": 2,
    })
    assert client.post(BASE + "/policies", headers=admin, json={
        "request_id": "rule-2", "expected_version": 0, "policy": configuration,
    }).status_code == 200
    items = emit(alert("alert-2", rule_id="RULE-2"))
    assert next(i for i in items if i["action"] == "COLLECT_NETWORK_CONNECTIONS")[
        "reason"] == "endpoint_frequency_budget"
    assert db.connect().execute(
        "SELECT SUM(reserved_bytes) FROM triage_items").fetchone()[0] == 2097152
    assert len(poll(client, agent).json()["commands"]) == 1


def test_policy_management_is_separate_idempotent_and_revision_checked(client, monkeypatch):
    _, admin, analyst = prepare(client, monkeypatch)
    assert client.get(BASE + "/policies", headers=analyst).status_code == 403
    assert client.get(BASE + "/runs", headers=admin).status_code == 403
    assert client.post("/api/v1/analysts/enroll", json={
        "analyst_id": "unauthorized-admin", "role": "triage_admin",
    }, headers={"X-Panopticon-Analyst-Enrollment-Token": "test-analyst-bootstrap-token"}
    ).status_code == 401
    count = audit_chain.verify(db.connect())["sequence"]
    configure(client, admin)
    assert audit_chain.verify(db.connect())["sequence"] == count
    value = {**default_policy("RULE-1").model_dump(), "enabled": False}
    assert client.post(BASE + "/policies", headers=admin, json={
        "request_id": "different", "expected_version": 0, "policy": value,
    }).status_code == 409
    assert client.post(BASE + "/policies", headers=admin, json={
        "request_id": "policy-1", "expected_version": 0, "policy": value,
    }).status_code == 409


def test_audit_failure_rolls_back_workflow_but_keeps_detection(client, monkeypatch):
    prepare(client, monkeypatch)
    conn = db.connect()
    conn.execute("CREATE TRIGGER fail_triage_audit BEFORE INSERT ON response_security_audit "
                 "WHEN NEW.event='auto_triage_created' BEGIN SELECT RAISE(ABORT,'test'); END")
    conn.commit()
    assert emit(alert()) == []
    assert conn.execute("SELECT 1 FROM alerts WHERE alert_id='alert-1'").fetchone()
    assert not conn.execute("SELECT 1 FROM commands").fetchone()
    assert not conn.execute("SELECT 1 FROM triage_runs").fetchone()


def test_deadline_blocks_execution_without_reusing_budget(client, monkeypatch):
    agent, _, _ = prepare(client, monkeypatch)
    emit(alert())
    conn = db.connect()
    conn.execute("UPDATE triage_runs SET deadline=?",
                 ((datetime.now(timezone.utc) - timedelta(seconds=1)).isoformat(),))
    conn.commit()
    assert not poll(client, agent).json()["commands"]
    assert conn.execute("SELECT SUM(reserved_bytes) FROM triage_items").fetchone()[0] == 3145728


def test_native_detection_sink_stages_triage_alongside_analyst_response(
    client, monkeypatch, tmp_path,
):
    from panopticon_detection.ingestion.endpoint_adapter import EndpointIngestionAdapter

    from manager.config import _DEFAULT_RULES_DIR
    from manager.detection.factory import build_detection_run
    from tests.test_endpoint_records import records

    _, admin, _ = prepare(client, monkeypatch)
    configuration = {**default_policy("DET-CRED-001").model_dump(), "enabled": True}
    assert client.post(BASE + "/policies", headers=admin, json={
        "request_id": "real-detection-rule", "expected_version": 0, "policy": configuration,
    }).status_code == 200
    raw = records()[0]
    raw["data"]["process"].update(
        name="reg.exe", command_line=r"reg.exe save hklm\sam C:\temp\sam.hiv",
    )
    run, sink, writer, _ = build_detection_run(
        db.connect(), alerts_path=tmp_path / "triage-alerts.ndjson", rules_dir=_DEFAULT_RULES_DIR,
    )
    try:
        sink.agent_id = "agent-1"
        run.process_event(EndpointIngestionAdapter.transform(raw))
        db.connect().commit()
    finally:
        writer.close()
    rows = db.connect().execute(
        "SELECT ra.action,ra.lifecycle_state FROM response_actions ra JOIN alerts a "
        "ON a.alert_id=ra.alert_id WHERE a.rule_id='DET-CRED-001'",
    ).fetchall()
    assert any(r["action"] == "KILL_PROCESS" and r["lifecycle_state"] == "PENDING" for r in rows)
    assert db.connect().execute("SELECT 1 FROM triage_runs WHERE rule_id='DET-CRED-001'").fetchone()
    assert any(r["action"] == "COLLECT_NETWORK_CONNECTIONS" for r in rows)


def test_concurrent_alerts_cannot_over_reserve_endpoint_budget(client, monkeypatch):
    import sqlite3
    import threading
    from concurrent.futures import ThreadPoolExecutor

    prepare(client, monkeypatch, budget={
        **default_policy("RULE-1").budget.model_dump(), "max_actions_per_endpoint_window": 2,
    })
    path = db.connect().execute("PRAGMA database_list").fetchone()[2]
    barrier = threading.Barrier(2)

    def emit_concurrently(number):
        conn = sqlite3.connect(path, timeout=5)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys=ON")
        audit_chain.register(conn)
        try:
            barrier.wait(timeout=5)
            conn.execute("BEGIN IMMEDIATE")
            value = alert("concurrent-" + str(number))
            insert_alert(conn, value, agent_id="agent-1")
            on_alert_created(conn, value)
            conn.commit()
        finally:
            conn.close()

    with ThreadPoolExecutor(max_workers=2) as pool:
        list(pool.map(emit_concurrently, (1, 2)))
    assert db.connect().execute("SELECT COUNT(*) FROM triage_runs").fetchone()[0] == 2
    assert db.connect().execute("SELECT COUNT(*) FROM commands").fetchone()[0] == 2
    assert db.connect().execute(
        "SELECT SUM(reserved_bytes) FROM triage_items").fetchone()[0] == 2097152
    assert audit_chain.verify(db.connect())["complete_history_verified"]
