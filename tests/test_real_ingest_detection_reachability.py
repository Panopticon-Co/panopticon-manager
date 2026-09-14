"""Phase 15: proves DET-PERS-007 is reachable through the REAL wire/ingest
boundary -- POST /api/v1/ingest -> persistence -> the real background
DetectionWorker thread -> OfficerIngestionAdapter -> RuleEvaluator -> Alert
-> response.on_alert_created -> QUARANTINE_FILE recommendation -- with no
internal process_event()/DetectionRun bypass anywhere in this file.

The default `client` fixture (tests/conftest.py) points PANOPTICON_RULES_DIR
at a one-rule fixture directory so most tests build the detection worker
fast; DET-PERS-007 isn't in that directory. This file builds its own
TestClient pointed at the real, full pinned rule set
(vendor/eyedetect/rules, the same directory manager/config.py's production
default resolves to), following the pattern documented in
tests/conftest.py's FIXTURE_RULES_DIR comment and used by
tests/test_detection_factory.py::test_full_rule_set_loads.

Background: DET-PERS-007's own YAML previously declared event_type
"file_write", a value no real telemetry source (Windows Sysmon Event ID 11
FileCreate, decoded by panopticon-agent's sysmon_telemetry_decoder.cpp, or
OfficerIngestionAdapter.transform_officer_event) ever produces -- real file
creation always synthesizes "file_create". RuleEvaluator indexes rules
strictly by event_type (src/evaluator/engine.py's _rules_by_type), so the
mismatch made the rule permanently unreachable via real ingest even though
tests/test_e2e_response_pipeline.py could still fire it by calling
DetectionRun.process_event() directly with a hand-built "file_write" event.
The fix (vendor/eyedetect pin bump) corrects the rule's event_type to
"file_create", matching the already-correct sibling rule DET-FILE-001.
"""

from __future__ import annotations

import importlib
import json
import time
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

_HOST_ID = "HOST-REAL-INGEST-PERS007"


@pytest.fixture()
def real_rules_client(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> TestClient:
    """Identical to tests/conftest.py's `client` fixture except
    PANOPTICON_RULES_DIR points at the real, full pinned production rule set
    instead of the fast one-rule fixture directory -- so the real background
    DetectionWorker thread this fixture starts actually has DET-PERS-007 (and
    every other production rule) loaded, exactly as it would in a deployed
    Manager."""
    from manager.config import _DEFAULT_RULES_DIR

    monkeypatch.setenv("PANOPTICON_DB_PATH", str(tmp_path / "panopticon.db"))
    monkeypatch.setenv("PANOPTICON_ALERTS_PATH", str(tmp_path / "alerts.ndjson"))
    monkeypatch.setenv("PANOPTICON_RULES_DIR", str(_DEFAULT_RULES_DIR))
    monkeypatch.setenv("PANOPTICON_ENROLLMENT_TOKEN", "test-bootstrap-token")
    monkeypatch.setenv("PANOPTICON_COMMAND_TOKEN", "test-command-token")
    monkeypatch.setenv("PANOPTICON_ANALYST_ENROLLMENT_TOKEN", "test-analyst-bootstrap-token")

    import manager.app as app_module
    import manager.auth as auth_module
    import manager.db as db_module
    import manager.detection.factory as factory_module
    import manager.detection.response as response_module
    import manager.migrations as migrations_module
    import manager.routers.alerts as alerts_module
    import manager.routers.commands as commands_module
    import manager.routers.enrollment as enrollment_module
    import manager.routers.health as health_module
    import manager.routers.ingest as ingest_module
    import manager.routers.response_actions as response_actions_module

    for mod in (
        health_module,
        ingest_module,
        enrollment_module,
        commands_module,
        response_module,
        response_actions_module,
        alerts_module,
        factory_module,
        auth_module,
        migrations_module,
        db_module,
        app_module,
    ):
        importlib.reload(mod)

    with TestClient(app_module.app) as c:
        yield c


def _enroll(client: TestClient, agent_id: str, host_id: str) -> str:
    from tests.conftest import enroll_test_agent

    response = enroll_test_agent(client, agent_id, host_id)
    assert response.status_code == 200
    return str(response.json()["access_token"])


def _enroll_analyst(client: TestClient, analyst_id: str) -> str:
    response = client.post(
        "/api/v1/analysts/enroll",
        json={"analyst_id": analyst_id},
        headers={"X-Panopticon-Analyst-Enrollment-Token": "test-analyst-bootstrap-token"},
    )
    assert response.status_code == 200
    return str(response.json()["access_token"])


def _canonical_startup_folder_file_create_event(
    *, event_id: str, file_path: str, host_id: str = _HOST_ID, agent_id: str
) -> dict:
    """A fully valid manager/wire/telemetry.py TelemetryEvent -- the exact
    shape a real Windows agent sends, not a simplified stand-in. category
    "file" + type "create" is what real Sysmon Event ID 11 FileCreate
    normalizes to."""
    return {
        "schema_version": "0.4",
        "event": {
            "id": event_id,
            "category": "file",
            "type": "create",
            "timestamp": "2026-09-14T12:00:00.000Z",
        },
        "source": {
            "kind": "sysmon",
            "provider": "Microsoft-Windows-Sysmon",
            "channel": "Microsoft-Windows-Sysmon/Operational",
            "record_id": 1,
        },
        "agent": {"id": agent_id, "version": "0.1.0"},
        "host": {
            "id": host_id,
            "hostname": host_id,
            "os": {"name": "Windows 11 Pro", "build": "26100"},
        },
        "user": {"name": None, "domain": None, "sid": None},
        "process": {
            "entity_id": "proc_" + "d" * 64,
            "pid": 6001,
            "name": "explorer.exe",
            "executable": r"C:\Windows\explorer.exe",
            "command_line": r"C:\Windows\explorer.exe",
            "start_time_ticks": None,
            "parent": {"entity_id": None, "pid": 600, "name": "userinit.exe"},
            "hash": {"sha256": None},
        },
        "file": {
            "operation": "create",
            "path": file_path,
            "target_path": None,
            "previous_path": None,
            "hash": {"sha256": None},
        },
    }


def _wait_for_alert(conn, agent_id: str, rule_id: str, timeout: float = 5.0):
    """Polls for the real background DetectionWorker thread (1s idle-sleep,
    manager/detection/worker.py's IDLE_SLEEP_SECONDS) to claim, normalize,
    and evaluate the just-ingested event -- no bypass, the same asynchronous
    path a deployed Manager actually runs. Filters by rule_id, not just
    agent_id: a real Windows startup-folder FileCreate event legitimately
    fires both DET-FILE-001 (detection-only, no active_response) and
    DET-PERS-007 (this test's actual target) -- overlapping real coverage
    from two different rules, not a bug this test needs to work around by
    picking whichever alert happens to land first."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        row = conn.execute(
            "SELECT alert_id, rule_id FROM alerts WHERE agent_id = ? AND rule_id = ?",
            (agent_id, rule_id),
        ).fetchone()
        if row is not None:
            return row
        time.sleep(0.1)
    return None


def test_det_pers_007_is_reachable_through_real_post_ingest(real_rules_client: TestClient) -> None:
    """POST /api/v1/ingest (real HTTP, real bearer auth, real wire schema) ->
    real background DetectionWorker -> real OfficerIngestionAdapter -> real
    RuleEvaluator -> DET-PERS-007 fires -> real Alert -> real
    response.on_alert_created -> QUARANTINE_FILE recommendation queued for
    analyst approval. No process_event()/DetectionRun bypass."""
    import manager.db as db_module

    agent_id = "agent-real-ingest-pers007"
    agent_token = _enroll(real_rules_client, agent_id, _HOST_ID)

    target_path = (
        r"C:\Users\victim\AppData\Roaming\Microsoft\Windows"
        r"\Start Menu\Programs\Startup\evil.exe"
    )
    event = _canonical_startup_folder_file_create_event(
        event_id="evt_" + "7" * 64, file_path=target_path, agent_id=agent_id
    )

    response = real_rules_client.post(
        "/api/v1/ingest",
        content=json.dumps(event) + "\n",
        headers={
            "Content-Type": "application/x-ndjson",
            "X-Panopticon-Batch-Id": "pers007-real-ingest-batch",
            "X-Panopticon-Agent-Id": agent_id,
            "X-Panopticon-Protocol": "1",
            "Authorization": f"Bearer {agent_token}",
        },
    )
    assert response.status_code == 200
    body = response.json()
    assert body["accepted"] == 1, body
    assert body["rejected"] == []

    conn = db_module.connect()
    alert_row = _wait_for_alert(conn, agent_id, "DET-PERS-007")
    assert alert_row is not None, (
        "DET-PERS-007 did not fire via the real ingest boundary within the timeout -- "
        "the real DetectionWorker thread never produced an Alert for this event"
    )

    response_row = conn.execute(
        "SELECT response_id, lifecycle_state, action, tier FROM response_actions "
        "WHERE alert_id = ?",
        (alert_row["alert_id"],),
    ).fetchone()
    assert response_row is not None
    assert response_row["action"] == "QUARANTINE_FILE"
    assert response_row["tier"] == "ANALYST_APPROVAL"
    assert response_row["lifecycle_state"] == "PENDING"

    # Authorize and dispatch too, proving the mapping survives all the way to
    # a real command the real agent-facing endpoints would serve.
    analyst_token = _enroll_analyst(real_rules_client, "analyst-real-ingest-pers007")
    response_id = str(response_row["response_id"])
    authorized = real_rules_client.post(
        f"/api/v1/response-actions/{response_id}/authorize",
        headers={"Authorization": f"Bearer {analyst_token}"},
    )
    assert authorized.status_code == 200

    command_id = str(
        conn.execute(
            "SELECT command_id FROM response_actions WHERE response_id = ?", (response_id,)
        ).fetchone()["command_id"]
    )
    command_row = conn.execute(
        "SELECT command_json FROM commands WHERE command_id = ?", (command_id,)
    ).fetchone()
    queued_target = json.loads(str(command_row["command_json"]))["target"]
    assert queued_target == {"path": target_path}

    polled = real_rules_client.get(
        f"/api/v1/agents/{agent_id}/commands",
        headers={"Authorization": f"Bearer {agent_token}"},
    )
    dispatched = polled.json()["commands"]
    assert len(dispatched) == 1 and dispatched[0]["action"] == "QUARANTINE_FILE"


def test_det_pers_007_does_not_fire_on_an_unrelated_real_ingested_file_event(
    real_rules_client: TestClient,
) -> None:
    """A real, wire-valid file_create event outside any startup/autostart
    path must not fire DET-PERS-007, proving the fix didn't loosen the rule's
    actual matching semantics -- only its reachability."""
    import manager.db as db_module

    agent_id = "agent-real-ingest-pers007-benign"
    agent_token = _enroll(real_rules_client, agent_id, "HOST-REAL-INGEST-PERS007-BENIGN")

    event = _canonical_startup_folder_file_create_event(
        event_id="evt_" + "6" * 64,
        file_path=r"C:\Users\victim\Documents\quarterly-report.docx",
        host_id="HOST-REAL-INGEST-PERS007-BENIGN",
        agent_id=agent_id,
    )
    response = real_rules_client.post(
        "/api/v1/ingest",
        content=json.dumps(event) + "\n",
        headers={
            "Content-Type": "application/x-ndjson",
            "X-Panopticon-Batch-Id": "pers007-benign-batch",
            "X-Panopticon-Agent-Id": agent_id,
            "X-Panopticon-Protocol": "1",
            "Authorization": f"Bearer {agent_token}",
        },
    )
    assert response.status_code == 200
    assert response.json()["accepted"] == 1

    conn = db_module.connect()
    # Give the worker its normal chance to run, then assert it produced
    # nothing for this agent -- a real negative, not merely "we never checked".
    time.sleep(1.5)
    row = conn.execute(
        "SELECT alert_id FROM alerts WHERE agent_id = ?", (agent_id,)
    ).fetchone()
    assert row is None
