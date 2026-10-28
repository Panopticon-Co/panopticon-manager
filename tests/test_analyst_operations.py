"""Real authenticated API flows, including dispatch exclusion and retained outcomes."""

import json

import pytest

from manager import db
from tests.test_command_route import _enroll
from tests.test_response_actions_route import _enroll_analyst, _stage_response_action


def setup(client):
    agent = _enroll(client, "agent-1", "host-1")
    analyst = _enroll_analyst(client, "alice")
    _stage_response_action("agent-1", "alert-1", action="ISOLATE_HOST")
    conn = db.connect()
    conn.execute("UPDATE response_actions SET lifecycle_state='REJECTED'")
    conn.execute("UPDATE alerts SET host_id='host-1'")
    conn.commit()
    return {"Authorization": "Bearer " + analyst}, {"Authorization": "Bearer " + agent}


def create(client, headers, action="COLLECT_NETWORK_CONNECTIONS", **extra):
    return client.post(
        "/api/v1/response-actions",
        headers=headers,
        json={
            "alert_id": "alert-1",
            "action": action,
            "reason": "Investigate incident",
            **extra,
        },
    )


def test_catalog_and_manual_routes_require_analyst_identity(client):
    _, agent = setup(client)
    assert client.get("/api/v1/response-actions/catalog", headers=agent).status_code == 401
    assert create(client, agent).status_code == 401


def test_manual_collection_always_requires_approval_and_retains_provenance(client):
    analyst, agent = setup(client)
    catalog = client.get("/api/v1/response-actions/catalog", headers=analyst).json()["actions"]
    assert len(catalog) == 7
    response = create(client, analyst)
    assert response.status_code == 201, response.text
    rid = response.json()["response_id"]
    assert client.get("/api/v1/agents/agent-1/commands", headers=agent).json() == {"commands": []}
    rows = client.get("/api/v1/response-actions?state=PENDING", headers=analyst).json()
    row = rows["response_actions"][0]
    assert row["tier"] == "ANALYST_APPROVAL"
    assert row["origin"] == "analyst" and row["requested_by"] == "analyst:alice"
    assert row["request_reason"] == "Investigate incident"
    assert create(client, analyst).status_code == 409
    assert (
        client.post(f"/api/v1/response-actions/{rid}/authorize", headers=analyst).json()[
            "authorized"
        ]
        is True
    )
    commands = client.get("/api/v1/agents/agent-1/commands", headers=agent).json()["commands"]
    assert len(commands) == 1
    command = commands[0]
    assert (
        client.post(
            "/api/v1/agents/agent-1/command-results",
            headers=agent,
            json={
                "result_id": "receipt-1",
                "command_id": command["command_id"],
                "schema_version": "2",
                "correlation_id": command["correlation_id"],
                "outcome": "indeterminate",
                "detail": "Execution interrupted; operator review required",
            },
        ).status_code
        == 200
    )
    row = client.get("/api/v1/response-actions?state=AUTHORIZED", headers=analyst).json()[
        "response_actions"
    ][0]
    assert row["command_lifecycle_state"] == "INDETERMINATE"
    assert row["receipts"][0]["payload"]["outcome"] == "indeterminate"
    assert row["results"][0]["detail"].startswith("Execution interrupted")
    assert row["command"]["correlation_id"] == command["correlation_id"]


@pytest.mark.parametrize("mode", ["single", "durable"])
def test_cancel_before_dispatch_is_idempotent_and_prevents_poll(client, mode):
    analyst, agent = setup(client)
    rid = create(client, analyst, "ISOLATE_HOST").json()["response_id"]
    client.post(f"/api/v1/response-actions/{rid}/authorize", headers=analyst)
    path = f"/api/v1/response-actions/{rid}/cancel"
    for _ in range(2):
        assert (
            client.post(path, headers=analyst, json={"reason": "False positive"}).status_code == 200
        )
    assert (
        client.get(f"/api/v1/agents/agent-1/commands?delivery_mode={mode}", headers=agent).json()[
            "commands"
        ]
        == []
    )
    conn = db.connect()
    assert conn.execute("SELECT lifecycle_state FROM commands").fetchone()[0] == "CANCELLED"
    assert (
        conn.execute("SELECT COUNT(*) FROM command_audit WHERE event='cancelled'").fetchone()[0]
        == 1
    )


def test_cancel_after_dispatch_refuses(client):
    analyst, agent = setup(client)
    rid = create(client, analyst).json()["response_id"]
    client.post(f"/api/v1/response-actions/{rid}/authorize", headers=analyst)
    client.get("/api/v1/agents/agent-1/commands", headers=agent)
    assert (
        client.post(
            f"/api/v1/response-actions/{rid}/cancel", headers=analyst, json={"reason": "Too late"}
        ).status_code
        == 409
    )


@pytest.mark.parametrize(
    "extra",
    [
        {"reason": "  "},
        {"action": "EXECUTE_COMMAND"},
        {"action": "COLLECT_FILE", "target": {}},
        {"action": "KILL_PROCESS", "target": {"pid": 5}},
    ],
)
def test_invalid_manual_requests_fail_closed(client, extra):
    analyst, _ = setup(client)
    assert create(client, analyst, **extra).status_code == 422
    assert db.connect().execute("SELECT COUNT(*) FROM commands").fetchone()[0] == 0


def test_manual_host_binding_is_rechecked_before_authorize(client):
    analyst, _ = setup(client)
    rid = create(client, analyst, "ISOLATE_HOST").json()["response_id"]
    conn = db.connect()
    conn.execute("UPDATE enrolled_agents SET host_id='replacement'")
    conn.commit()
    assert (
        client.post(f"/api/v1/response-actions/{rid}/authorize", headers=analyst).status_code == 409
    )
    assert conn.execute("SELECT COUNT(*) FROM commands").fetchone()[0] == 0


def test_manual_canonical_process_uses_verified_subject_and_preserves_ticks(client):
    from tests.test_endpoint_records import records

    analyst, _ = setup(client)
    raw = records()[0]
    record = {"endpoint_context": {"endpoint": raw["endpoint"], "subject": raw["subject"]}}
    conn = db.connect()
    conn.execute("UPDATE alerts SET alert_json=?", (json.dumps(record),))
    conn.commit()
    result = create(client, analyst, "KILL_PROCESS")
    assert result.status_code == 201, result.text
    assert result.json()["target"]["start_time_ticks"] == raw["subject"]["native_creation_ticks"]
    assert client.post(
        f"/api/v1/response-actions/{result.json()['response_id']}/authorize", headers=analyst
    ).json()["authorized"]
    wire = json.loads(conn.execute("SELECT command_json FROM commands").fetchone()[0])
    assert wire["schema_version"] == "2"
    assert wire["target"] == result.json()["target"]


def test_queue_filters_and_pagination(client):
    analyst, _ = setup(client)
    create(client, analyst)
    create(client, analyst, "COLLECT_FILE", target={"path": "/tmp/evidence"})
    page = client.get("/api/v1/response-actions?state=PENDING&limit=1", headers=analyst).json()
    assert len(page["response_actions"]) == 1 and page["next_offset"] == 1
    next_page = client.get(
        "/api/v1/response-actions?state=PENDING&limit=1&offset=1", headers=analyst
    ).json()
    assert (
        next_page["response_actions"][0]["response_id"]
        != page["response_actions"][0]["response_id"]
    )
    assert next_page["next_offset"] is None
    assert (
        client.get("/api/v1/response-actions?host_id=wrong", headers=analyst).json()[
            "response_actions"
        ]
        == []
    )
    assert client.get("/api/v1/response-actions?limit=0", headers=analyst).status_code == 422


@pytest.mark.parametrize(
    "action,target",
    [
        ("COLLECT_FILE", {"path": "/tmp/evidence"}),
        ("QUARANTINE_FILE", {"path": "/tmp/suspect"}),
        ("RELEASE_HOST_ISOLATION", {}),
        ("COLLECT_PROCESS_INFO", {}),
    ],
)
def test_manual_investigation_and_recovery_actions_dispatch_exact_targets(client, action, target):
    from tests.test_endpoint_records import records

    analyst, agent = setup(client)
    if action == "COLLECT_PROCESS_INFO":
        raw = records()[0]
        record = {"endpoint_context": {"endpoint": raw["endpoint"], "subject": raw["subject"]}}
        conn = db.connect()
        conn.execute("UPDATE alerts SET alert_json=?", (json.dumps(record),))
        conn.commit()
    result = create(client, analyst, action, target=target)
    assert result.status_code == 201, result.text
    rid = result.json()["response_id"]
    assert client.post(f"/api/v1/response-actions/{rid}/authorize", headers=analyst).json()[
        "authorized"
    ]
    wire = client.get("/api/v1/agents/agent-1/commands", headers=agent).json()["commands"][0]
    assert wire["action"] == action and wire["target"] == result.json()["target"]


def test_late_structured_receipt_is_visible_without_rewriting_cancelled_state(client):
    from tests.test_endpoint_records import records

    analyst, agent = setup(client)
    raw = records()[0]
    record = {"endpoint_context": {"endpoint": raw["endpoint"], "subject": raw["subject"]}}
    conn = db.connect()
    conn.execute("UPDATE alerts SET alert_json=?", (json.dumps(record),))
    conn.commit()
    rid = create(client, analyst, "KILL_PROCESS").json()["response_id"]
    client.post(f"/api/v1/response-actions/{rid}/authorize", headers=analyst)
    wire = json.loads(conn.execute("SELECT command_json FROM commands").fetchone()[0])
    client.post(
        f"/api/v1/response-actions/{rid}/cancel",
        headers=analyst,
        json={"reason": "Cancel before delivery"},
    )
    receipt = {
        "schema_version": "2",
        "result_id": "late-evidence",
        "command_id": wire["command_id"],
        "correlation_id": wire["correlation_id"],
        "outcome": "indeterminate",
        "execution": {
            "representation": "windows_process_termination_v1",
            "stage": "completion",
            "action_initiated": True,
            "completion_observed": False,
            "native_error": 5,
        },
    }
    assert (
        client.post(
            "/api/v1/agents/agent-1/command-results", headers=agent, json=receipt
        ).status_code
        == 200
    )
    row = client.get("/api/v1/response-actions?state=AUTHORIZED", headers=analyst).json()[
        "response_actions"
    ][0]
    assert row["command_lifecycle_state"] == "CANCELLED"
    assert row["results"] == []
    assert row["receipts"][0]["payload"]["execution"] == receipt["execution"]


@pytest.mark.parametrize("context", [{"endpoint": []}, {"subject": {}}, []])
def test_malformed_retained_context_cannot_create_manual_command(client, context):
    analyst, _ = setup(client)
    conn = db.connect()
    conn.execute("UPDATE alerts SET alert_json=?", (json.dumps({"endpoint_context": context}),))
    conn.commit()
    assert create(client, analyst, "KILL_PROCESS").status_code in (409, 422)
    assert conn.execute("SELECT COUNT(*) FROM commands").fetchone()[0] == 0
