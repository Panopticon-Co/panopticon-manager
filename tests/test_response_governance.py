import json
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path

import jsonschema
import pytest
from pydantic import ValidationError

from manager import db
from manager.routers.response_actions import ManualRequest
from tests.test_analyst_operations import create, setup


def identity(client, name, role):
    result = client.post(
        "/api/v1/analysts/enroll",
        json={"analyst_id": name, "role": role},
        headers={"X-Panopticon-Analyst-Enrollment-Token": "test-analyst-bootstrap-token"},
    )
    assert result.status_code == 200, result.text
    return {"Authorization": "Bearer " + result.json()["access_token"]}


def test_permissions_enforced_for_viewer_requester_and_approver(client):
    analyst, agent = setup(client)
    viewer = identity(client, "reader", "viewer")
    responder = identity(client, "requester", "responder")
    approver = identity(client, "reviewer", "approver")
    assert client.get("/api/v1/analysts/me", headers=viewer).json()["permissions"] == []
    assert create(client, viewer).status_code == 403
    assert create(client, approver).status_code == 403
    rid = create(client, responder).json()["response_id"]
    for operation in ("authorize", "reject", "cancel"):
        kwargs = {} if operation == "authorize" else {"json": {"reason": "Review"}}
        for headers in (viewer, responder):
            assert (
                client.post(
                    f"/api/v1/response-actions/{rid}/{operation}", headers=headers, **kwargs
                ).status_code
                == 403
            )
    assert (
        client.post(
            "/api/v1/incidents/unknown/status", headers=viewer, json={"status": "resolved"}
        ).status_code
        == 403
    )
    assert client.post(f"/api/v1/response-actions/{rid}/authorize", headers=approver).json()[
        "authorized"
    ]
    exported = client.get(f"/api/v1/response-actions/{rid}/export", headers=viewer)
    assert exported.status_code == 200
    assert client.get(f"/api/v1/response-actions/{rid}/export", headers=agent).status_code == 401
    record = exported.json()["response_action"]
    assert record["requested_by"] == "analyst:requester"
    assert record["authorized_by"] == "analyst:reviewer"
    assert [event["event"] for event in record["decision_audit"]] == ["staged", "authorized"]
    assert analyst["Authorization"] not in exported.text


def test_separate_approver_policy_refuses_self_approval_and_invalid_config(client, monkeypatch):
    analyst, _ = setup(client)
    rid = create(client, analyst).json()["response_id"]
    monkeypatch.setenv("PANOPTICON_REQUIRE_SEPARATE_APPROVER", "true")
    assert (
        client.post(f"/api/v1/response-actions/{rid}/authorize", headers=analyst).status_code == 403
    )
    assert db.connect().execute("SELECT COUNT(*) FROM commands").fetchone()[0] == 0
    approver = identity(client, "second-person", "approver")
    assert client.post(f"/api/v1/response-actions/{rid}/authorize", headers=approver).json()[
        "authorized"
    ]
    monkeypatch.setenv("PANOPTICON_REQUIRE_SEPARATE_APPROVER", "typo")
    assert client.get("/api/v1/response-actions/catalog", headers=analyst).status_code == 503


def test_retry_identity_survives_decision_and_conflicting_payload_cannot_create_action(client):
    analyst, _ = setup(client)
    first = create(client, analyst, request_id="stable-1")
    rid = first.json()["response_id"]
    client.post(
        f"/api/v1/response-actions/{rid}/reject",
        headers=analyst,
        json={"reason": "No longer needed"},
    )
    replay = create(client, analyst, request_id="stable-1")
    assert replay.json() == {
        "response_id": rid,
        "lifecycle_state": "REJECTED",
        "target": {},
        "replayed": True,
    }
    assert (
        create(client, analyst, request_id="stable-1", reason="Changed intent").status_code == 409
    )
    # The same key belongs independently to a different authenticated identity.
    other = identity(client, "another-analyst", "analyst")
    assert create(client, other, request_id="stable-1").status_code == 201
    conn = db.connect()
    assert conn.execute("SELECT COUNT(*) FROM response_request_keys").fetchone()[0] == 2
    assert (
        conn.execute(
            "SELECT COUNT(*) FROM response_decision_audit WHERE response_id=?", (rid,)
        ).fetchone()[0]
        == 2
    )


def test_decision_audit_is_append_only_and_expiry_is_recorded_once(client):
    analyst, _ = setup(client)
    rid = create(client, analyst).json()["response_id"]
    conn = db.connect()
    stale = (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()
    conn.execute("UPDATE response_actions SET created_at=? WHERE response_id=?", (stale, rid))
    conn.commit()
    for _ in range(2):
        client.get("/api/v1/response-actions", headers=analyst)
    events = conn.execute(
        "SELECT event FROM response_decision_audit WHERE response_id=? ORDER BY occurred_at,rowid",
        (rid,),
    ).fetchall()
    assert [r["event"] for r in events] == ["staged", "expired"]
    for sql in (
        "UPDATE response_decision_audit SET actor='attacker'",
        "DELETE FROM response_decision_audit",
    ):
        with pytest.raises(sqlite3.IntegrityError, match="append-only"):
            conn.execute(sql)
        conn.rollback()


def test_command_filter_and_export_include_complete_bounded_history(client):
    analyst, _ = setup(client)
    rid = create(client, analyst).json()["response_id"]
    client.post(f"/api/v1/response-actions/{rid}/authorize", headers=analyst)
    conn = db.connect()
    command = conn.execute("SELECT command_id FROM commands").fetchone()[0]
    conn.executemany(
        "INSERT INTO command_audit VALUES (?,?,?,?,?,?)",
        [
            (f"extra-{i}", command, "transport_note", "agent:agent-1", "test", f"2099-{i:04}")
            for i in range(105)
        ],
    )
    conn.commit()
    client.post(
        f"/api/v1/response-actions/{rid}/cancel",
        headers=analyst,
        json={"reason": "Cancel queued collection"},
    )
    row = client.get("/api/v1/response-actions?command_state=CANCELLED", headers=analyst).json()[
        "response_actions"
    ][0]
    assert row["evidence_truncated"] and len(row["audit"]) == 100
    assert (
        client.get("/api/v1/response-actions?command_state=INDETERMINATE", headers=analyst).json()[
            "response_actions"
        ]
        == []
    )
    full = client.get(f"/api/v1/response-actions/{rid}/export", headers=analyst).json()[
        "response_action"
    ]
    assert not full["evidence_truncated"] and len(full["audit"]) == 107
    assert [r["event"] for r in full["decision_audit"]] == ["staged", "authorized", "cancelled"]


def test_shared_manual_request_fixtures_match_manager_validation():
    root = Path(__file__).resolve().parents[2] / "panopticon-contracts"
    fixtures = json.loads((root / "fixtures/analyst/requests.json").read_text())
    schema = json.loads((root / "schema/analyst-response-request.schema.json").read_text())
    for record in fixtures["valid"]:
        jsonschema.validate(record, schema)
        ManualRequest.model_validate(record)
    for record in fixtures["invalid"]:
        assert not jsonschema.Draft202012Validator(schema).is_valid(record)
        with pytest.raises(ValidationError):
            ManualRequest.model_validate(record)
    with pytest.raises(ValidationError):
        ManualRequest.model_validate({**fixtures["valid"][0], "request_id": None})
