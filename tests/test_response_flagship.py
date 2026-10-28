"""Focused unit/API regression tests; no native endpoint or E2E execution."""

import json
import os
from pathlib import Path

import jsonschema
import pytest

from manager import command_signing, db
from manager.routers.response_actions import CampaignRequest
from tests.test_analyst_operations import create, setup
from tests.test_response_governance import identity


def test_channel_contact_is_authenticated_and_signing_demand_is_sticky(client):
    analyst, agent = setup(client)
    path = "/api/v1/agents/agent-1/commands?delivery_mode=durable&command_auth=ES256"
    assert client.get(path, headers=analyst).status_code == 401
    assert db.connect().execute("SELECT COUNT(*) FROM agent_response_channels").fetchone()[0] == 0
    assert client.get(path, headers=agent).json()["commands"] == []
    client.get("/api/v1/agents/agent-1/commands", headers=agent)
    readiness = client.get("/api/v1/agents/agent-1/response-readiness", headers=analyst).json()
    assert readiness["contact_state"] == "recent" and readiness["command_auth"] == "ES256"
    assert readiness["execution_mode"] == "unknown"
    assert readiness["native_capabilities"] == "not_reported"
    rid = create(client, analyst).json()["response_id"]
    preview = client.get(f"/api/v1/response-actions/{rid}/preflight", headers=analyst).json()
    assert preview["advisory"] and not preview["allowed_to_authorize"]
    assert any(
        c["check"] == "command_authority" and c["state"] == "block" for c in preview["checks"]
    )
    assert (
        client.post(f"/api/v1/response-actions/{rid}/authorize", headers=analyst).status_code == 503
    )


def test_preflight_rechecks_identity_and_separate_approver(client, monkeypatch):
    analyst, _ = setup(client)
    rid = create(client, analyst, "ISOLATE_HOST").json()["response_id"]
    path = f"/api/v1/response-actions/{rid}/preflight"
    result = client.get(path, headers=analyst).json()
    assert result["allowed_to_authorize"] and result["readiness"]["contact_state"] == "unknown"
    assert any(c["state"] == "warning" for c in result["checks"])
    viewer = identity(client, "review-only", "viewer")
    assert not client.get(path, headers=viewer).json()["allowed_to_authorize"]
    monkeypatch.setenv("PANOPTICON_REQUIRE_SEPARATE_APPROVER", "true")
    assert not client.get(path, headers=analyst).json()["allowed_to_authorize"]
    conn = db.connect()
    conn.execute("UPDATE enrolled_agents SET host_id='rebound'")
    conn.commit()
    result = client.get(path, headers=analyst).json()
    assert any(c["check"] == "retained_target" and c["state"] == "block" for c in result["checks"])


def test_signing_key_rotation_and_invalid_replacement_fail_closed(tmp_path, monkeypatch):
    path = tmp_path / "authority.pem"
    command_signing.generate(path)
    monkeypatch.setenv(command_signing.SIGNING_KEY_ENV, str(path))
    first = command_signing.readiness()
    replacement = tmp_path / "rotated.pem"
    command_signing.generate(replacement)
    os.replace(replacement, path)
    second = command_signing.readiness()
    assert first["state"] == second["state"] == "ready" and first["key_id"] != second["key_id"]
    path.write_text("invalid replacement")
    assert command_signing.readiness()["state"] == "unavailable"
    if os.name == "posix":
        path.write_text("not read when permissions are broad")
        path.chmod(0o644)
        with pytest.raises(command_signing.SigningUnavailable):
            command_signing.load_key_file(path)


def test_campaign_partial_results_are_retry_safe_and_never_authorize(client):
    analyst, _ = setup(client)
    request = {
        "campaign_id": "case-1",
        "items": [
            {"alert_id": "alert-1", "action": "ISOLATE_HOST", "reason": "Contain after review"},
            {
                "alert_id": "missing-alert",
                "action": "COLLECT_NETWORK_CONNECTIONS",
                "reason": "Inspect",
            },
            {
                "alert_id": "alert-1",
                "action": "COLLECT_FILE",
                "reason": "Collect",
                "target": {"path": "/tmp/evidence"},
            },
        ],
    }
    first = client.post("/api/v1/response-campaigns", json=request, headers=analyst)
    assert first.status_code == 201, first.text
    report = first.json()
    assert report["created_count"] == 2 and report["failed_count"] == 1
    assert [item["status_code"] for item in report["items"]] == [201, 422, 201]
    conn = db.connect()
    assert conn.execute("SELECT COUNT(*) FROM commands").fetchone()[0] == 0
    before = conn.execute("SELECT COUNT(*) FROM response_actions").fetchone()[0]
    replay = client.post("/api/v1/response-campaigns", json=request, headers=analyst).json()
    assert replay["replayed"] and replay["items"] == report["items"]
    assert conn.execute("SELECT COUNT(*) FROM response_actions").fetchone()[0] == before
    request["items"][0]["reason"] = "Different intent"
    assert (
        client.post("/api/v1/response-campaigns", json=request, headers=analyst).status_code == 409
    )
    history = client.get("/api/v1/response-campaigns", headers=analyst).json()["campaigns"]
    assert len(history) == 1 and history[0]["created_count"] == 2
    viewer = identity(client, "campaign-viewer", "viewer")
    assert (
        client.post("/api/v1/response-campaigns", json=request, headers=viewer).status_code == 403
    )
    assert (
        conn.execute(
            "SELECT COUNT(*) FROM response_decision_audit WHERE event='campaign_linked'"
        ).fetchone()[0]
        == 2
    )


def test_campaign_limits_and_central_schema_agree(client):
    analyst, _ = setup(client)
    item = {"alert_id": "alert-1", "action": "ISOLATE_HOST", "reason": "Review"}
    assert (
        client.post(
            "/api/v1/response-campaigns",
            headers=analyst,
            json={"campaign_id": "oversized", "items": [item] * 26},
        ).status_code
        == 422
    )
    assert (
        client.post(
            "/api/v1/response-campaigns",
            headers=analyst,
            json={"campaign_id": "override", "items": [{**item, "request_id": "hidden"}]},
        ).status_code
        == 422
    )
    root = Path(__file__).resolve().parents[2] / "panopticon-contracts"
    schema = json.loads((root / "schema/response-campaign-request.schema.json").read_text())
    fixtures = json.loads((root / "fixtures/analyst/campaigns.json").read_text())
    assert (
        schema["properties"]["items"]["maxItems"]
        == CampaignRequest.model_json_schema()["properties"]["items"]["maxItems"]
    )
    for record in fixtures["valid"]:
        jsonschema.validate(record, schema)
        CampaignRequest.model_validate(record)
