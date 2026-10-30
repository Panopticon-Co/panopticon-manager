import copy
import json
import sqlite3
from datetime import datetime

import pytest
from fastapi import HTTPException

from manager import audit_chain, db
from manager.forensic_context import validate_retained_manifest
from tests.artifact_access_support import grant_reader
from tests.test_analyst_operations import create, setup
from tests.test_auto_triage import alert
from tests.test_signed_artifacts import prepared


def staged(client, *, provenance=True):
    reader, agent = setup(client)
    if provenance:
        value = alert(detection_source="rule")
        db.connect().execute(
            "UPDATE alerts SET alert_json=?,event_id=?,alert_timestamp=?,detection_source='rule'",
            (json.dumps(value), value["event_id"], value["timestamp"]),
        )
        db.connect().commit()
    result = create(client, reader, request_id="forensic-request")
    assert result.status_code == 201
    return reader, agent, result.json()["response_id"]


def exported(client, reader, rid):
    response = client.get(f"/api/v1/response-actions/{rid}/export", headers=reader)
    assert response.status_code == 200
    return response.json()["response_action"]


def test_planner_is_called_before_execution_and_scope_gates_the_context(client):
    reader, agent, rid = staged(client)
    saved = json.loads(db.connect().execute(
        "SELECT plan_json FROM response_forensic_plans WHERE response_id=?", (rid,),
    ).fetchone()[0])
    assert saved["state"] == "planned" and saved["advisory_only"]
    plan = saved["plan"]
    assert plan["request"]["context"]["source_record_id"] == "original-event"
    assert plan["request"]["context"]["source_id"] == "rule"
    assert plan["request"]["context"]["alert_id"] == "alert-1"
    assert plan["asset_class"] == "unknown" and plan["decision"] == "require_approval"
    assert plan["policy_id"] == "forensic-context-v1" and plan["policy_version"] == 1
    assert not db.connect().execute("SELECT 1 FROM commands").fetchone()
    assert exported(client, reader, rid)["forensic_context"] is None
    grant_reader(client, reader)
    record = exported(client, reader, rid)
    assert record["artifact_access"] == "granted"
    assert record["forensic_context"]["plan"] == plan
    assert record["forensic_context"]["effective_response_tier"] == "ANALYST_APPROVAL"
    assert not client.get("/api/v1/agents/agent-1/commands", headers=agent).json()["commands"]
    assert audit_chain.verify(db.connect())["complete_history_verified"]


def test_request_retry_does_not_duplicate_or_rewrite_forensic_planning(client):
    reader, _, rid = staged(client)
    before = audit_chain.verify(db.connect())["sequence"]
    repeated = create(client, reader, request_id="forensic-request")
    assert repeated.status_code == 201 and repeated.json()["response_id"] == rid
    assert repeated.json()["replayed"]
    assert audit_chain.verify(db.connect())["sequence"] == before
    assert db.connect().execute("SELECT COUNT(*) FROM response_forensic_plans").fetchone()[0] == 1
    events = client.get("/api/v1/response-audit", headers=reader, params={
        "request_id": rid, "actor": "analyst:alice", "asset_id": "host-1",
        "since": "2020-01-01T00:00:00Z",
    }).json()["events"]
    assert any(e["event"] == "forensic_collection_planned" for e in events)
    for operation in ("UPDATE response_forensic_plans SET plan_json='{}'",
                      "DELETE FROM response_forensic_plans"):
        with pytest.raises(sqlite3.IntegrityError, match="immutable"):
            db.connect().execute(operation)
        db.connect().rollback()


def test_missing_legacy_provenance_is_explicit_and_never_fabricated(client):
    reader, _, rid = staged(client, provenance=False)
    grant_reader(client, reader)
    value = exported(client, reader, rid)["forensic_context"]
    assert value["state"] == "unavailable"
    assert "plan" not in value
    assert "observed_at" not in value and "sha256" not in value


def test_native_identity_is_exposed_without_browser_integer_rounding(client):
    from tests.test_endpoint_records import records

    reader, _ = setup(client)
    raw = records()[0]
    value = alert(endpoint_context=raw, detection_source="rule")
    db.connect().execute(
        "UPDATE alerts SET alert_json=?,event_id=?,alert_timestamp=?",
        (json.dumps(value), raw["record_id"], value["timestamp"]),
    )
    db.connect().commit()
    rid = create(client, reader, action="COLLECT_PROCESS_INFO").json()["response_id"]
    grant_reader(client, reader)
    context = exported(client, reader, rid)["forensic_context"]
    assert context["state"] == "planned"
    assert context["native_process_identity"]["start_time_ticks"] == raw["subject"][
        "native_creation_ticks"]
    assert context["plan"]["request"]["context"]["source_record_id"] == raw["record_id"]
    assert datetime.fromisoformat(context["plan"]["request"]["context"]["observed_at"].replace(
        "Z", "+00:00")) == datetime.fromisoformat(raw["observed_at"].replace("Z", "+00:00"))


def test_plan_snapshot_cannot_silently_diverge_from_its_chained_audit_fact(client):
    reader, _, rid = staged(client)
    grant_reader(client, reader)
    conn = db.connect()
    conn.execute("DROP TRIGGER forensic_plan_no_update")
    conn.execute("UPDATE response_forensic_plans SET plan_json='{}'")
    conn.commit()
    value = exported(client, reader, rid)["forensic_context"]
    assert value["state"] == "inconsistent_plan" and "plan" not in value


def test_signed_evidence_is_metadata_validated_attached_and_audited_once(client):
    reader, agent, command, body, url = prepared(client)
    assert client.post(url, headers=agent, json=body).status_code == 200
    rid = db.connect().execute("SELECT response_id FROM response_actions WHERE command_id=?",
                               (command["command_id"],)).fetchone()[0]
    value = exported(client, reader, rid)["forensic_context"]
    reference = value["evidence_references"][0]
    assert reference["manifest"] == body["manifest"]
    assert reference["metadata_status"] == "consistent_with_retained_command"
    assert reference["trust_status"] == "active_key"
    assert "content_base64" not in reference
    count = audit_chain.verify(db.connect())["sequence"]
    assert client.post(url, headers=agent, json=body).status_code == 200
    assert audit_chain.verify(db.connect())["sequence"] == count
    assert db.connect().execute("SELECT COUNT(*) FROM response_security_audit "
                                "WHERE event='forensic_metadata_validated'").fetchone()[0] == 1
    db.connect().execute("UPDATE artifact_signing_keys SET compromised_at='2026-10-30T00:00:00Z',"
                         "compromise_reason='Retained forensic evidence must remain flagged'")
    db.connect().commit()
    value = exported(client, reader, rid)["forensic_context"]
    assert value["evidence_references"][0]["trust_status"] == "compromised_key"
    # Existing download enforcement, not the forensic summary, remains authoritative.
    path = "/api/v1/response-artifacts/" + body["manifest"]["artifact_id"] + "/content"
    assert client.get(path, headers=reader).status_code == 403


@pytest.mark.parametrize("field,value", [
    ("host_id", "different-host"), ("agent_id", "different-agent"),
    ("command_id", "another-command"), ("correlation_id", "another-case"),
    ("kind", "process_snapshot"), ("sha256", "A" * 64),
])
def test_metadata_validation_uses_manager_binding_not_upload_claims(client, field, value):
    _, _, command, body, _ = prepared(client)
    original = copy.deepcopy(body["manifest"])
    original[field] = value
    with pytest.raises(HTTPException) as error:
        validate_retained_manifest(db.connect(), original, command["command_id"])
    assert error.value.status_code == 422


def test_failed_forensic_metadata_audit_cannot_commit_accepted_evidence(client):
    _, agent, _, body, url = prepared(client)
    conn = db.connect()
    conn.execute("CREATE TRIGGER fail_forensic_audit BEFORE INSERT ON response_security_audit "
                 "WHEN NEW.event='forensic_metadata_validated' "
                 "BEGIN SELECT RAISE(ABORT,'forensic audit unavailable'); END")
    conn.commit()
    with pytest.raises(sqlite3.IntegrityError, match="forensic audit unavailable"):
        client.post(url, headers=agent, json=body)
    assert not conn.execute("SELECT 1 FROM response_artifacts WHERE artifact_id=?",
                            (body["manifest"]["artifact_id"],)).fetchone()
    assert not conn.execute("SELECT 1 FROM artifact_manifest_attestations").fetchone()
    assert audit_chain.verify(conn)["complete_history_verified"]


def test_existing_signed_collection_execution_reports_remain_accepted(client):
    from cryptography.hazmat.primitives.asymmetric import ec
    from response_engine.artifacts import artifact_signing_input

    from manager.command_signing import CommandSigner

    private = ec.generate_private_key(ec.SECP256R1())
    reader, agent, command, body, url = prepared(client, key=private)
    body["manifest"]["kind"] = "execution_report"
    body["manifest"]["authorization"] = CommandSigner(private).sign_bytes(
        artifact_signing_input(body["manifest"]),
    )
    response = client.post(url, headers=agent, json=body)
    assert response.status_code == 200, response.text
    rid = db.connect().execute("SELECT response_id FROM response_actions WHERE command_id=?",
                               (command["command_id"],)).fetchone()[0]
    retained = exported(client, reader, rid)
    assert retained["artifacts"][0]["kind"] == "execution_report"
    assert not retained["forensic_context"]["evidence_references"]
    assert audit_chain.verify(db.connect())["complete_history_verified"]
