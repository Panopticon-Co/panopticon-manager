"""No role-only, cross-case, cross-host or stale-credential artifact retrieval."""

import json
import sqlite3
from pathlib import Path

import jsonschema
import pytest

from manager import audit_chain, db
from tests.artifact_access_support import administrator, grant_reader
from tests.test_response_governance import identity
from tests.test_signed_artifacts import prepared

BASE = "/api/v1/artifact-access/grants"


def grant_body(**changes):
    return {
        "schema_version": "1",
        "policy_version": 1,
        "request_id": "access-1",
        "analyst_id": "operator",
        "host_id": "host-1",
        "alert_id": "alert-1",
        "reason": "Investigation assigned to this analyst",
        **changes,
    }


def retained(client):
    reader, agent, command, body, url = prepared(client, with_scope=False)
    assert client.post(url, headers=agent, json=body).status_code == 200
    path = "/api/v1/response-artifacts/" + body["manifest"]["artifact_id"]
    rid = (
        db.connect()
        .execute(
            "SELECT response_id FROM response_actions WHERE command_id=?", (command["command_id"],)
        )
        .fetchone()[0]
    )
    return reader, path, rid


def test_default_deny_covers_content_custody_case_and_alert_exports(client):
    reader, path, rid = retained(client)
    for suffix in ("/content", "/custody"):
        assert client.get(path + suffix, headers=reader).status_code == 403
    routes = (
        ("/api/v1/response-actions", lambda x: x["response_actions"]),
        (f"/api/v1/response-actions/{rid}/export", lambda x: [x["response_action"]]),
        ("/api/v1/alerts/alert-1", lambda x: x["response_actions"]),
    )
    for route, rows in routes:
        record = next(
            r for r in rows(client.get(route, headers=reader).json()) if r["response_id"] == rid
        )
        assert record["artifacts"] == []
        assert record["artifact_access"] == "requires_case_endpoint_grant"
    grant_reader(client, reader)
    for route, rows in routes:
        record = next(
            r for r in rows(client.get(route, headers=reader).json()) if r["response_id"] == rid
        )
        assert len(record["artifacts"]) == 1
        assert record["artifact_access"] == "granted"
    assert client.get(path + "/content", headers=reader).status_code == 200
    assert audit_chain.verify(db.connect())["complete_history_verified"]


def test_only_separately_provisioned_admin_can_grant_and_admin_needs_own_scope(client):
    reader, path, _ = retained(client)
    for role in ("viewer", "responder", "approver", "analyst"):
        actor = identity(client, "user-" + role, role)
        assert client.post(BASE, headers=actor, json=grant_body()).status_code == 403
        assert client.get(BASE, headers=actor).status_code == 403
    bad = client.post(
        "/api/v1/analysts/enroll",
        json={"analyst_id": "admin", "role": "artifact_admin"},
        headers={"X-Panopticon-Analyst-Enrollment-Token": "test-analyst-bootstrap-token"},
    )
    assert bad.status_code == 401
    admin = administrator(client)
    permissions = client.get("/api/v1/analysts/me", headers=admin).json()["permissions"]
    assert "response:decide" not in permissions
    assert client.get(path + "/content", headers=admin).status_code == 403
    grant_reader(client, reader, admin=admin)
    assert client.get(path + "/content", headers=reader).status_code == 200
    assert client.get(path + "/content", headers=admin).status_code == 403
    replacement = client.post(
        "/api/v1/analysts/enroll",
        json={"analyst_id": "evidence-admin", "role": "analyst"},
        headers={"X-Panopticon-Analyst-Enrollment-Token": "test-analyst-bootstrap-token"},
    )
    assert replacement.status_code == 403


def test_idempotent_grant_revoke_and_regrant_do_not_resurrect_old_grant(client):
    reader, path, _ = retained(client)
    admin = administrator(client)
    first = client.post(BASE, headers=admin, json=grant_body())
    assert first.status_code == 200, first.text
    count = audit_chain.verify(db.connect())["sequence"]
    assert client.post(BASE, headers=admin, json=grant_body()).json() == first.json()
    assert audit_chain.verify(db.connect())["sequence"] == count
    assert client.post(BASE, headers=admin, json=grant_body(reason="Changed")).status_code == 409
    grant_id = first.json()["grant"]["grant_id"]
    revoke = {
        "schema_version": "1",
        "policy_version": 1,
        "request_id": "revoke-1",
        "reason": "Assignment ended",
    }
    endpoint = BASE + "/" + grant_id + "/revoke"
    result = client.post(endpoint, headers=admin, json=revoke)
    assert result.status_code == 200 and result.json()["changed"]
    count = audit_chain.verify(db.connect())["sequence"]
    assert client.post(endpoint, headers=admin, json=revoke).json() == result.json()
    assert audit_chain.verify(db.connect())["sequence"] == count
    assert client.post(BASE, headers=admin, json=grant_body()).json() == first.json()
    assert client.get(path + "/content", headers=reader).status_code == 403
    second = client.post(BASE, headers=admin, json=grant_body(request_id="access-2")).json()
    assert second["grant"]["grant_id"] != grant_id
    assert client.get(path + "/content", headers=reader).status_code == 200
    listed = client.get(BASE, headers=admin).json()["grants"]
    assert len(listed) == 2 and "credential_digest" not in json.dumps(listed)


def test_credential_reissue_revocation_and_role_are_rechecked_on_each_retrieval(client):
    reader, path, _ = retained(client)
    admin = administrator(client)
    grant_reader(client, reader, admin=admin)
    assert client.get(path + "/content", headers=reader).status_code == 200
    replacement = identity(client, "operator", "analyst")
    assert client.get(path + "/content", headers=reader).status_code == 401
    assert client.get(path + "/content", headers=replacement).status_code == 403
    grant_reader(client, replacement, admin=admin, request_id="after-reissue")
    assert client.get(path + "/content", headers=replacement).status_code == 200
    conn = db.connect()
    conn.execute("UPDATE analyst_credentials SET role='viewer' WHERE analyst_id='operator'")
    conn.commit()
    assert client.get(path + "/content", headers=replacement).status_code == 403
    conn.execute("UPDATE analyst_credentials SET revoked_at='now' WHERE analyst_id='operator'")
    conn.commit()
    assert client.get(path + "/custody", headers=replacement).status_code == 401


@pytest.mark.parametrize("other_host", ["host-1", "host-2"])
def test_valid_grant_for_another_case_or_endpoint_never_opens_this_artifact(client, other_host):
    reader, path, _ = retained(client)
    conn = db.connect()
    source = dict(conn.execute("SELECT * FROM alerts WHERE alert_id='alert-1'").fetchone())
    source.update(alert_id="case-2", host_id=other_host)
    columns = ",".join(source)
    placeholders = ",".join("?" for _ in source)
    conn.execute(f"INSERT INTO alerts ({columns}) VALUES ({placeholders})", tuple(source.values()))
    conn.commit()
    grant_reader(client, reader, host_id=other_host, alert_id="case-2")
    assert client.get(path + "/content", headers=reader).status_code == 403
    assert client.get(path + "/custody", headers=reader).status_code == 403


def test_identical_bootstrap_secrets_refuse_administrator_enrollment(client, monkeypatch):
    monkeypatch.setenv("PANOPTICON_ARTIFACT_ADMIN_ENROLLMENT_TOKEN", "test-analyst-bootstrap-token")
    response = client.post(
        "/api/v1/analysts/enroll",
        json={"analyst_id": "admin", "role": "artifact_admin"},
        headers={"X-Panopticon-Analyst-Enrollment-Token": "test-analyst-bootstrap-token"},
    )
    assert response.status_code == 503


@pytest.mark.parametrize(
    "changes",
    [
        {"host_id": "other-host"},
        {"alert_id": "other-case"},
        {"host_id": "*"},
        {"analyst_id": "unprovisioned"},
    ],
)
def test_scope_is_exact_never_wildcard_or_cross_case(client, changes):
    reader, path, _ = retained(client)
    admin = administrator(client)
    assert client.post(BASE, headers=admin, json=grant_body(**changes)).status_code == 403
    assert client.get(path + "/content", headers=reader).status_code == 403
    assert db.connect().execute("SELECT COUNT(*) FROM artifact_access_grants").fetchone()[0] == 0


def test_critical_asset_still_requires_explicit_grant_and_reader_role(client):
    reader, path, _ = retained(client)
    conn = db.connect()
    raw = json.loads(
        conn.execute("SELECT alert_json FROM alerts WHERE alert_id='alert-1'").fetchone()[0]
    )
    raw["asset_class"] = "critical"
    conn.execute("UPDATE alerts SET alert_json=? WHERE alert_id='alert-1'", (json.dumps(raw),))
    conn.commit()
    assert client.get(path + "/content", headers=reader).status_code == 403
    admin = administrator(client)
    identity(client, "observer", "viewer")
    assert (
        client.post(BASE, headers=admin, json=grant_body(analyst_id="observer")).status_code == 403
    )
    grant_reader(client, reader, admin=admin)
    assert client.get(path + "/content", headers=reader).status_code == 200
    assert conn.execute("SELECT COUNT(*) FROM commands").fetchone()[0] == 1


def test_scope_history_is_immutable_and_audit_failure_rolls_back_grant(client):
    reader, _, _ = retained(client)
    admin = administrator(client)
    conn = db.connect()
    conn.execute("""CREATE TRIGGER refuse_scope_audit BEFORE INSERT ON response_security_audit
        WHEN NEW.event='artifact_access_granted'
        BEGIN SELECT RAISE(ABORT,'audit unavailable'); END""")
    conn.commit()
    with pytest.raises(sqlite3.IntegrityError, match="audit unavailable"):
        client.post(BASE, headers=admin, json=grant_body())
    assert conn.execute("SELECT COUNT(*) FROM artifact_access_grants").fetchone()[0] == 0
    conn.execute("DROP TRIGGER refuse_scope_audit")
    conn.commit()
    result = grant_reader(client, reader, admin=admin)
    for query in (
        "UPDATE artifact_access_grants SET host_id='other'",
        "DELETE FROM artifact_access_grants",
    ):
        with pytest.raises(sqlite3.IntegrityError):
            conn.execute(query)
        conn.rollback()
    query = client.get(
        "/api/v1/response-audit",
        headers=reader,
        params={
            "request_id": "scope-test-1",
            "actor": "analyst:evidence-admin",
            "asset_id": "host-1",
            "since": "2026-01-01T00:00:00Z",
        },
    )
    assert query.status_code == 200 and len(query.json()["events"]) == 1
    detail = json.loads(query.json()["events"][0]["payload"]["detail"])
    assert detail["grant_id"] == result["grant"]["grant_id"]
    assert audit_chain.verify(conn)["complete_history_verified"]


def test_scope_request_matches_closed_central_policy_schema(client):
    from manager.routers.artifact_access import Grant

    root = Path(__file__).resolve().parents[2] / "panopticon-contracts/schema"
    schema = json.loads((root / "artifact-access-grant-v1.schema.json").read_text())
    jsonschema.validate(grant_body(), schema)
    assert Grant.model_validate(grant_body()).model_dump() == grant_body()
    for changed in (
        {"policy_version": True},
        {"policy_version": 2},
        {"reason": "   "},
        {"automatic": True},
    ):
        with pytest.raises(ValueError):
            Grant.model_validate(grant_body(**changed))
        with pytest.raises(jsonschema.ValidationError):
            jsonschema.validate(grant_body(**changed), schema)
