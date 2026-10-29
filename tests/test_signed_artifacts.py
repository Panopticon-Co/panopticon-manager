"""Real authenticated signed-manifest retention; no native endpoint execution."""

import base64
import copy
import json

import pytest
from response_engine.artifacts import artifact_signing_input

from manager import audit_chain, command_signing, db
from tests.test_analyst_operations import create
from tests.test_artifact_keys import analyst, enrolled
from tests.test_response_actions_route import _stage_response_action
from tests.test_response_artifacts import artifact


def prepared(client):
    private, agent = enrolled(client)
    operator = analyst(client)
    _stage_response_action("agent-1", "alert-1", action="ISOLATE_HOST")
    conn = db.connect()
    conn.execute("UPDATE response_actions SET lifecycle_state='REJECTED'")
    conn.execute("UPDATE alerts SET host_id='host-1'")
    conn.commit()
    rid = create(client, operator).json()["response_id"]
    assert (
        client.post(f"/api/v1/response-actions/{rid}/authorize", headers=operator).status_code
        == 200
    )
    command = client.get("/api/v1/agents/agent-1/commands", headers=agent).json()["commands"][0]
    value = artifact(command)
    manifest = {k: v for k, v in value.items() if k != "content_base64"}
    manifest.update(
        schema_version="2",
        agent_id="agent-1",
        produced_at_unix=1793232000,
        authorization={
            "algorithm": "ES256",
            "key_id": command_signing.key_id(command_signing.public_point(private.public_key())),
            "signature": base64.b64encode(bytes(64)).decode(),
        },
    )
    manifest["authorization"] = command_signing.CommandSigner(private).sign_bytes(
        artifact_signing_input(manifest)
    )
    body = {"manifest": manifest, "content_base64": value["content_base64"]}
    url = f"/api/v1/agents/agent-1/commands/{command['command_id']}/artifacts/signed"
    return operator, agent, command, body, url


def test_exact_signed_upload_retry_has_one_attestation_and_complete_custody(client):
    operator, agent, command, body, url = prepared(client)
    first = client.post(url, headers=agent, json=body)
    assert first.status_code == 200, first.text
    assert first.json() == {
        "artifact_id": body["manifest"]["artifact_id"],
        "sha256": body["manifest"]["sha256"],
        "retained": True,
    }
    conn = db.connect()
    count = audit_chain.verify(conn)["sequence"]
    assert client.post(url, headers=agent, json=body).json() == first.json()
    assert audit_chain.verify(conn)["sequence"] == count
    assert conn.execute("SELECT COUNT(*) FROM artifact_manifest_attestations").fetchone()[0] == 1
    rows = client.get("/api/v1/response-actions", headers=operator).json()["response_actions"]
    case = next(row for row in rows if row["command_id"] == command["command_id"])
    assert case["artifacts"][0]["signing"]["trust_status"] == "active_key"
    assert case["command_lifecycle_state"] == "DISPATCHED"
    events = conn.execute(
        "SELECT event FROM response_artifact_custody ORDER BY sequence"
    ).fetchall()
    assert [row[0] for row in events] == [
        "received",
        "artifact_produced",
        "artifact_transferred",
        "artifact_signature_verified",
        "artifact_hash_verified",
    ]


@pytest.mark.parametrize("change", ["signature", "bytes", "command", "public_key", "unsigned"])
def test_manifest_mismatch_is_refused_audited_and_never_retained(client, change):
    _, agent, _, body, url = prepared(client)
    invalid = copy.deepcopy(body)
    if change == "signature":
        invalid["manifest"]["authorization"]["signature"] = base64.b64encode(bytes(64)).decode()
    elif change == "bytes":
        invalid["content_base64"] = base64.b64encode(b'{"different":true}').decode()
    elif change == "command":
        invalid["manifest"]["command_id"] = "another-command"
    elif change == "public_key":
        invalid["public_key"] = "untrusted upload key"
    else:
        del invalid["manifest"]["authorization"]
    response = client.post(url, headers=agent, json=invalid)
    assert response.status_code == 422, response.text
    conn = db.connect()
    assert conn.execute("SELECT COUNT(*) FROM response_artifacts").fetchone()[0] == 0
    assert (
        conn.execute(
            "SELECT COUNT(*) FROM response_security_audit WHERE event='artifact_manifest_refused'"
        ).fetchone()[0]
        == 1
    )
    assert audit_chain.verify(conn)["complete_history_verified"]


def test_signed_manifest_cannot_be_changed_or_reattested_on_retry(client):
    _, agent, _, body, url = prepared(client)
    assert client.post(url, headers=agent, json=body).status_code == 200
    changed = copy.deepcopy(body)
    changed["manifest"]["produced_at_unix"] += 1
    assert client.post(url, headers=agent, json=changed).status_code == 409
    original = json.loads(
        db.connect()
        .execute("SELECT manifest_json FROM artifact_manifest_attestations")
        .fetchone()[0]
    )
    assert original == body["manifest"]
