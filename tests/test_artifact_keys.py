"""Artifact signature identity, two-key rotation proof and retained compromise flags."""

import base64
import copy
import json
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils
from fastapi import HTTPException

from manager import artifact_keys as keys
from manager import audit_chain, db
from tests.test_response_actions_route import _enroll_analyst
from tests.test_response_governance import identity


def point(key):
    return base64.b64encode(
        key.public_key().public_bytes(
            serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint
        )
    ).decode()


def signature(key, data):
    r, s = utils.decode_dss_signature(key.sign(data, ec.ECDSA(hashes.SHA256())))
    return base64.b64encode(r.to_bytes(32, "big") + s.to_bytes(32, "big")).decode()


def enrolled(client, *, agent_id="agent-1", host_id="host-1", key=None):
    key = key or ec.generate_private_key(ec.SECP256R1())
    challenge = client.post("/api/v1/agents/enrollment-challenge").json()
    result = client.post(
        "/api/v1/agents/enroll",
        json={
            "agent_id": agent_id,
            "host_id": host_id,
            "public_key": point(key),
            "nonce": challenge["nonce"],
            "signature": signature(key, base64.b64decode(challenge["nonce"])),
        },
        headers={"X-Panopticon-Enrollment-Token": "test-bootstrap-token"},
    )
    assert result.status_code == 200, result.text
    return key, {"Authorization": "Bearer " + result.json()["access_token"]}


def analyst(client):
    return {"Authorization": "Bearer " + _enroll_analyst(client, "operator")}


def proposal(client, old, new, *, request_id="rotate-1"):
    challenge = client.post("/api/v1/agents/enrollment-challenge").json()
    payload = {
        "request_id": request_id,
        "old_key_id": keys.public_key_id(point(old)),
        "new_public_key": point(new),
        "nonce": challenge["nonce"],
    }
    data = keys.rotation_input(
        agent_id="agent-1", host_id="host-1", expires_at=challenge["expires_at"], **payload
    )
    return {
        "schema_version": "1",
        **payload,
        "old_signature": signature(old, data),
        "new_signature": signature(new, data),
    }


def test_enrollment_records_versioned_key_and_chained_security_event(client):
    key, agent = enrolled(client)
    operator = analyst(client)
    response = client.get("/api/v1/agents/agent-1/artifact-keys", headers=operator)
    assert response.status_code == 200
    first = response.json()["keys"][0]
    assert first["public_key"] == point(key)
    assert first["key_version"] == 1 and first["trust_status"] == "active_key"
    # Agent key enrollment and the separately authenticated analyst identity are chained.
    assert audit_chain.verify(db.connect())["chain_verified_count"] == 2
    assert client.get("/api/v1/agents/agent-1/artifact-keys", headers=agent).status_code == 401


def test_central_signature_vector_verifies_and_manifest_edits_fail(client):
    root = (
        Path(__file__).resolve().parents[1]
        / "vendor/response_engine/tests/vendor/panopticon-contracts"
    )
    fixture = json.loads((root / "fixtures/artifacts/signing-v2.json").read_text())
    enrolled(client, key=ec.derive_private_key(1, ec.SECP256R1()))
    result = keys.verify_manifest(db.connect(), "agent-1", fixture["manifest"])
    assert result["public_key"] == fixture["public_key"]
    for field, value in (
        ("host_id", "another-host"),
        ("command_id", "another-command"),
        ("sha256", "0" * 64),
        ("produced_at_unix", 1),
    ):
        changed = copy.deepcopy(fixture["manifest"])
        changed[field] = value
        with pytest.raises(HTTPException):
            keys.verify_manifest(db.connect(), "agent-1", changed)


def test_rotation_requires_both_proofs_and_operator_approval_preserves_old_key(client):
    old, agent = enrolled(client)
    new = ec.generate_private_key(ec.SECP256R1())
    operator = analyst(client)
    body = proposal(client, old, new)
    url = "/api/v1/agents/agent-1/artifact-key-rotations"
    bad = {**body, "new_signature": body["old_signature"]}
    assert client.post(url, headers=agent, json=bad).status_code == 403
    accepted = client.post(url, headers=agent, json=body)
    assert accepted.status_code == 201, accepted.text
    assert accepted.json()["state"] == "PENDING"
    assert keys.current(db.connect(), "agent-1")["key_id"] == body["old_key_id"]
    assert client.post(url, headers=agent, json=body).json()["replayed"] is True
    assert (
        client.post(
            url, headers=agent, json={**body, "old_signature": body["new_signature"]}
        ).status_code
        == 409
    )
    approval = url + "/rotate-1/approve"
    assert client.post(approval, headers=agent).status_code == 401
    responder = identity(client, "requester", "responder")
    assert client.post(approval, headers=responder).status_code == 403
    assert client.post(approval, headers=operator).status_code == 200
    assert client.post(approval, headers=operator).json()["replayed"] is True
    history = client.get("/api/v1/agents/agent-1/artifact-keys", headers=operator).json()["keys"]
    assert len(history) == 2
    assert history[0]["trust_status"] == "retired_key"
    assert history[0]["public_key"] == point(old)
    assert history[1]["trust_status"] == "active_key" and history[1]["key_version"] == 2
    assert audit_chain.verify(db.connect())["legacy_import_count"] == 0


def test_rotation_nonce_replay_and_expired_approval_are_refused(client):
    old, agent = enrolled(client)
    new = ec.generate_private_key(ec.SECP256R1())
    body = proposal(client, old, new)
    url = "/api/v1/agents/agent-1/artifact-key-rotations"
    assert client.post(url, headers=agent, json=body).status_code == 201
    replay = {**body, "request_id": "another-rotation"}
    assert client.post(url, headers=agent, json=replay).status_code == 401
    conn = db.connect()
    conn.execute("UPDATE artifact_key_rotations SET expires_at='2000-01-01T00:00:00Z'")
    conn.commit()
    assert client.post(url + "/rotate-1/approve", headers=analyst(client)).status_code == 409
    assert keys.current(conn, "agent-1")["key_id"] == body["old_key_id"]
    assert conn.execute("SELECT COUNT(*) FROM artifact_signing_keys").fetchone()[0] == 1
    assert audit_chain.verify(conn)["complete_history_verified"]


def test_historical_key_material_cannot_be_replaced_or_deleted(client):
    import sqlite3

    enrolled(client)
    conn = db.connect()
    for statement in (
        "UPDATE artifact_signing_keys SET public_key='replacement'",
        "DELETE FROM artifact_signing_keys",
    ):
        with pytest.raises(sqlite3.IntegrityError):
            conn.execute(statement)
        conn.rollback()
    assert audit_chain.verify(conn)["complete_history_verified"]


def test_retired_key_only_finishes_previously_admitted_session(client):
    old, agent = enrolled(client, key=ec.derive_private_key(1, ec.SECP256R1()))
    root = (
        Path(__file__).resolve().parents[1]
        / "vendor/response_engine/tests/vendor/panopticon-contracts"
    )
    manifest = json.loads((root / "fixtures/artifacts/signing-v2.json").read_text())["manifest"]
    new = ec.generate_private_key(ec.SECP256R1())
    body = proposal(client, old, new)
    url = "/api/v1/agents/agent-1/artifact-key-rotations"
    assert client.post(url, headers=agent, json=body).status_code == 201
    assert client.post(url + "/rotate-1/approve", headers=analyst(client)).status_code == 200
    with pytest.raises(HTTPException, match="retired key"):
        keys.verify_manifest(db.connect(), "agent-1", manifest)
    assert (
        keys.verify_manifest(db.connect(), "agent-1", manifest, admitted_at="2020-01-01T00:00:00Z")[
            "key_version"
        ]
        == 1
    )
    # Historical verification is independent of trust eligibility.
    from response_engine.artifacts import artifact_signing_input

    assert keys.verify_signature(
        point(old), manifest["authorization"]["signature"], artifact_signing_input(manifest)
    )


def test_compromise_blocks_acceptance_and_status_is_queryable_without_key_deletion(client):
    old, _ = enrolled(client, key=ec.derive_private_key(1, ec.SECP256R1()))
    operator = analyst(client)
    key_id = keys.public_key_id(point(old))
    url = f"/api/v1/agents/agent-1/artifact-keys/{key_id}/revoke"
    body = {"request_id": "compromise-1", "reason": "Private key exposure confirmed"}
    first = client.post(url, headers=operator, json=body)
    assert first.status_code == 200 and first.json()["state"] == "compromised_key"
    assert client.post(url, headers=operator, json=body).json() == first.json()
    assert client.post(url, headers=operator, json={**body, "reason": "changed"}).status_code == 409
    history = client.get("/api/v1/agents/agent-1/artifact-keys", headers=operator).json()["keys"]
    assert len(history) == 1 and history[0]["trust_status"] == "compromised_key"
    assert history[0]["compromise_reason"] == body["reason"]
    assert history[0]["public_key"] == point(old)
    root = (
        Path(__file__).resolve().parents[1]
        / "vendor/response_engine/tests/vendor/panopticon-contracts"
    )
    manifest = json.loads((root / "fixtures/artifacts/signing-v2.json").read_text())["manifest"]
    with pytest.raises(HTTPException, match="compromised"):
        keys.verify_manifest(db.connect(), "agent-1", manifest, admitted_at="2020-01-01T00:00:00Z")
    events = client.get(
        "/api/v1/response-audit",
        headers=operator,
        params={"request_id": "compromise-1", "asset_id": "host-1"},
    ).json()["events"]
    assert sum(e["event"] == "artifact_key_compromised" for e in events) == 1
    assert audit_chain.verify(db.connect())["complete_history_verified"]


def test_compromised_retained_artifact_is_flagged_and_preserved(client):
    from manager import command_signing
    from manager.response_artifacts import manifests
    from tests.artifact_access_support import grant_reader
    from tests.test_analyst_operations import create
    from tests.test_response_actions_route import _stage_response_action
    from tests.test_response_artifacts import artifact, upload

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
    client.artifact_signer = command_signing.CommandSigner(private)
    client.artifact_signatures = {}
    grant_reader(client, operator)
    assert upload(client, agent, command, value).status_code == 200
    manifest = json.loads(
        conn.execute(
            "SELECT manifest_json FROM artifact_manifest_attestations WHERE artifact_id=?",
            (value["artifact_id"],),
        ).fetchone()[0]
    )
    keys.verify_manifest(conn, "agent-1", manifest)
    assert manifests(conn, command["command_id"])[0]["signing"]["trust_status"] == "active_key"
    original = bytes(conn.execute("SELECT content FROM response_artifacts").fetchone()[0])
    result = client.post(
        "/api/v1/agents/agent-1/artifact-keys/" + manifest["authorization"]["key_id"] + "/revoke",
        headers=operator,
        json={"request_id": "retained-compromise", "reason": "Key compromised"},
    )
    assert result.status_code == 200
    status = manifests(conn, command["command_id"])[0]["signing"]
    assert status["trust_status"] == "compromised_key" and status["compromised_at"]
    path = "/api/v1/response-artifacts/" + value["artifact_id"] + "/content"
    assert client.get(path, headers=operator).status_code == 403
    assert bytes(conn.execute("SELECT content FROM response_artifacts").fetchone()[0]) == original
    assert audit_chain.verify(conn)["complete_history_verified"]


def test_reimage_requires_new_agent_identity_and_revokes_old_host_binding(client):
    _, old_agent = enrolled(client)
    operator = analyst(client)
    url = "/api/v1/agents/agent-1/artifact-enrollment/revoke"
    body = {"request_id": "reimage-1", "reason": "Approved endpoint reimage"}
    assert client.post(url, headers=old_agent, json=body).status_code == 401
    result = client.post(url, headers=operator, json=body)
    assert result.status_code == 200
    assert client.post(url, headers=operator, json=body).json() == result.json()
    assert client.get("/api/v1/agents/agent-1/commands", headers=old_agent).status_code == 401
    enrolled(client, agent_id="agent-after-reimage", host_id="host-1")
    assert db.connect().execute("SELECT COUNT(*) FROM artifact_signing_keys").fetchone()[0] == 2
    assert (
        db.connect()
        .execute("SELECT revoked_at FROM enrolled_agents WHERE agent_id='agent-1'")
        .fetchone()[0]
    )
