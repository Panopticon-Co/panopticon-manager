"""Interruption, durable replay, admission budgets and execution-time key rechecks."""

import base64
import copy
import hashlib
import json
import os
import sqlite3
from pathlib import Path

import jsonschema
from cryptography.hazmat.primitives.asymmetric import ec
from response_engine.artifacts import artifact_signing_input

from manager import artifact_transfers as transfers
from manager import audit_chain, command_signing, db
from tests.test_artifact_keys import proposal
from tests.test_signed_artifacts import prepared


def data(size=140000):
    return b'{"evidence":"' + b"x" * size + b'"}'


def start(client, agent, command, body):
    url = f"/api/v1/agents/agent-1/commands/{command['command_id']}/artifact-transfers"
    return url, client.post(
        url, headers=agent, json={"schema_version": "1", "manifest": body["manifest"]}
    )


def chunk(client, agent, url, body, offset, content, *, digest=None):
    return client.put(
        url + "/" + body["manifest"]["artifact_id"] + f"/chunks/{offset}",
        headers={
            **agent,
            "Content-Type": "application/octet-stream",
            "X-Panopticon-Chunk-SHA256": digest or hashlib.sha256(content).hexdigest(),
        },
        content=content,
    )


def finish(client, agent, url, body, digest):
    return client.post(
        url + "/" + body["manifest"]["artifact_id"] + "/complete",
        headers=agent,
        json={"schema_version": "1", "manifest_sha256": digest},
    )


def resign(body, key):
    body["manifest"]["authorization"] = command_signing.CommandSigner(key).sign_bytes(
        artifact_signing_input(body["manifest"])
    )
    return body


def send_remaining(client, agent, url, body, offset=0):
    content = base64.b64decode(body["content_base64"])
    while offset < len(content):
        part = content[offset : offset + transfers.CHUNK_BYTES]
        reply = chunk(client, agent, url, body, offset, part)
        assert reply.status_code == 200, reply.text
        offset += len(part)
        assert reply.json()["received_bytes"] == offset
    return content


def test_interruption_resume_new_connection_exact_retry_and_final_retention(client):
    operator, agent, command, body, _ = prepared(client, data=data())
    url, admission = start(client, agent, command, body)
    assert admission.status_code == 200, admission.text
    first = admission.json()
    assert first["received_bytes"] == 0 and not first["complete"]
    conn = db.connect()
    count = audit_chain.verify(conn)["sequence"]
    assert start(client, agent, command, body)[1].json() == first
    assert audit_chain.verify(conn)["sequence"] == count
    raw = base64.b64decode(body["content_base64"])
    first_part = raw[: transfers.CHUNK_BYTES]
    reply = chunk(client, agent, url, body, 0, first_part)
    assert reply.status_code == 200
    assert conn.execute("SELECT COUNT(*) FROM response_artifacts").fetchone()[0] == 0
    assert (
        client.get(
            "/api/v1/response-artifacts/" + body["manifest"]["artifact_id"] + "/content",
            headers=operator,
        ).status_code
        == 404
    )
    count = audit_chain.verify(conn)["sequence"]
    assert chunk(client, agent, url, body, 0, first_part).json() == reply.json()
    assert audit_chain.verify(conn)["sequence"] == count
    reopened = sqlite3.connect(os.environ["PANOPTICON_DB_PATH"])
    reopened.row_factory = sqlite3.Row
    audit_chain.register(reopened)
    reopened.execute("BEGIN IMMEDIATE")
    resumed = transfers.admit(
        reopened,
        "agent-1",
        command["command_id"],
        transfers.Admission(schema_version="1", manifest=body["manifest"]),
    )
    reopened.commit()
    reopened.close()
    assert resumed["received_bytes"] == transfers.CHUNK_BYTES
    send_remaining(client, agent, url, body, resumed["received_bytes"])
    result = finish(client, agent, url, body, first["manifest_sha256"])
    assert result.status_code == 200, result.text
    assert result.json() == {
        "artifact_id": body["manifest"]["artifact_id"],
        "sha256": body["manifest"]["sha256"],
        "retained": True,
    }
    count = audit_chain.verify(conn)["sequence"]
    assert finish(client, agent, url, body, first["manifest_sha256"]).json() == result.json()
    assert start(client, agent, command, body)[1].json()["complete"] is True
    assert audit_chain.verify(conn)["sequence"] == count
    assert bytes(conn.execute("SELECT content FROM response_artifacts").fetchone()[0]) == raw
    assert conn.execute("SELECT COUNT(*) FROM response_artifact_chunks").fetchone()[0] == 0
    assert (
        conn.execute("SELECT reserved_bytes FROM response_artifact_transfer_usage").fetchone()[0]
        == 0
    )


def test_changed_manifest_duplicate_chunk_and_out_of_order_are_refused(client):
    _, agent, command, body, _ = prepared(client, data=data())
    url, response = start(client, agent, command, body)
    assert response.status_code == 200
    raw = base64.b64decode(body["content_base64"])
    assert (
        chunk(
            client,
            agent,
            url,
            body,
            transfers.CHUNK_BYTES,
            raw[transfers.CHUNK_BYTES : transfers.CHUNK_BYTES * 2],
        ).status_code
        == 409
    )
    assert chunk(client, agent, url, body, 0, raw[: transfers.CHUNK_BYTES]).status_code == 200
    changed = b"z" + raw[1 : transfers.CHUNK_BYTES]
    assert chunk(client, agent, url, body, 0, changed).status_code == 409
    different = copy.deepcopy(body)
    different["manifest"]["produced_at_unix"] += 1
    assert start(client, agent, command, different)[1].status_code == 409
    assert finish(client, agent, url, body, "f" * 64).status_code == 409
    assert finish(client, agent, url, body, response.json()["manifest_sha256"]).status_code == 409
    assert (
        db.connect().execute("SELECT received_bytes FROM response_artifact_transfers").fetchone()[0]
        == transfers.CHUNK_BYTES
    )


def test_wrong_whole_hash_rolls_back_completion_and_keeps_reserved_partial_bytes(client):
    private = ec.generate_private_key(ec.SECP256R1())
    _, agent, command, body, _ = prepared(client, data=data(100), key=private)
    body["manifest"]["sha256"] = "0" * 64
    resign(body, private)
    url, response = start(client, agent, command, body)
    assert response.status_code == 200
    send_remaining(client, agent, url, body)
    result = finish(client, agent, url, body, response.json()["manifest_sha256"])
    assert result.status_code == 422, result.text
    conn = db.connect()
    assert conn.execute("SELECT state FROM response_artifact_transfers").fetchone()[0] == "OPEN"
    assert (
        conn.execute("SELECT reserved_bytes FROM response_artifact_transfer_usage").fetchone()[0]
        == body["manifest"]["content_bytes"]
    )
    assert conn.execute("SELECT COUNT(*) FROM response_artifacts").fetchone()[0] == 0
    assert conn.execute("SELECT COUNT(*) FROM response_artifact_chunks").fetchone()[0] == 1
    assert audit_chain.verify(conn)["complete_history_verified"]


def test_revocation_mid_transfer_blocks_further_chunks_and_completion(client):
    operator, agent, command, body, _ = prepared(client, data=data())
    url, response = start(client, agent, command, body)
    raw = base64.b64decode(body["content_base64"])
    assert chunk(client, agent, url, body, 0, raw[: transfers.CHUNK_BYTES]).status_code == 200
    key_id = body["manifest"]["authorization"]["key_id"]
    revoked = client.post(
        f"/api/v1/agents/agent-1/artifact-keys/{key_id}/revoke",
        headers=operator,
        json={"request_id": "compromised-during-transfer", "reason": "Key exposure"},
    )
    assert revoked.status_code == 200
    assert (
        chunk(
            client,
            agent,
            url,
            body,
            transfers.CHUNK_BYTES,
            raw[transfers.CHUNK_BYTES : transfers.CHUNK_BYTES * 2],
        ).status_code
        == 403
    )
    assert finish(client, agent, url, body, response.json()["manifest_sha256"]).status_code == 403
    assert db.connect().execute("SELECT COUNT(*) FROM response_artifacts").fetchone()[0] == 0


def test_retired_key_can_finish_previously_admitted_session(client):
    private = ec.generate_private_key(ec.SECP256R1())
    operator, agent, command, body, _ = prepared(client, data=data(100), key=private)
    url, response = start(client, agent, command, body)
    rotation = proposal(client, private, ec.generate_private_key(ec.SECP256R1()))
    key_url = "/api/v1/agents/agent-1/artifact-key-rotations"
    assert client.post(key_url, headers=agent, json=rotation).status_code == 201
    assert client.post(key_url + "/rotate-1/approve", headers=operator).status_code == 200
    assert start(client, agent, command, body)[1].status_code == 200
    send_remaining(client, agent, url, body)
    assert finish(client, agent, url, body, response.json()["manifest_sha256"]).status_code == 200


def test_expired_partial_chunks_restart_with_original_manifest_and_audited_cleanup(client):
    _, agent, command, body, _ = prepared(client, data=data())
    url, response = start(client, agent, command, body)
    first = base64.b64decode(body["content_base64"])[: transfers.CHUNK_BYTES]
    assert chunk(client, agent, url, body, 0, first).status_code == 200
    conn = db.connect()
    conn.execute("UPDATE response_artifact_transfers SET expires_at='2000-01-01T00:00:00.000Z'")
    conn.commit()
    assert chunk(client, agent, url, body, 0, first).status_code == 409
    _, resumed = start(client, agent, command, body)
    assert resumed.status_code == 200 and resumed.json()["received_bytes"] == 0
    assert resumed.json()["manifest_sha256"] == response.json()["manifest_sha256"]
    assert conn.execute("SELECT COUNT(*) FROM response_artifact_chunks").fetchone()[0] == 0
    assert (
        conn.execute("SELECT total_sessions FROM response_artifact_transfer_usage").fetchone()[0]
        == 1
    )
    audit = conn.execute(
        "SELECT detail FROM response_security_audit WHERE event='artifact_transfer_expired'"
    ).fetchone()
    assert json.loads(audit[0])["partial_chunks"][0]["sha256"] == hashlib.sha256(first).hexdigest()
    assert audit_chain.verify(conn)["complete_history_verified"]


def test_reserved_budget_blocks_one_shot_bypass_and_agent_open_limit(client, monkeypatch):
    private = ec.generate_private_key(ec.SECP256R1())
    _, agent, command, body, signed_url = prepared(client, data=data(100), key=private)
    monkeypatch.setenv("PANOPTICON_ARTIFACT_STORAGE_BYTES", str(body["manifest"]["content_bytes"]))
    _, response = start(client, agent, command, body)
    assert response.status_code == 200
    different = copy.deepcopy(body)
    different["manifest"]["artifact_id"] = "art_" + "a" * 64
    resign(different, private)
    assert client.post(signed_url, headers=agent, json=different).status_code == 507
    assert client.post(signed_url, headers=agent, json=body).status_code == 409
    monkeypatch.delenv("PANOPTICON_ARTIFACT_STORAGE_BYTES")
    for index in range(3):
        other = copy.deepcopy(body)
        other["manifest"]["artifact_id"] = "art_" + hashlib.sha256(str(index).encode()).hexdigest()
        resign(other, private)
        assert start(client, agent, command, other)[1].status_code == 200
    assert start(client, agent, command, different)[1].status_code == 507
    assert (
        db.connect()
        .execute("SELECT open_sessions FROM response_artifact_transfer_usage")
        .fetchone()[0]
        == 4
    )


def test_chunk_bounds_digest_and_ownership_are_enforced(client):
    operator, agent, command, body, _ = prepared(client, data=data())
    url, _ = start(client, agent, command, body)
    raw = base64.b64decode(body["content_base64"])
    assert chunk(client, agent, url, body, 0, raw[: transfers.CHUNK_BYTES + 1]).status_code == 413
    assert (
        chunk(
            client, agent, url, body, 0, raw[: transfers.CHUNK_BYTES], digest="0" * 64
        ).status_code
        == 422
    )
    assert chunk(client, agent, url, body, 1, raw[: transfers.CHUNK_BYTES]).status_code == 422
    assert chunk(client, operator, url, body, 0, raw[: transfers.CHUNK_BYTES]).status_code == 401
    assert (
        db.connect().execute("SELECT received_bytes FROM response_artifact_transfers").fetchone()[0]
        == 0
    )


def test_progress_matches_central_closed_schema(client):
    _, agent, command, body, _ = prepared(client)
    _, response = start(client, agent, command, body)
    root = Path(__file__).resolve().parents[2] / "panopticon-contracts/schema"
    schema = json.loads((root / "artifact-transfer-progress-v1.schema.json").read_text())
    jsonschema.validate(response.json(), schema)
