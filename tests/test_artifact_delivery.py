"""Signed resumable reads, per-frame authorization, custody and legacy closure."""

import base64
import hashlib
import json
import sqlite3
from pathlib import Path

import jsonschema
import pytest
from referencing import Registry, Resource

from manager import audit_chain, db
from manager import response_artifacts as store
from tests.artifact_access_support import administrator
from tests.test_response_artifacts import artifact
from tests.test_signed_artifacts import prepared


def retained(client, *, data=b'{"snapshot":[]}'):
    reader, agent, command, body, url = prepared(client, data=data)
    assert client.post(url, headers=agent, json=body).status_code == 200
    path = "/api/v1/response-artifacts/" + body["manifest"]["artifact_id"]
    context = client.get(path + "/context", headers=reader)
    assert context.status_code == 200, context.text
    return reader, path, context.json(), command


def frame(client, reader, path, context, offset):
    return client.get(
        path + "/chunks",
        headers=reader,
        params={"offset": offset, "manifest_sha256": context["manifest_sha256"]},
    )


def acknowledgement(context, **changes):
    return {
        "schema_version": "1",
        "request_id": "verified-view-1",
        "manifest_sha256": context["manifest_sha256"],
        "operation": "view",
        **changes,
    }


def test_resumable_reads_return_exact_bound_frames_and_match_central_schema(client):
    data = json.dumps({"snapshot": "x" * 140000}).encode()
    reader, path, context, command = retained(client, data=data)
    assert context["trusted"]["command_id"] == command["command_id"]
    assert context["trusted"]["alert_id"] == "alert-1"
    root = Path(__file__).resolve().parents[2] / "panopticon-contracts/schema"
    manifest_schema = json.loads((root / "response-artifact-manifest-v2.schema.json").read_text())
    registry = Registry().with_resource(
        manifest_schema["$id"], Resource.from_contents(manifest_schema)
    )
    jsonschema.Draft202012Validator(
        json.loads((root / "artifact-download-context-v1.schema.json").read_text()),
        registry=registry,
    ).validate(context)
    chunk_schema = json.loads((root / "artifact-download-chunk-v1.schema.json").read_text())
    downloaded = bytearray()
    first = frame(client, reader, path, context, 0)
    assert first.status_code == 200 and first.headers["cache-control"] == "no-store"
    assert frame(client, reader, path, context, 0).json() == first.json()
    while len(downloaded) < len(data):
        reply = frame(client, reader, path, context, len(downloaded))
        assert reply.status_code == 200
        value = reply.json()
        jsonschema.validate(value, chunk_schema)
        part = base64.b64decode(value["content_base64"])
        assert len(part) == value["content_bytes"] <= 65536
        assert hashlib.sha256(part).hexdigest() == value["sha256"]
        downloaded.extend(part)
        assert value["next_offset"] == len(downloaded)
        assert value["complete"] == (len(downloaded) == len(data))
    assert bytes(downloaded) == data
    assert db.connect().execute("SELECT COUNT(*) FROM response_artifacts").fetchone()[0] == 1


def test_chunk_binding_and_offsets_cannot_select_arbitrary_content(client):
    reader, path, context, _ = retained(client)
    assert frame(client, reader, path, context, 1).status_code == 422
    assert (
        frame(client, reader, path, context, context["manifest"]["content_bytes"]).status_code
        == 422
    )
    assert (
        frame(client, reader, path, {**context, "manifest_sha256": "0" * 64}, 0).status_code == 409
    )
    assert (
        client.get(
            path + "/chunks?offset=true&manifest_sha256=" + context["manifest_sha256"],
            headers=reader,
        ).status_code
        == 422
    )


def test_revocation_between_frames_and_before_acknowledgement_fails_closed(client):
    reader, path, context, _ = retained(client, data=json.dumps({"x": "y" * 90000}).encode())
    assert frame(client, reader, path, context, 0).status_code == 200
    admin = administrator(client)
    grant_id = db.connect().execute("SELECT grant_id FROM artifact_access_grants").fetchone()[0]
    assert (
        client.post(
            "/api/v1/artifact-access/grants/" + grant_id + "/revoke",
            headers=admin,
            json={
                "schema_version": "1",
                "policy_version": 1,
                "request_id": "end-assignment",
                "reason": "Assignment ended",
            },
        ).status_code
        == 200
    )
    assert frame(client, reader, path, context, 65536).status_code == 403
    assert client.get(path + "/context", headers=reader).status_code == 403
    assert (
        client.post(path + "/view", headers=reader, json=acknowledgement(context)).status_code
        == 403
    )
    assert db.connect().execute("SELECT COUNT(*) FROM artifact_view_receipts").fetchone()[0] == 0


def test_compromised_key_flags_context_but_blocks_remaining_bytes_and_views(client):
    reader, path, context, _ = retained(client, data=json.dumps({"x": "y" * 90000}).encode())
    assert frame(client, reader, path, context, 0).status_code == 200
    agent_id = context["trusted"]["agent_id"]
    key_id = context["trusted"]["key_id"]
    reply = client.post(
        f"/api/v1/agents/{agent_id}/artifact-keys/{key_id}/revoke",
        headers=reader,
        json={"request_id": "compromise-key", "reason": "Signing key compromise confirmed"},
    )
    assert reply.status_code == 200, reply.text
    fresh = client.get(path + "/context", headers=reader)
    assert fresh.status_code == 200
    assert fresh.json()["trusted"]["trust_status"] == "compromised_key"
    assert fresh.json()["trusted"]["compromise_reason"]
    assert frame(client, reader, path, context, 65536).status_code == 403
    assert (
        client.post(path + "/view", headers=reader, json=acknowledgement(context)).status_code
        == 403
    )
    assert db.connect().execute("SELECT COUNT(*) FROM response_artifacts").fetchone()[0] == 1


def test_view_acknowledgement_is_idempotent_audited_and_queryable(client):
    reader, path, context, command = retained(client)
    body = acknowledgement(context)
    first = client.post(path + "/view", headers=reader, json=body)
    assert first.status_code == 200 and first.json()["recorded"]
    sequence = audit_chain.verify(db.connect())["sequence"]
    assert client.post(path + "/view", headers=reader, json=body).json() == first.json()
    assert audit_chain.verify(db.connect())["sequence"] == sequence
    assert (
        client.post(
            path + "/view", headers=reader, json={**body, "operation": "download"}
        ).status_code
        == 409
    )
    assert frame(client, reader, path, context, 0).status_code == 200
    rid = context["trusted"]["response_id"]
    result = client.get(
        "/api/v1/response-audit",
        headers=reader,
        params={
            "request_id": rid,
            "actor": "analyst:operator",
            "asset_id": "host-1",
            "since": "2026-01-01T00:00:00Z",
        },
    )
    assert result.status_code == 200
    events = {row["payload"]["event"] for row in result.json()["events"]}
    assert {"artifact_context_viewed", "artifact_download_chunk", "artifact_viewed"} <= events
    assert db.connect().execute("SELECT COUNT(*) FROM artifact_view_receipts").fetchone()[0] == 1


def test_failed_mandatory_view_audit_rolls_back_receipt(client):
    reader, path, context, _ = retained(client)
    conn = db.connect()
    conn.execute("""CREATE TRIGGER refuse_view_audit BEFORE INSERT ON response_artifact_custody
        WHEN NEW.event='artifact_viewed' BEGIN SELECT RAISE(ABORT,'audit unavailable'); END""")
    conn.commit()
    with pytest.raises(sqlite3.IntegrityError, match="audit unavailable"):
        client.post(path + "/view", headers=reader, json=acknowledgement(context))
    assert conn.execute("SELECT COUNT(*) FROM artifact_view_receipts").fetchone()[0] == 0
    assert audit_chain.verify(conn)["complete_history_verified"]


@pytest.mark.parametrize("route", ["context", "chunks"])
def test_corrupt_retained_bytes_fail_closed_before_context_or_frame_release(client, route):
    reader, path, context, _ = retained(client)
    conn = db.connect()
    conn.execute("DROP TRIGGER response_artifact_immutable")
    conn.execute("UPDATE response_artifacts SET content=x'00'")
    conn.commit()
    result = (
        client.get(path + "/context", headers=reader)
        if route == "context"
        else frame(client, reader, path, context, 0)
    )
    assert result.status_code == 503
    assert "content_base64" not in result.json()
    event = conn.execute(
        "SELECT event FROM response_artifact_custody ORDER BY sequence DESC LIMIT 1"
    ).fetchone()[0]
    assert event == "integrity_check_failed"
    assert audit_chain.verify(conn)["complete_history_verified"]


def test_old_view_receipt_cannot_bypass_later_scope_revocation(client):
    reader, path, context, _ = retained(client)
    body = acknowledgement(context)
    assert client.post(path + "/view", headers=reader, json=body).status_code == 200
    admin = administrator(client)
    grant_id = db.connect().execute("SELECT grant_id FROM artifact_access_grants").fetchone()[0]
    response = client.post(
        "/api/v1/artifact-access/grants/" + grant_id + "/revoke",
        headers=admin,
        json={
            "schema_version": "1",
            "policy_version": 1,
            "request_id": "revoke-after-view",
            "reason": "Assignment ended",
        },
    )
    assert response.status_code == 200
    assert client.post(path + "/view", headers=reader, json=body).status_code == 403
    assert db.connect().execute("SELECT COUNT(*) FROM artifact_view_receipts").fetchone()[0] == 1


def test_unsigned_upload_and_historical_raw_download_paths_are_closed(client):
    reader, agent, command, _, _ = prepared(client)
    legacy = artifact(command)
    upload = f"/api/v1/agents/agent-1/commands/{command['command_id']}/artifacts"
    assert client.post(upload, headers=agent, json=legacy).status_code == 410
    assert db.connect().execute("SELECT COUNT(*) FROM response_artifacts").fetchone()[0] == 0
    # Historical evidence is imported through the old store only in this isolated
    # migration fixture; there is no HTTP path for new unsigned evidence.
    conn = db.connect()
    conn.execute("BEGIN IMMEDIATE")
    store.retain(
        conn,
        "agent-1",
        command["command_id"],
        store.ArtifactUpload.model_validate(legacy),
        base64.b64decode(legacy["content_base64"]),
    )
    conn.commit()
    path = "/api/v1/response-artifacts/" + legacy["artifact_id"]
    assert client.get(path + "/content", headers=reader).status_code == 410
    assert client.get(path + "/context", headers=reader).status_code == 410
    assert client.get(path + "/custody", headers=reader).status_code == 200
    assert conn.execute("SELECT COUNT(*) FROM response_artifacts").fetchone()[0] == 1
    assert audit_chain.verify(conn)["complete_history_verified"]
