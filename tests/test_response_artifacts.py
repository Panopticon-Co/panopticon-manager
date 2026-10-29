"""Exact-byte collection retention, binding, quotas and custody regression tests."""

import base64
import hashlib
import json
import sqlite3
from pathlib import Path

import jsonschema
import pytest

from manager import db
from manager.response_artifacts import canonical
from tests.artifact_access_support import grant_reader
from tests.test_analyst_operations import create, setup


def prepared(client, *, dispatch=True):
    analyst, agent = setup(client)
    rid = create(client, analyst).json()["response_id"]
    assert (
        client.post(f"/api/v1/response-actions/{rid}/authorize", headers=analyst).status_code == 200
    )
    conn = db.connect()
    command = json.loads(conn.execute("SELECT command_json FROM commands").fetchone()[0])
    if dispatch:
        assert client.get("/api/v1/agents/agent-1/commands", headers=agent).status_code == 200
    grant_reader(client, analyst)
    return analyst, agent, rid, command


def artifact(command, data=b'{"connections": []}', **changes):
    digest = hashlib.sha256(data).hexdigest()
    value = {
        "schema_version": "1",
        "artifact_id": "art_"
        + hashlib.sha256((command["command_id"] + digest).encode()).hexdigest(),
        "command_id": command["command_id"],
        "correlation_id": command["correlation_id"],
        "host_id": "host-1",
        "kind": "network_snapshot",
        "media_type": "application/json",
        "content_bytes": len(data),
        "sha256": digest,
        "content_base64": base64.b64encode(data).decode(),
    }
    value.update(changes)
    return value


def upload(client, agent, command, value):
    return client.post(
        f"/api/v1/agents/agent-1/commands/{command['command_id']}/artifacts",
        headers=agent,
        json=value,
    )


def test_exact_bytes_retry_identity_case_manifest_and_download_custody(client):
    analyst, agent, rid, command = prepared(client)
    data = b'{ "connections": [], "note": "\\u00e9" }\n'
    value = artifact(command, data)
    first = upload(client, agent, command, value)
    assert first.status_code == 200, first.text
    assert first.json() == {
        "artifact_id": value["artifact_id"],
        "sha256": value["sha256"],
        "retained": True,
    }
    assert upload(client, agent, command, value).json() == first.json()
    conn = db.connect()
    assert conn.execute("SELECT COUNT(*) FROM response_artifacts").fetchone()[0] == 1
    assert conn.execute("SELECT COUNT(*) FROM response_artifact_custody").fetchone()[0] == 1
    rows = client.get("/api/v1/response-actions", headers=analyst).json()["response_actions"]
    case = next(row for row in rows if row["response_id"] == rid)
    assert case["artifacts"][0]["sha256"] == hashlib.sha256(data).hexdigest()
    assert case["command_lifecycle_state"] == "DISPATCHED"  # no inferred success
    path = f"/api/v1/response-artifacts/{value['artifact_id']}/content"
    assert client.get(path, headers=agent).status_code == 401
    downloaded = client.get(path, headers=analyst)
    assert downloaded.status_code == 200 and downloaded.content == data
    assert downloaded.headers["x-content-type-options"] == "nosniff"
    assert downloaded.headers["content-disposition"].startswith("attachment;")
    assert downloaded.headers["cache-control"] == "no-store"
    events = client.get(path.replace("/content", "/custody"), headers=analyst).json()["events"]
    assert [event["event"] for event in events] == ["received", "download_requested"]
    previous = "0" * 64
    for event in events:
        digest = event.pop("event_hash")
        assert event["previous_hash"] == previous
        assert hashlib.sha256(canonical(event).encode()).hexdigest() == digest
        previous = digest
    exported = client.get(f"/api/v1/response-actions/{rid}/export", headers=analyst).json()
    assert exported["response_action"]["artifacts"][0]["custody_count"] == 2


@pytest.mark.parametrize(
    "change,status",
    [
        ({"host_id": "other-host"}, 403),
        ({"correlation_id": "other"}, 409),
        ({"command_id": "other"}, 409),
        ({"kind": "file_metadata"}, 422),
        ({"sha256": "0" * 64}, 422),
        ({"content_bytes": 999}, 422),
        ({"content_base64": "@@@="}, 422),
        ({"content_bytes": True}, 422),
        ({"extra": "x"}, 422),
        ({"artifact_id": "../escape"}, 422),
        ({"media_type": "text/html"}, 422),
    ],
)
def test_binding_and_closed_envelope_fail_without_retention(client, change, status):
    _, agent, _, command = prepared(client)
    result = upload(client, agent, command, artifact(command, **change))
    assert result.status_code == status, result.text
    assert db.connect().execute("SELECT COUNT(*) FROM response_artifacts").fetchone()[0] == 0


@pytest.mark.parametrize(
    "data",
    [
        b"[] NaN",
        b'{"x":NaN}',
        b'{"x":1e999}',
        b'{"x":1,"x":2}',
        b'"not an object"',
        b"\xff",
        b"[" * 40 + b"0" + b"]" * 40,
    ],
)
def test_invalid_or_overdeep_json_is_never_retained(client, data):
    _, agent, _, command = prepared(client)
    assert upload(client, agent, command, artifact(command, data)).status_code == 422


def test_undispatched_or_wrong_identity_cannot_upload(client):
    analyst, agent, _, command = prepared(client, dispatch=False)
    assert upload(client, analyst, command, artifact(command)).status_code == 401
    assert upload(client, agent, command, artifact(command)).status_code == 409
    client.get("/api/v1/agents/agent-1/commands", headers=agent)
    conn = db.connect()
    conn.execute("UPDATE enrolled_agents SET host_id='rebound'")
    conn.commit()
    assert upload(client, agent, command, artifact(command)).status_code == 403


def test_changed_retry_preserves_first_original_and_custody(client):
    _, agent, _, command = prepared(client)
    first = artifact(command)
    assert upload(client, agent, command, first).status_code == 200
    changed = artifact(command, b'{"connections": ["different"]}', artifact_id=first["artifact_id"])
    assert upload(client, agent, command, changed).status_code == 409
    row = db.connect().execute("SELECT content FROM response_artifacts").fetchone()
    assert bytes(row[0]) == base64.b64decode(first["content_base64"])
    assert db.connect().execute("SELECT COUNT(*) FROM response_artifact_custody").fetchone()[0] == 1


def test_quotas_refuse_new_bytes_without_evicting_evidence(client, monkeypatch):
    _, agent, _, command = prepared(client)
    monkeypatch.setenv("PANOPTICON_ARTIFACT_STORAGE_BYTES", "32")
    first = artifact(command)
    assert upload(client, agent, command, first).status_code == 200
    assert (
        upload(
            client, agent, command, artifact(command, b'{"connections":[1,2,3,4,5,6]}')
        ).status_code
        == 507
    )
    assert upload(client, agent, command, first).status_code == 200  # retry does not consume quota
    assert db.connect().execute("SELECT COUNT(*) FROM response_artifacts").fetchone()[0] == 1


def test_per_command_count_is_bounded_and_late_evidence_does_not_change_state(client):
    _, agent, _, command = prepared(client)
    conn = db.connect()
    conn.execute("UPDATE commands SET lifecycle_state='EXPIRED'")
    conn.commit()
    for i in range(8):
        assert (
            upload(
                client, agent, command, artifact(command, json.dumps({"index": i}).encode())
            ).status_code
            == 200
        )
    assert upload(client, agent, command, artifact(command, b'{"index":9}')).status_code == 507
    assert conn.execute("SELECT lifecycle_state FROM commands").fetchone()[0] == "EXPIRED"


def test_body_and_concurrent_admission_are_bounded(client):
    from manager.routers.response_artifacts import _upload_slots

    _, agent, _, command = prepared(client)
    path = f"/api/v1/agents/agent-1/commands/{command['command_id']}/artifacts"
    assert (
        client.post(
            path,
            headers={**agent, "Content-Type": "application/json"},
            content=b"x" * (1500 * 1024 + 1),
        ).status_code
        == 413
    )
    for _ in range(4):
        assert _upload_slots.acquire(blocking=False)
    try:
        assert upload(client, agent, command, artifact(command)).status_code == 429
    finally:
        for _ in range(4):
            _upload_slots.release()
    assert upload(client, agent, command, artifact(command)).status_code == 200


def test_originals_and_custody_are_append_only(client):
    analyst, agent, _, command = prepared(client)
    value = artifact(command)
    upload(client, agent, command, value)
    conn = db.connect()
    for sql in (
        "UPDATE response_artifacts SET content=x'00'",
        "UPDATE response_artifact_custody SET actor='changed'",
        "DELETE FROM response_artifact_custody",
    ):
        with pytest.raises(sqlite3.IntegrityError):
            conn.execute(sql)
        conn.rollback()
    path = f"/api/v1/response-artifacts/{value['artifact_id']}/custody"
    first = client.get(path + "?limit=1", headers=analyst).json()
    assert first["next_after"] == 1 and len(first["events"]) == 1
    assert client.get(path + "?after=1", headers=analyst).json()["events"] == []
    assert (
        client.get(path + "?after=99999999999999999999999999", headers=analyst).status_code == 422
    )


def test_corrupt_storage_is_not_served_and_records_integrity_failure(client):
    analyst, agent, _, command = prepared(client)
    value = artifact(command)
    upload(client, agent, command, value)
    conn = db.connect()
    # Deliberate corruption in this isolated fixture; production updates are prohibited.
    conn.execute("DROP TRIGGER response_artifact_immutable")
    conn.execute("UPDATE response_artifacts SET content=x'00'")
    conn.commit()
    result = client.get(
        f"/api/v1/response-artifacts/{value['artifact_id']}/content", headers=analyst
    )
    assert result.status_code == 503
    events = conn.execute(
        "SELECT event FROM response_artifact_custody ORDER BY sequence"
    ).fetchall()
    assert [row[0] for row in events] == ["received", "integrity_check_failed"]


def test_artifact_matches_central_contract():
    root = Path(__file__).resolve().parents[2] / "panopticon-contracts"
    schema = json.loads((root / "schema/response-artifact-v1.schema.json").read_text())
    value = artifact({"command_id": "command-1", "correlation_id": "correlation-1"})
    jsonschema.validate(value, schema)
