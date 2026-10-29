"""Audit provenance, atomicity, corruption refusal and externally pinned anchors."""

import base64
import copy
import json
import sqlite3
from concurrent.futures import ThreadPoolExecutor

import pytest

from manager import audit_chain, audit_chain_cli, command_signing, db, migrations
from manager.routers.commands import _audit
from tests.test_response_artifacts import artifact, prepared, upload
from tests.test_response_governance import identity


def connection(path):
    conn = sqlite3.connect(path, timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys=ON")
    audit_chain.register(conn)
    return conn


def seed_command(conn):
    conn.execute("""INSERT INTO commands
        (command_id,agent_id,command_json,created_at,expires_at,lifecycle_state)
        VALUES ('cmd-1','agent-1','{"host_id":"host-1"}','2026-10-29T00:00:00Z',
                '2026-10-29T00:15:00Z','AUTHORIZED')""")
    conn.commit()


def test_legacy_snapshot_passes_integrity_but_is_refused_as_chained_provenance(
    tmp_path, monkeypatch
):
    conn = connection(tmp_path / "legacy.db")
    with monkeypatch.context() as scoped:
        scoped.setattr(migrations, "_MIGRATIONS", migrations._MIGRATIONS[:26])
        assert migrations.migrate(conn) == 26
    seed_command(conn)
    _audit(conn, "cmd-1", "created", "legacy:operator")
    conn.commit()
    assert migrations.migrate(conn) == len(migrations._MIGRATIONS)
    row = conn.execute("SELECT * FROM response_audit_ledger").fetchone()
    assert row["legacy_import"] == 1
    result = audit_chain.verify(conn)
    assert result["legacy_import_count"] == 1
    assert result["chain_verified_count"] == 0
    assert result["complete_history_verified"] is False
    with pytest.raises(ValueError, match="legacy history"):
        audit_chain.verify(conn, require_chained_history=True)
    _audit(conn, "cmd-1", "dispatched", "agent:agent-1")
    conn.commit()
    result = audit_chain.verify(conn)
    assert result["chain_verified_count"] == 1
    assert result["legacy_import_count"] == 1
    assert migrations.migrate(conn) == len(migrations._MIGRATIONS)  # No second import or replay.
    assert conn.execute("SELECT COUNT(*) FROM response_audit_ledger").fetchone()[0] == 2


def test_all_response_writers_chain_and_are_queryable_with_retry_idempotency(client):
    analyst, agent, rid, command = prepared(client)
    value = artifact(command)
    assert upload(client, agent, command, value).status_code == 200
    count = db.connect().execute("SELECT COUNT(*) FROM response_audit_ledger").fetchone()[0]
    assert upload(client, agent, command, value).status_code == 200
    assert db.connect().execute("SELECT COUNT(*) FROM response_audit_ledger").fetchone()[0] == count
    check = client.get("/api/v1/response-audit/verify", headers=analyst)
    assert check.status_code == 200, check.text
    assert check.json()["legacy_import_count"] == 0
    assert check.json()["complete_history_verified"] is True
    events = client.get(
        "/api/v1/response-audit", headers=analyst, params={"request_id": rid, "asset_id": "host-1"}
    ).json()["events"]
    assert {e["source"] for e in events} == set(audit_chain.SOURCES) | {"response_security_audit"}
    created = next(e for e in events if e["source"] == "command_audit" and e["event"] == "created")
    assert created["request_id"] == rid  # Creation precedes response command_id UPDATE.
    filtered = client.get(
        "/api/v1/response-audit",
        headers=analyst,
        params={
            "actor": "agent:agent-1",
            "asset_id": "host-1",
            "since": "2020-01-01T00:00:00Z",
            "until": "2100-01-01T00:00:00Z",
            "limit": 1,
        },
    ).json()
    assert len(filtered["events"]) == 1
    assert filtered["events"][0]["actor"] == "agent:agent-1"
    assert filtered["events"][0]["provenance"] == "chained_event"
    assert client.get("/api/v1/response-audit", headers=agent).status_code == 401
    assert (
        client.get("/api/v1/response-audit", headers=analyst, params={"limit": 201}).status_code
        == 422
    )
    assert (
        client.get(
            "/api/v1/response-audit", headers=analyst, params={"since": "2026-10-01T00:00:00"}
        ).status_code
        == 422
    )


def test_broken_post_migration_link_fails_closed_in_verifier_and_api(client):
    analyst, _, _, _ = prepared(client)
    conn = db.connect()
    assert audit_chain.verify(conn)["sequence"] > 1
    # Simulate privileged storage corruption. Ordinary UPDATE is prohibited.
    conn.execute("DROP TRIGGER chain_no_update_response_audit_ledger")
    conn.execute("UPDATE response_audit_ledger SET previous_hash=? WHERE sequence=2", ("a" * 64,))
    conn.commit()
    with pytest.raises(ValueError, match="chain disagreement"):
        audit_chain.verify(conn)
    assert client.get("/api/v1/response-audit/verify", headers=analyst).status_code == 503


def test_source_edits_and_missing_events_are_detected_even_if_triggers_removed(tmp_path):
    conn = connection(tmp_path / "source.db")
    migrations.migrate(conn)
    seed_command(conn)
    _audit(conn, "cmd-1", "created", "system:test")
    conn.commit()
    with pytest.raises(sqlite3.IntegrityError, match="immutable"):
        conn.execute("UPDATE command_audit SET actor='attacker'")
    conn.rollback()
    conn.execute("DROP TRIGGER chain_no_update_command_audit")
    conn.execute("UPDATE command_audit SET actor='attacker'")
    conn.commit()
    with pytest.raises(ValueError, match="source disagreement"):
        audit_chain.verify(conn)


def test_audit_append_is_atomic_fail_closed_and_restart_safe(tmp_path):
    path = tmp_path / "atomic.db"
    conn = connection(path)
    migrations.migrate(conn)
    seed_command(conn)
    conn.execute("BEGIN IMMEDIATE")
    _audit(conn, "cmd-1", "created", "system:test")
    conn.rollback()
    assert audit_chain.verify(conn)["sequence"] == 0
    assert conn.execute("SELECT COUNT(*) FROM command_audit").fetchone()[0] == 0
    _audit(conn, "cmd-1", "created", "system:test")
    conn.commit()
    conn.close()
    unmanaged = sqlite3.connect(path)
    with pytest.raises(sqlite3.OperationalError, match="panopticon_audit_hash"):
        _audit(unmanaged, "cmd-1", "dispatched", "agent:agent-1")
    unmanaged.rollback()
    unmanaged.close()
    reopened = connection(path)
    assert audit_chain.verify(reopened)["sequence"] == 1
    _audit(reopened, "cmd-1", "dispatched", "agent:agent-1")
    reopened.commit()
    assert audit_chain.verify(reopened)["sequence"] == 2


def test_concurrent_writers_have_one_unbroken_chain(tmp_path):
    path = tmp_path / "concurrent.db"
    conn = connection(path)
    migrations.migrate(conn)
    seed_command(conn)

    def write(index):
        current = connection(path)
        try:
            current.execute("BEGIN IMMEDIATE")
            _audit(current, "cmd-1", "observed", f"writer:{index}")
            current.commit()
        finally:
            current.close()

    with ThreadPoolExecutor(max_workers=4) as pool:
        list(pool.map(write, range(16)))
    assert audit_chain.verify(conn)["chain_verified_count"] == 16


def test_signed_checkpoint_rejects_tampering_wrong_key_and_history_truncation(
    tmp_path, monkeypatch
):
    path = tmp_path / "anchor.db"
    conn = connection(path)
    migrations.migrate(conn)
    seed_command(conn)
    _audit(conn, "cmd-1", "created", "system:test")
    conn.commit()
    keyfile = tmp_path / "audit.pem"
    key_line = command_signing.generate(keyfile)
    point = base64.b64decode(key_line.split()[0])
    monkeypatch.setenv("PANOPTICON_AUDIT_SIGNING_KEY", str(keyfile))
    conn.execute("BEGIN IMMEDIATE")
    anchor = audit_chain.checkpoint(conn, request_key="test:one", actor="analyst:alice")
    conn.commit()
    assert audit_chain.verify_checkpoint(conn, anchor, point)["sequence"] == 1
    _audit(conn, "cmd-1", "dispatched", "agent:agent-1")
    conn.commit()
    assert audit_chain.verify_checkpoint(conn, anchor, point)["sequence"] == 2
    conn.execute("BEGIN IMMEDIATE")
    assert audit_chain.checkpoint(conn, request_key="test:one", actor="analyst:alice") == anchor
    conn.commit()
    tampered = copy.deepcopy(anchor)
    tampered["document"]["head_hash"] = "f" * 64
    with pytest.raises(ValueError, match="signature"):
        audit_chain.verify_checkpoint(conn, tampered, point)
    wrong = tmp_path / "wrong.pem"
    wrong_point = base64.b64decode(command_signing.generate(wrong).split()[0])
    with pytest.raises(ValueError, match="identity"):
        audit_chain.verify_checkpoint(conn, anchor, wrong_point)
    conn.execute("DROP TRIGGER chain_no_delete_response_audit_ledger")
    conn.execute("DROP TRIGGER chain_no_delete_command_audit")
    conn.execute("DELETE FROM response_audit_ledger")
    conn.execute("DELETE FROM command_audit")
    conn.commit()
    # Locally consistent empty history still disagrees with the external anchor.
    assert audit_chain.verify(conn)["sequence"] == 0
    with pytest.raises(ValueError, match="retained history"):
        audit_chain.verify_checkpoint(conn, anchor, point)


def test_checkpoint_endpoint_requires_signing_and_is_idempotent(client, tmp_path, monkeypatch):
    analyst, agent, _, _ = prepared(client)
    url = "/api/v1/response-audit/checkpoints"
    body = {"request_id": "checkpoint-1"}
    monkeypatch.delenv("PANOPTICON_AUDIT_SIGNING_KEY", raising=False)
    assert client.post(url, headers=analyst, json=body).status_code == 503
    assert client.post(url, headers=agent, json=body).status_code == 401
    keyfile = tmp_path / "checkpoint.pem"
    command_signing.generate(keyfile)
    monkeypatch.setenv("PANOPTICON_AUDIT_SIGNING_KEY", str(keyfile))
    first = client.post(url, headers=analyst, json=body)
    assert first.status_code == 201, first.text
    assert client.post(url, headers=analyst, json=body).json() == first.json()
    assert (
        db.connect().execute("SELECT COUNT(*) FROM response_audit_checkpoints").fetchone()[0] == 1
    )
    assert first.json()["document"]["created_by"] == "analyst:alice"
    assert (
        json.loads(
            db.connect()
            .execute("SELECT document_json FROM response_audit_checkpoints")
            .fetchone()[0]
        )
        == first.json()["document"]
    )


def test_audit_routes_refuse_viewer_and_responder(client):
    prepared(client)
    for role in ("viewer", "responder"):
        credentials = identity(client, role, role)
        for path in ("/api/v1/response-audit", "/api/v1/response-audit/verify"):
            assert client.get(path, headers=credentials).status_code == 403
        assert (
            client.post(
                "/api/v1/response-audit/checkpoints",
                headers=credentials,
                json={"request_id": "forbidden"},
            ).status_code
            == 403
        )


def test_audit_failure_does_not_leave_an_unaudited_staged_response(client, monkeypatch):
    from manager.detection import response

    prepared(client)
    conn = db.connect()
    count = conn.execute("SELECT COUNT(*) FROM response_actions").fetchone()[0]
    chain_count = audit_chain.verify(conn)["sequence"]

    def stage(current, alert):
        response._insert_response_action(
            current,
            alert_id="alert-1",
            action="COLLECT_FILE",
            tier="ANALYST_APPROVAL",
            state="PENDING",
            target={"path": "/approved/example"},
            reason="test",
        )

    def broken_hash(*args):
        raise ValueError("simulated audit storage failure")

    monkeypatch.setattr(response, "_on_alert_created", stage)
    conn.create_function("panopticon_audit_hash", len(audit_chain.FIELDS), broken_hash)
    conn.execute("BEGIN IMMEDIATE")
    response.on_alert_created(conn, {})
    conn.commit()
    audit_chain.register(conn)
    assert conn.execute("SELECT COUNT(*) FROM response_actions").fetchone()[0] == count
    assert audit_chain.verify(conn)["sequence"] == chain_count
    assert conn.execute("SELECT 1 FROM alerts WHERE alert_id='alert-1'").fetchone()


def test_read_only_checkpoint_cli_rejects_tampered_anchor(tmp_path, monkeypatch, capsys):
    path = tmp_path / "offline.db"
    conn = connection(path)
    migrations.migrate(conn)
    seed_command(conn)
    _audit(conn, "cmd-1", "created", "system:test")
    conn.commit()
    keyfile = tmp_path / "private.pem"
    public = tmp_path / "public.keys"
    public.write_text(command_signing.generate(keyfile), encoding="utf-8")
    monkeypatch.setenv("PANOPTICON_AUDIT_SIGNING_KEY", str(keyfile))
    conn.execute("BEGIN IMMEDIATE")
    anchor = audit_chain.checkpoint(conn, request_key="offline:one", actor="analyst:alice")
    conn.commit()
    conn.close()
    original_bytes = path.read_bytes()
    checkpoint = tmp_path / "anchor.json"
    checkpoint.write_text(json.dumps(anchor), encoding="utf-8")
    args = ["--database", str(path), "--checkpoint", str(checkpoint), "--trusted-key", str(public)]
    assert audit_chain_cli.main(args) == 0
    assert json.loads(capsys.readouterr().out)["verified"] is True
    assert path.read_bytes() == original_bytes
    anchor["document"]["legacy_import_count"] = 999
    checkpoint.write_text(json.dumps(anchor), encoding="utf-8")
    assert audit_chain_cli.main(args) == 1
    assert "verification failed" in capsys.readouterr().err
    assert path.read_bytes() == original_bytes
