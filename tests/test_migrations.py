import sqlite3
from pathlib import Path

from manager import migrations


def _connect(path: Path) -> sqlite3.Connection:
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    return conn


def test_migrate_from_empty_db_creates_schema_migrations(tmp_path: Path) -> None:
    conn = _connect(tmp_path / "test.db")
    assert migrations.current_version(conn) == 0

    version = migrations.migrate(conn)

    assert version == len(migrations._MIGRATIONS)
    row = conn.execute("SELECT COUNT(*) AS c FROM schema_migrations").fetchone()
    assert row["c"] == len(migrations._MIGRATIONS)


def test_migrate_is_idempotent(tmp_path: Path) -> None:
    conn = _connect(tmp_path / "test.db")
    migrations.migrate(conn)
    version_again = migrations.migrate(conn)
    assert version_again == len(migrations._MIGRATIONS)
    count = conn.execute("SELECT COUNT(*) AS c FROM schema_migrations").fetchone()["c"]
    assert count == len(migrations._MIGRATIONS)


def test_latest_migration_preserves_alerts_table(tmp_path: Path) -> None:
    conn = _connect(tmp_path / "test.db")
    migrations.migrate(conn)

    assert migrations.current_version(conn) == len(migrations._MIGRATIONS)

    cols = {row["name"] for row in conn.execute("PRAGMA table_info(alerts)")}
    assert cols == {
        "alert_id",
        "rule_id",
        "level",
        "severity",
        "host_id",
        "agent_id",
        "event_id",
        "alert_timestamp",
        "created_at",
        "mitre_tactic",
        "mitre_technique",
        "alert_json",
    }

    indexes = {
        row["name"]
        for row in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='index' AND tbl_name='alerts'"
        )
    }
    assert "ix_alerts_created" in indexes


def test_current_version_refuses_future_schema(tmp_path: Path, monkeypatch) -> None:
    conn = _connect(tmp_path / "test.db")
    migrations.migrate(conn)

    monkeypatch.setattr(migrations, "_MIGRATIONS", [])
    try:
        migrations.migrate(conn)
    except RuntimeError as exc:
        assert "newer than" in str(exc)
    else:
        raise AssertionError("expected RuntimeError for a schema newer than known migrations")


def test_capture_index_upgrade_preserves_existing_bodies_and_backfills_orphan_pages(
    tmp_path: Path, monkeypatch
) -> None:
    import hashlib
    import json

    from tests.test_endpoint_records import capture_record

    path = tmp_path / "capture-upgrade.db"
    conn = _connect(path)
    with monkeypatch.context() as scoped:
        scoped.setattr(migrations, "_MIGRATIONS", migrations._MIGRATIONS[:16])
        assert migrations.migrate(conn) == 16
    begin = capture_record("begin", "upgrade-begin")
    page = capture_record("page", "upgrade-page", begin["record_id"])
    orphan = capture_record("page", "orphan-page", "rec_" + "e" * 64)
    legacy = capture_record("manifest", "legacy-prefix")
    legacy["data"] = {"entries": [], "inventory_complete": False}
    source = []
    for record in (page, begin, orphan, legacy):
        raw = json.dumps(record, indent=2)
        digest = hashlib.sha256(raw.encode()).hexdigest()
        source.append((record["record_id"], raw, digest))
        conn.execute(
            "INSERT INTO endpoint_records(agent_id,host_id,record_id,kind,category,"
            "observed_at,ingested_at,payload_digest,raw_json) VALUES (?,?,?,?,?,?,?,?,?)",
            ("agent-1", "host-1", record["record_id"], "state", record["category"],
             record["observed_at"], record["observed_at"], digest, raw),
        )
    conn.commit()
    assert migrations.migrate(conn) == len(migrations._MIGRATIONS)
    conn.close()
    conn = _connect(path)
    assert migrations.migrate(conn) == len(migrations._MIGRATIONS)
    indexed = conn.execute(
        "SELECT record_id,capture_id,role FROM endpoint_process_capture_records"
    ).fetchall()
    assert len(indexed) == 3
    assert {row["record_id"] for row in indexed} == {
        begin["record_id"], page["record_id"], orphan["record_id"]
    }
    for record_id, raw, digest in source:
        row = conn.execute(
            "SELECT raw_json,payload_digest,detect_state FROM endpoint_records WHERE record_id=?",
            (record_id,),
        ).fetchone()
        assert (row["raw_json"], row["payload_digest"], row["detect_state"]) == (
            raw, digest, "pending"
        )
    conn.close()
