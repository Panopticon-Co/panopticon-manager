import sqlite3
from pathlib import Path

import pytest

from manager import migrations


def _lab_v13_database(tmp_path, monkeypatch):
    conn = _connect(tmp_path / "lab-v13.db")
    with monkeypatch.context() as scoped:
        scoped.setattr(migrations, "_MIGRATIONS", migrations._MIGRATIONS[:11])
        migrations.migrate(conn)
    conn.execute("INSERT INTO schema_migrations VALUES (12,'legacy'),(13,'legacy')")
    conn.execute("""CREATE TABLE endpoint_records (
        record_id TEXT PRIMARY KEY, agent_id TEXT NOT NULL, host_id TEXT NOT NULL,
        kind TEXT NOT NULL, category TEXT NOT NULL, observed_at TEXT NOT NULL,
        received_at TEXT NOT NULL, schema_version TEXT NOT NULL,
        raw_sha256 TEXT NOT NULL, raw_json TEXT NOT NULL
    )""")
    conn.execute("CREATE INDEX ix_endpoint_records_host ON endpoint_records(host_id)")
    conn.execute("INSERT INTO endpoint_records VALUES "
                 "('rec-old','agent-old','host-old','health','endpoint_health',"
                 "'t0','t1','1.0','digest-old','{\"retained\":true}')")
    conn.execute("INSERT INTO enrolled_agents "
                 "(agent_id,host_id,token_digest,enrolled_at) VALUES "
                 "('agent-old','host-old','token-digest','t0')")
    conn.commit()
    return conn


def test_deployed_lab_v13_upgrades_without_copying_or_losing_history(tmp_path, monkeypatch):
    conn = _lab_v13_database(tmp_path, monkeypatch)
    original = tuple(conn.execute("SELECT * FROM endpoint_records").fetchone())
    original_root = conn.execute(
        "SELECT rootpage FROM sqlite_master WHERE name='endpoint_records'"
    ).fetchone()[0]
    assert migrations.migrate(conn) == 23
    assert tuple(conn.execute("SELECT * FROM endpoint_records_legacy_v13").fetchone()) == original
    assert conn.execute(
        "SELECT rootpage FROM sqlite_master WHERE name='endpoint_records_legacy_v13'"
    ).fetchone()[0] == original_root
    assert conn.execute("SELECT COUNT(*) FROM endpoint_records").fetchone()[0] == 0
    assert conn.execute("SELECT token_digest FROM enrolled_agents").fetchone()[0] == "token-digest"
    assert conn.execute("SELECT COUNT(*) FROM incidents").fetchone()[0] == 0
    assert migrations.migrate(conn) == 23


def test_unknown_lab_layout_refuses_upgrade_atomically(tmp_path, monkeypatch):
    conn = _lab_v13_database(tmp_path, monkeypatch)
    conn.execute("ALTER TABLE endpoint_records ADD COLUMN unexpected TEXT")
    conn.commit()
    with pytest.raises(RuntimeError, match="unrecognized lab v13 layout"):
        migrations.migrate(conn)
    assert migrations.current_version(conn) == 13
    assert conn.execute("SELECT COUNT(*) FROM endpoint_records").fetchone()[0] == 1
    assert conn.execute("SELECT name FROM sqlite_master WHERE name='incidents'").fetchone() is None


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
        # Migration 12 (capstone incidents).
        "detection_source",
        "incident_id",
    }

    indexes = {
        row["name"]
        for row in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='index' AND tbl_name='alerts'"
        )
    }
    assert "ix_alerts_created" in indexes
    assert "ix_alerts_incident" in indexes


def test_migration_12_creates_incident_tables(tmp_path: Path) -> None:
    conn = _connect(tmp_path / "test.db")
    migrations.migrate(conn)
    tables = {
        row["name"] for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")
    }
    assert {"incidents", "incident_alerts", "incident_audit"} <= tables
    incident_cols = {row["name"] for row in conn.execute("PRAGMA table_info(incidents)")}
    assert {
        "incident_id", "host_id", "agent_id", "status", "severity", "level", "score",
        "confidence", "tactics_json", "stage_count", "root_process", "root_pid", "revision",
        "latest_alert_id", "first_seen", "last_seen", "incident_json", "created_at",
        "updated_at",
    } == incident_cols
    pk = [row["name"] for row in conn.execute("PRAGMA table_info(incident_alerts)") if row["pk"]]
    assert sorted(pk) == ["alert_id", "incident_id"]
    indexes = {
        row["name"]
        for row in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='index' AND tbl_name='incidents'"
        )
    }
    assert {"ix_incidents_status", "ix_incidents_host"} <= indexes


def test_migration_12_backfills_alert_columns_from_alert_json(tmp_path: Path) -> None:
    conn = _connect(tmp_path / "test.db")
    # Stop at version 11, write a pre-migration row, then upgrade.
    full = migrations._MIGRATIONS
    migrations._MIGRATIONS = full[:11]
    try:
        migrations.migrate(conn)
    finally:
        migrations._MIGRATIONS = full
    conn.execute(
        "INSERT INTO alerts (alert_id, rule_id, created_at, alert_json) VALUES "
        "('INC-1-R1', 'PROV-CAMPAIGN', 'x', "
        "'{\"detection_source\":\"correlation\",\"incident_id\":\"INC-1\"}'), "
        "('ALT-OLD', 'rule-1', 'x', 'not json')"
    )
    conn.commit()
    migrations.migrate(conn)
    rows = {
        r["alert_id"]: (r["detection_source"], r["incident_id"])
        for r in conn.execute("SELECT alert_id, detection_source, incident_id FROM alerts")
    }
    assert rows == {"INC-1-R1": ("correlation", "INC-1"), "ALT-OLD": (None, None)}


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


def test_main_version_12_database_upgrades_to_endpoint_tables(tmp_path: Path, monkeypatch) -> None:
    """A Manager DB created by main (version 12, incidents) gains the endpoint
    migrations 13+ without altering its incident rows."""
    path = tmp_path / "main-v12.db"
    conn = _connect(path)
    with monkeypatch.context() as scoped:
        scoped.setattr(migrations, "_MIGRATIONS", migrations._MIGRATIONS[:12])
        assert migrations.migrate(conn) == 12
    conn.execute(
        "INSERT INTO incidents (incident_id, revision, latest_alert_id, incident_json, "
        "created_at, updated_at) VALUES ('INC-1', 1, 'ALERT-1', '{}', 't0', 't0')"
    )
    conn.commit()
    assert migrations.migrate(conn) == len(migrations._MIGRATIONS)
    tables = {
        row["name"] for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")
    }
    assert {"endpoint_records", "endpoint_latest", "endpoint_generations",
            "endpoint_freshness_challenges", "endpoint_process_capture_records"} <= tables
    incident = conn.execute("SELECT incident_id, revision FROM incidents").fetchone()
    assert (incident["incident_id"], incident["revision"]) == ("INC-1", 1)
    conn.close()
