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
