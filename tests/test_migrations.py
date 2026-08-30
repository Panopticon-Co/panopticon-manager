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

    assert version == 1
    row = conn.execute("SELECT version FROM schema_migrations").fetchone()
    assert row["version"] == 1


def test_migrate_is_idempotent(tmp_path: Path) -> None:
    conn = _connect(tmp_path / "test.db")
    migrations.migrate(conn)
    version_again = migrations.migrate(conn)
    assert version_again == 1
    count = conn.execute("SELECT COUNT(*) AS c FROM schema_migrations").fetchone()["c"]
    assert count == 1


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
