"""Numbered schema migrations, modeled on the ordered-function pattern in
vendor/eyedetect/src/reliability/spool.py (``_migration_1`` / ``_MIGRATIONS``).

Each entry in ``_MIGRATIONS`` upgrades version i to i+1. Never edit an
already-applied migration function — append a new one instead. Tables beyond
``schema_migrations`` itself arrive as new migrations in later phases (the
``events`` table in Phase 1, ``agents``/``batches`` in Phase 4/5, etc.).
"""

from __future__ import annotations

import sqlite3
import time
from typing import Callable, List


def _migration_1(conn: sqlite3.Connection) -> None:
    conn.execute(
        """
        CREATE TABLE schema_migrations (
            version    INTEGER PRIMARY KEY,
            applied_at TEXT NOT NULL
        )
        """
    )


_MIGRATIONS: List[Callable[[sqlite3.Connection], None]] = [_migration_1]


def current_version(conn: sqlite3.Connection) -> int:
    row = conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name='schema_migrations'"
    ).fetchone()
    if row is None:
        return 0
    row = conn.execute("SELECT COALESCE(MAX(version), 0) AS v FROM schema_migrations").fetchone()
    return int(row["v"])


def migrate(conn: sqlite3.Connection) -> int:
    """Apply any pending migrations in order. Returns the resulting version."""
    version = current_version(conn)
    if version > len(_MIGRATIONS):
        raise RuntimeError(
            f"database is at schema version {version}, newer than the "
            f"{len(_MIGRATIONS)} migrations this build knows about"
        )
    for i in range(version, len(_MIGRATIONS)):
        conn.execute("BEGIN IMMEDIATE")
        try:
            _MIGRATIONS[i](conn)
            next_version = i + 1
            conn.execute(
                "INSERT INTO schema_migrations (version, applied_at) VALUES (?, ?)",
                (next_version, time.strftime("%Y-%m-%dT%H:%M:%S.000Z", time.gmtime())),
            )
            conn.commit()
        except Exception:
            conn.rollback()
            raise
    return current_version(conn)
