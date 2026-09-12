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


def _migration_2(conn: sqlite3.Connection) -> None:
    """The events table — see docs/adr/002 and docs/adr/003. detect_state and
    claimed_at sit unused until Phase 3's detection worker; shaped now so the
    table isn't migrated twice."""
    conn.execute(
        """
        CREATE TABLE events (
            event_id       TEXT PRIMARY KEY,
            agent_id       TEXT NOT NULL,
            host_id        TEXT NOT NULL,
            category       TEXT NOT NULL,
            event_timestamp TEXT NOT NULL,
            ingested_at    TEXT NOT NULL,
            schema_version TEXT NOT NULL,
            clock_skew     INTEGER NOT NULL DEFAULT 0,
            raw_json       TEXT NOT NULL,
            detect_state   TEXT NOT NULL DEFAULT 'pending',
            detect_attempts INTEGER NOT NULL DEFAULT 0,
            claimed_at     TEXT
        )
        """
    )
    conn.execute("CREATE INDEX ix_events_detect ON events (detect_state, event_timestamp)")
    conn.execute("CREATE INDEX ix_events_host ON events (host_id, event_timestamp)")


def _migration_3(conn: sqlite3.Connection) -> None:
    """The alerts table — output of Phase 3's detection worker. Column set is
    docs/MANAGER_ARCHITECTURE.md §Data. ``alert_id`` is the detection engine's
    own deterministic ``ALT-<sha1[:8]>`` for atomic alerts, so ``INSERT OR
    IGNORE`` on it makes replay and crash-recovery idempotent. ``alert_json``
    keeps the full engine Alert payload for the console and future query API."""
    conn.execute(
        """
        CREATE TABLE alerts (
            alert_id        TEXT PRIMARY KEY,
            rule_id         TEXT NOT NULL,
            level           INTEGER,
            severity        TEXT,
            host_id         TEXT,
            agent_id        TEXT,
            event_id        TEXT,
            alert_timestamp TEXT,
            created_at      TEXT NOT NULL,
            mitre_tactic    TEXT,
            mitre_technique TEXT,
            alert_json      TEXT NOT NULL
        )
        """
    )
    conn.execute("CREATE INDEX ix_alerts_created ON alerts (created_at DESC, alert_id DESC)")


def _migration_4(conn: sqlite3.Connection) -> None:
    """Enrolled agent identities. Tokens are stored only as SHA-256 digests."""
    conn.execute(
        """
        CREATE TABLE enrolled_agents (
            agent_id TEXT PRIMARY KEY,
            host_id TEXT NOT NULL,
            token_digest TEXT NOT NULL,
            enrolled_at TEXT NOT NULL,
            revoked_at TEXT
        )
        """
    )


_MIGRATIONS: List[Callable[[sqlite3.Connection], None]] = [
    _migration_1,
    _migration_2,
    _migration_3,
    _migration_4,
]


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
