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


def _migration_5(conn: sqlite3.Connection) -> None:
    conn.execute(
        """
        CREATE TABLE commands (
            command_id TEXT PRIMARY KEY,
            agent_id TEXT NOT NULL,
            command_json TEXT NOT NULL,
            created_at TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            delivered_at TEXT
        )
        """
    )
    conn.execute("CREATE INDEX ix_commands_agent ON commands (agent_id, delivered_at, expires_at)")


def _migration_6(conn: sqlite3.Connection) -> None:
    conn.execute(
        """
        CREATE TABLE command_results (
            result_id TEXT PRIMARY KEY,
            command_id TEXT NOT NULL,
            agent_id TEXT NOT NULL,
            outcome TEXT NOT NULL,
            detail TEXT,
            received_at TEXT NOT NULL,
            FOREIGN KEY(command_id) REFERENCES commands(command_id)
        )
        """
    )


def _migration_7(conn: sqlite3.Connection) -> None:
    """Command lifecycle audit trail. The shared command-creation token carries
    no caller identity, so ``actor`` records what identity information is
    available at each event (e.g. ``system:command-token`` today, a specific
    analyst id once the Response Engine adds per-caller auth)."""
    conn.execute(
        """
        CREATE TABLE command_audit (
            audit_id TEXT PRIMARY KEY,
            command_id TEXT NOT NULL,
            event TEXT NOT NULL,
            actor TEXT NOT NULL,
            detail TEXT,
            occurred_at TEXT NOT NULL,
            FOREIGN KEY(command_id) REFERENCES commands(command_id)
        )
        """
    )
    conn.execute("CREATE INDEX ix_command_audit_command ON command_audit (command_id, occurred_at)")


def _migration_8(conn: sqlite3.Connection) -> None:
    """Response Engine staging table: an alert's recommended response lives
    here from creation through analyst authorization, distinct from the
    ``commands`` row it produces once authorized. ``tier`` and
    ``lifecycle_state`` are enforced at the Pydantic/app layer (see
    manager/detection/response.py), matching this codebase's existing
    convention of not using SQLite CHECK constraints for enums."""
    conn.execute(
        """
        CREATE TABLE response_actions (
            response_id TEXT PRIMARY KEY,
            alert_id TEXT NOT NULL,
            action TEXT NOT NULL,
            tier TEXT NOT NULL,
            lifecycle_state TEXT NOT NULL,
            target_json TEXT NOT NULL,
            command_id TEXT,
            created_at TEXT NOT NULL,
            authorized_at TEXT,
            authorized_by TEXT,
            decided_reason TEXT,
            FOREIGN KEY(alert_id) REFERENCES alerts(alert_id),
            FOREIGN KEY(command_id) REFERENCES commands(command_id)
        )
        """
    )
    conn.execute(
        "CREATE INDEX ix_response_actions_state ON response_actions (lifecycle_state, created_at)"
    )
    conn.execute("CREATE INDEX ix_response_actions_alert ON response_actions (alert_id)")


def _migration_9(conn: sqlite3.Connection) -> None:
    """Links a dispatched command back to the alert/response_action that
    authorized it, and gives commands their own lifecycle state distinct
    from the raw delivered_at/command_results rows (see
    manager/detection/response.py for the state machine)."""
    conn.execute("ALTER TABLE commands ADD COLUMN alert_id TEXT")
    conn.execute("ALTER TABLE commands ADD COLUMN lifecycle_state TEXT NOT NULL DEFAULT 'PENDING'")


def _migration_10(conn: sqlite3.Connection) -> None:
    """Analyst identities for the response-authorization path -- distinct
    from agent bearer tokens (enrolled_agents) and the shared
    command-creation token (PANOPTICON_COMMAND_TOKEN), so an authorization
    finally carries a real per-caller identity into command_audit.actor."""
    conn.execute(
        """
        CREATE TABLE analyst_credentials (
            analyst_id TEXT PRIMARY KEY,
            token_digest TEXT NOT NULL,
            created_at TEXT NOT NULL,
            revoked_at TEXT
        )
        """
    )


def _migration_11(conn: sqlite3.Connection) -> None:
    """Phase 13: cryptographic endpoint identity. ``public_key`` binds an
    enrolled agent to the ECDSA P-256 keypair it generated locally and
    proved possession of during enrollment (see docs/adr/004). NULL for rows
    from before this migration (none should exist in a fresh dev DB, but a
    long-lived deployment upgrading in place would have pre-Phase-13 rows;
    those must simply never authenticate via signature-based paths, since
    they have no key on file -- they keep working via the pre-existing
    bearer-token check, which this migration does not touch or weaken).

    ``enrollment_nonces`` implements one-time proof-of-possession challenges:
    a nonce is minted by /enrollment-challenge, consumed exactly once by a
    matching /enroll call (or never, if it expires or is abandoned), and is
    never valid twice -- the concrete defense against replaying a captured
    enrollment request.
    """
    conn.execute("ALTER TABLE enrolled_agents ADD COLUMN public_key TEXT")
    conn.execute(
        """
        CREATE TABLE enrollment_nonces (
            nonce TEXT PRIMARY KEY,
            created_at TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            consumed_at TEXT
        )
        """
    )
    conn.execute("CREATE INDEX ix_enrollment_nonces_expires ON enrollment_nonces (expires_at)")


_MIGRATIONS: List[Callable[[sqlite3.Connection], None]] = [
    _migration_1,
    _migration_2,
    _migration_3,
    _migration_4,
    _migration_5,
    _migration_6,
    _migration_7,
    _migration_8,
    _migration_9,
    _migration_10,
    _migration_11,
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
