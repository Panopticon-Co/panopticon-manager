"""Numbered schema migrations, modeled on the ordered-function pattern in
vendor/eyedetect/panopticon_detection/reliability/spool.py (``_migration_1`` / ``_MIGRATIONS``).

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


def _migration_12(conn: sqlite3.Connection) -> None:
    """Capstone incidents (panopticon-detection-engine
    docs/integration/CONTRACT.md §5).

    ``incidents`` holds one row per engine incident, keyed by the engine's
    stable ``incident_id`` (an incident alert's ``alert_id`` changes with every
    revision, ``INC-...-R<n>``; its ``incident_id`` does not). ``revision`` only
    moves forward and ``status`` belongs to the analyst -- both enforced in
    manager/detection/store.py, not by the schema. ``incident_json`` is the
    latest incident alert's evidence (stages, causal_path, score_breakdown...).

    ``incident_alerts`` links an incident to its revision alerts
    (role='revision') and to the stage alerts its evidence names
    (role='stage'). ``incident_audit`` records opened / revised / analyst
    status changes.

    ``alerts`` gains ``detection_source`` (rule|stateful|behavioral|
    correlation -- the response policy reads it) and ``incident_id``, both
    backfilled from ``alert_json`` for rows written before this migration.
    """
    conn.execute(
        """
        CREATE TABLE incidents (
            incident_id     TEXT PRIMARY KEY,
            host_id         TEXT,
            agent_id        TEXT,
            status          TEXT NOT NULL DEFAULT 'open',
            severity        TEXT,
            level           INTEGER,
            score           REAL,
            confidence      REAL,
            tactics_json    TEXT NOT NULL DEFAULT '[]',
            stage_count     INTEGER NOT NULL DEFAULT 0,
            root_process    TEXT,
            root_pid        INTEGER,
            revision        INTEGER NOT NULL,
            latest_alert_id TEXT NOT NULL,
            first_seen      TEXT,
            last_seen       TEXT,
            incident_json   TEXT NOT NULL,
            created_at      TEXT NOT NULL,
            updated_at      TEXT NOT NULL
        )
        """
    )
    conn.execute("CREATE INDEX ix_incidents_status ON incidents (status, last_seen)")
    conn.execute("CREATE INDEX ix_incidents_host ON incidents (host_id, last_seen)")
    conn.execute(
        """
        CREATE TABLE incident_alerts (
            incident_id TEXT NOT NULL,
            alert_id    TEXT NOT NULL,
            role        TEXT NOT NULL,
            PRIMARY KEY (incident_id, alert_id),
            FOREIGN KEY(incident_id) REFERENCES incidents(incident_id),
            FOREIGN KEY(alert_id) REFERENCES alerts(alert_id)
        )
        """
    )
    conn.execute("CREATE INDEX ix_incident_alerts_alert ON incident_alerts (alert_id)")
    conn.execute(
        """
        CREATE TABLE incident_audit (
            audit_id    TEXT PRIMARY KEY,
            incident_id TEXT NOT NULL,
            event       TEXT NOT NULL,
            actor       TEXT NOT NULL,
            detail      TEXT,
            occurred_at TEXT NOT NULL,
            FOREIGN KEY(incident_id) REFERENCES incidents(incident_id)
        )
        """
    )
    conn.execute(
        "CREATE INDEX ix_incident_audit_incident ON incident_audit (incident_id, occurred_at)"
    )
    conn.execute("ALTER TABLE alerts ADD COLUMN detection_source TEXT")
    conn.execute("ALTER TABLE alerts ADD COLUMN incident_id TEXT")
    conn.execute("CREATE INDEX ix_alerts_incident ON alerts (incident_id)")
    conn.execute(
        "UPDATE alerts SET "
        "detection_source = json_extract(alert_json, '$.detection_source'), "
        "incident_id = json_extract(alert_json, '$.incident_id') "
        "WHERE json_valid(alert_json)"
    )


def _migration_13(conn: sqlite3.Connection) -> None:
    """Preserve the full endpoint record surface independently of legacy detection schemas.

    Ported from snapshot/windows-endpoint-dev, where it was numbered 12; main's 12
    (incidents) is kept, so the endpoint migrations here are 13-17.
    """
    conn.execute("""
        CREATE TABLE endpoint_records (
            agent_id TEXT NOT NULL, host_id TEXT NOT NULL, record_id TEXT NOT NULL,
            kind TEXT NOT NULL, category TEXT NOT NULL, observed_at TEXT NOT NULL,
            ingested_at TEXT NOT NULL, payload_digest TEXT NOT NULL, raw_json TEXT NOT NULL,
            PRIMARY KEY(agent_id,record_id)
        )
    """)
    conn.execute(
        "CREATE INDEX ix_endpoint_records_host "
        "ON endpoint_records(host_id,kind,category,observed_at)"
    )
    conn.execute("""
        CREATE TABLE endpoint_latest (
            agent_id TEXT NOT NULL, category TEXT NOT NULL, kind TEXT NOT NULL,
            observed_at TEXT NOT NULL, record_id TEXT NOT NULL, raw_json TEXT NOT NULL,
            PRIMARY KEY(agent_id,category,kind)
        )
    """)



def _migration_14(conn: sqlite3.Connection) -> None:
    """Canonical records are a durable detection queue, including existing rows."""
    conn.execute(
        "ALTER TABLE endpoint_records ADD COLUMN detect_state TEXT NOT NULL DEFAULT 'pending'"
    )
    conn.execute(
        "ALTER TABLE endpoint_records ADD COLUMN detect_attempts INTEGER NOT NULL DEFAULT 0"
    )
    conn.execute("ALTER TABLE endpoint_records ADD COLUMN claimed_at TEXT")
    conn.execute(
        "CREATE INDEX ix_endpoint_records_detect ON endpoint_records(detect_state,ingested_at)"
    )


def _migration_15(conn: sqlite3.Connection) -> None:
    """Clock-independent canonical state ordering; old projections stay unverified."""
    conn.execute("""
        CREATE TABLE endpoint_generations (
            agent_id TEXT NOT NULL, installation_id TEXT NOT NULL,
            generation TEXT NOT NULL, collector_epoch TEXT NOT NULL,
            PRIMARY KEY(agent_id,installation_id,generation)
        )
    """)
    conn.execute("""
        CREATE TABLE endpoint_active_streams (
            agent_id TEXT PRIMARY KEY, installation_id TEXT NOT NULL,
            generation TEXT NOT NULL, collector_epoch TEXT NOT NULL
        )
    """)
    for column in ("installation_id", "generation", "collector_epoch", "sequence"):
        conn.execute(f"ALTER TABLE endpoint_latest ADD COLUMN {column} TEXT")


def _migration_16(conn: sqlite3.Connection) -> None:
    """One-use freshness challenges and immutable first-receipt capture age."""
    conn.execute("""
        CREATE TABLE endpoint_freshness_challenges (
            agent_id TEXT PRIMARY KEY, nonce_digest TEXT NOT NULL,
            server_epoch TEXT NOT NULL, issued_ns TEXT NOT NULL,
            consumed INTEGER NOT NULL DEFAULT 0
        )
    """)
    conn.execute("""
        CREATE TABLE endpoint_capture_age (
            agent_id TEXT NOT NULL, record_id TEXT NOT NULL, server_epoch TEXT NOT NULL,
            received_ns TEXT NOT NULL, age_upper_bound_ms TEXT NOT NULL,
            PRIMARY KEY(agent_id,record_id)
        )
    """)


def _migration_17(conn: sqlite3.Connection) -> None:
    """Discover retained unfinished captures without rewriting endpoint evidence."""
    import json

    from manager.process_snapshots import index_record

    conn.execute("""
        CREATE TABLE endpoint_process_capture_records (
            agent_id TEXT NOT NULL, capture_id TEXT NOT NULL, record_id TEXT NOT NULL,
            role TEXT NOT NULL CHECK(role IN ('begin','page','manifest')),
            endpoint_scope TEXT NOT NULL, collector_epoch TEXT, collector_generation TEXT,
            page_index TEXT, PRIMARY KEY(agent_id,record_id),
            FOREIGN KEY(agent_id,record_id) REFERENCES endpoint_records(agent_id,record_id)
        )
    """)
    conn.execute(
        "CREATE INDEX ix_endpoint_process_captures "
        "ON endpoint_process_capture_records(agent_id,capture_id,record_id)"
    )
    # Iterate one retained body at a time; never fetch all historical page payloads.
    for row in conn.execute(
        "SELECT raw_json FROM endpoint_records WHERE kind='state' AND category IN "
        "('process_inventory_begin','process_inventory_page','process_inventory')"
    ):
        index_record(conn, json.loads(row["raw_json"]))


def _migration_18(conn: sqlite3.Connection) -> None:
    """Immutable command result v2 receipts: one canonical body per result_id,
    bound to agent and command with a SHA-256 digest (snapshot numbering: 16)."""
    conn.execute("""
        CREATE TABLE command_result_receipts (
            result_id TEXT PRIMARY KEY, agent_id TEXT NOT NULL, command_id TEXT NOT NULL,
            payload_digest TEXT NOT NULL, raw_json TEXT NOT NULL, received_at TEXT NOT NULL
        )
    """)


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
    _migration_12,
    _migration_13,
    _migration_14,
    _migration_15,
    _migration_16,
    _migration_17,
    _migration_18,
]


def current_version(conn: sqlite3.Connection) -> int:
    row = conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name='schema_migrations'"
    ).fetchone()
    if row is None:
        return 0
    row = conn.execute("SELECT COALESCE(MAX(version), 0) AS v FROM schema_migrations").fetchone()
    return int(row["v"])


def _upgrade_lab_v13_layout(conn: sqlite3.Connection) -> None:
    """Bridge the deployed, pre-feature lab schema numbered 13.

    That lab revision predates main's incident migration and uses a different
    endpoint table. Archive it by rename: large historical bodies remain intact
    without copying or replaying them into the current detection queue. Existing
    enrolled agents, legacy events, commands and results remain in their tables.
    The exact signature prevents guessing how to repair an unrelated database.
    """
    columns = {row["name"] for row in conn.execute("PRAGMA table_info(endpoint_records)")}
    if "received_at" not in columns and "raw_sha256" not in columns:
        return
    expected = {
        "record_id", "agent_id", "host_id", "kind", "category", "observed_at",
        "received_at", "schema_version", "raw_sha256", "raw_json",
    }
    tables = {row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    alert_columns = {row["name"] for row in conn.execute("PRAGMA table_info(alerts)")}
    if columns != expected or tables & {
        "endpoint_records_legacy_v13", "endpoint_latest", "incidents",
    } or alert_columns & {"detection_source", "incident_id"}:
        raise RuntimeError("unrecognized lab v13 layout; database left unchanged")
    conn.execute("BEGIN IMMEDIATE")
    try:
        _migration_12(conn)
        conn.execute("ALTER TABLE endpoint_records RENAME TO endpoint_records_legacy_v13")
        # The old lab used this name for a different column layout.
        old_index = conn.execute(
            "SELECT tbl_name FROM sqlite_master WHERE type='index' "
            "AND name='ix_endpoint_records_host'"
        ).fetchone()
        if old_index is not None:
            conn.execute("DROP INDEX ix_endpoint_records_host")
            conn.execute(
                "CREATE INDEX ix_endpoint_legacy_v13_host "
                "ON endpoint_records_legacy_v13(host_id,kind,category,observed_at)"
            )
        _migration_13(conn)
        conn.commit()
    except Exception:
        conn.rollback()
        raise


def migrate(conn: sqlite3.Connection) -> int:
    """Apply any pending migrations in order. Returns the resulting version."""
    version = current_version(conn)
    if version > len(_MIGRATIONS):
        raise RuntimeError(
            f"database is at schema version {version}, newer than the "
            f"{len(_MIGRATIONS)} migrations this build knows about"
        )
    if version == 13:
        _upgrade_lab_v13_layout(conn)
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
