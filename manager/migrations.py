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


def _migration_19(conn: sqlite3.Connection) -> None:
    """Retain manual response provenance independently of the approving actor."""
    conn.execute("ALTER TABLE response_actions ADD COLUMN origin TEXT NOT NULL DEFAULT 'detection'")
    for column in ("requested_by", "request_reason", "requested_agent_id", "requested_host_id"):
        conn.execute(f"ALTER TABLE response_actions ADD COLUMN {column} TEXT")


def _migration_20(conn: sqlite3.Connection) -> None:
    """Analyst roles, persistent request identity and append-only decision facts."""
    conn.execute("ALTER TABLE analyst_credentials ADD COLUMN role TEXT NOT NULL DEFAULT 'analyst'")
    conn.execute("""CREATE TABLE response_request_keys (
        analyst_id TEXT NOT NULL, request_id TEXT NOT NULL, payload_digest TEXT NOT NULL,
        response_id TEXT NOT NULL REFERENCES response_actions(response_id),
        PRIMARY KEY(analyst_id,request_id)
    )""")
    conn.execute("""CREATE TABLE response_decision_audit (
        event_id TEXT PRIMARY KEY,
        response_id TEXT NOT NULL REFERENCES response_actions(response_id),
        event TEXT NOT NULL, actor TEXT NOT NULL, detail TEXT, occurred_at TEXT NOT NULL
    )""")
    conn.execute("CREATE INDEX ix_response_decision_audit ON response_decision_audit(response_id)")
    for operation in ("UPDATE", "DELETE"):
        conn.execute(f"""CREATE TRIGGER response_audit_no_{operation.lower()}
            BEFORE {operation} ON response_decision_audit
            BEGIN SELECT RAISE(ABORT, 'response decision audit is append-only'); END""")


def _migration_21(conn: sqlite3.Connection) -> None:
    """Authenticated response channel observations; never infer endpoint capabilities."""
    conn.execute("""CREATE TABLE agent_response_channels (
        agent_id TEXT PRIMARY KEY REFERENCES enrolled_agents(agent_id),
        last_polled_at TEXT NOT NULL, delivery_mode TEXT NOT NULL, command_auth TEXT
    )""")
    conn.execute("""CREATE TABLE response_campaigns (
        actor TEXT NOT NULL, campaign_id TEXT NOT NULL, payload_digest TEXT NOT NULL,
        result_json TEXT NOT NULL, created_at TEXT NOT NULL, PRIMARY KEY(actor,campaign_id)
    )""")


def _migration_22(conn: sqlite3.Connection) -> None:
    """Retain Linux sensor provenance, stream gaps and coverage reports."""
    conn.execute("""CREATE TABLE IF NOT EXISTS linux_endpoint_records (
    agent_id    TEXT NOT NULL,
    record_id   TEXT NOT NULL,
    sensor_id   TEXT NOT NULL,
    boot_id     TEXT NOT NULL,
    seq         INTEGER NOT NULL,
    host_id     TEXT NOT NULL,
    record_type TEXT NOT NULL,
    type        TEXT NOT NULL,
    event_time  TEXT NOT NULL,
    ingested_at TEXT NOT NULL,
    digest      TEXT NOT NULL,
    raw_json    TEXT NOT NULL,
    PRIMARY KEY (agent_id, record_id)
)""")
    conn.execute("""CREATE UNIQUE INDEX IF NOT EXISTS ix_linux_endpoint_stream_seq
    ON linux_endpoint_records (agent_id, sensor_id, boot_id, seq)""")
    conn.execute("""CREATE INDEX IF NOT EXISTS ix_linux_endpoint_host_time
    ON linux_endpoint_records (host_id, event_time)""")
    conn.execute("""CREATE TABLE IF NOT EXISTS linux_endpoint_streams (
    agent_id        TEXT NOT NULL,
    sensor_id       TEXT NOT NULL,
    boot_id         TEXT NOT NULL,
    host_id         TEXT NOT NULL,
    first_seq       INTEGER NOT NULL,
    highest_seq     INTEGER NOT NULL,
    acked_through   INTEGER NOT NULL,
    record_count    INTEGER NOT NULL,
    updated_at      TEXT NOT NULL,
    PRIMARY KEY (agent_id, sensor_id, boot_id)
)""")
    conn.execute("""CREATE TABLE IF NOT EXISTS linux_endpoint_detection (
    agent_id   TEXT NOT NULL,
    record_id  TEXT NOT NULL,
    state      TEXT NOT NULL,
    attempts   INTEGER NOT NULL DEFAULT 0,
    claimed_at TEXT,
    PRIMARY KEY (agent_id, record_id)
)""")
    conn.execute("""CREATE TABLE IF NOT EXISTS linux_endpoint_health (
    host_id     TEXT PRIMARY KEY,
    agent_id    TEXT NOT NULL,
    record_id   TEXT NOT NULL,
    event_time  TEXT NOT NULL,
    received_at TEXT NOT NULL,
    health_json TEXT NOT NULL
)""")


def _migration_23(conn: sqlite3.Connection) -> None:
    """Queue existing Linux process records without replaying completed work."""
    conn.execute(
        "INSERT OR IGNORE INTO linux_endpoint_detection (agent_id,record_id,state) "
        "SELECT agent_id,record_id,'pending' FROM linux_endpoint_records "
        "WHERE record_type='event' AND type='process.exec'"
    )
    conn.execute(
        "CREATE INDEX IF NOT EXISTS ix_linux_detection_state "
        "ON linux_endpoint_detection(state,agent_id,record_id)"
    )


def _migration_24(conn: sqlite3.Connection) -> None:
    """Index retained native response reports without duplicating their bodies."""
    conn.execute(
        "CREATE INDEX IF NOT EXISTS ix_linux_response_command "
        "ON linux_endpoint_records(agent_id,json_extract(raw_json,'$.response.command_id'),"
        "ingested_at,record_id) WHERE type='response.action'"
    )


def _migration_25(conn: sqlite3.Connection) -> None:
    """Bind current runtime configuration to authenticated command-channel observations."""
    for column in ("profile_json", "profile_observed_at", "profile_host_id"):
        conn.execute(f"ALTER TABLE agent_response_channels ADD COLUMN {column} TEXT")


def _migration_26(conn: sqlite3.Connection) -> None:
    """Immutable command-bound collection artifacts and append-only custody."""
    conn.execute("""CREATE TABLE response_artifacts (
        artifact_id TEXT PRIMARY KEY, agent_id TEXT NOT NULL, command_id TEXT NOT NULL,
        host_id TEXT NOT NULL, correlation_id TEXT NOT NULL, kind TEXT NOT NULL,
        media_type TEXT NOT NULL, content_bytes INTEGER NOT NULL, sha256 TEXT NOT NULL,
        manifest_digest TEXT NOT NULL, content BLOB NOT NULL, received_at TEXT NOT NULL,
        FOREIGN KEY(command_id) REFERENCES commands(command_id))""")
    conn.execute(
        "CREATE INDEX ix_response_artifact_command ON response_artifacts(command_id,received_at)"
    )
    conn.execute("""CREATE TABLE response_artifact_usage (
        id INTEGER PRIMARY KEY CHECK(id=1), content_bytes INTEGER NOT NULL,
        artifacts INTEGER NOT NULL)""")
    conn.execute("INSERT INTO response_artifact_usage VALUES (1,0,0)")
    conn.execute("""CREATE TRIGGER response_artifact_usage_insert AFTER INSERT ON response_artifacts
        BEGIN UPDATE response_artifact_usage SET content_bytes=content_bytes+NEW.content_bytes,
        artifacts=artifacts+1 WHERE id=1; END""")
    conn.execute("""CREATE TABLE response_artifact_custody (
        artifact_id TEXT NOT NULL, sequence INTEGER NOT NULL, event TEXT NOT NULL,
        actor TEXT NOT NULL, occurred_at TEXT NOT NULL, detail TEXT NOT NULL,
        previous_hash TEXT NOT NULL, event_hash TEXT NOT NULL,
        PRIMARY KEY(artifact_id,sequence),
        FOREIGN KEY(artifact_id) REFERENCES response_artifacts(artifact_id))""")
    conn.execute("""CREATE TRIGGER response_artifact_immutable BEFORE UPDATE ON response_artifacts
        BEGIN SELECT RAISE(ABORT,'artifact evidence is immutable'); END""")
    conn.execute("""CREATE TRIGGER response_artifact_custody_immutable_update
        BEFORE UPDATE ON response_artifact_custody
        BEGIN SELECT RAISE(ABORT,'custody evidence is append-only'); END""")
    conn.execute("""CREATE TRIGGER response_artifact_custody_immutable_delete
        BEFORE DELETE ON response_artifact_custody
        BEGIN SELECT RAISE(ABORT,'custody evidence is append-only'); END""")


def _migration_27(conn: sqlite3.Connection) -> None:
    """Hash-chain response audit. Existing records persist legacy_import=1.

    The imported snapshot is protected from this migration onward; historical
    event authenticity is explicitly NOT inferred from its new chain entry.
    New trigger-generated events have legacy_import=0.
    """
    from manager.audit_chain import install

    install(conn)


def _migration_28(conn: sqlite3.Connection) -> None:
    """Retain artifact signing key versions and audit every identity transition."""
    from manager.audit_chain import install_security_source

    conn.execute("""CREATE TABLE response_security_audit (
        event_id TEXT PRIMARY KEY, request_id TEXT, asset_id TEXT, event TEXT NOT NULL,
        actor TEXT NOT NULL, detail TEXT NOT NULL, occurred_at TEXT NOT NULL)""")
    install_security_source(conn)
    conn.execute("""CREATE TABLE artifact_signing_keys (
        agent_id TEXT NOT NULL REFERENCES enrolled_agents(agent_id), host_id TEXT NOT NULL,
        key_id TEXT NOT NULL, key_version INTEGER NOT NULL CHECK(key_version>0),
        public_key TEXT NOT NULL, valid_from TEXT NOT NULL, retired_at TEXT,
        compromised_at TEXT, compromise_reason TEXT,
        PRIMARY KEY(agent_id,key_id), UNIQUE(agent_id,key_version))""")
    conn.execute("""CREATE UNIQUE INDEX ix_active_artifact_key ON artifact_signing_keys(agent_id)
        WHERE retired_at IS NULL AND compromised_at IS NULL""")
    conn.execute("""INSERT INTO artifact_signing_keys
        (agent_id,host_id,key_id,key_version,public_key,valid_from,retired_at)
        SELECT agent_id,host_id,panopticon_public_key_id(public_key),1,
            public_key,enrolled_at,revoked_at
        FROM enrolled_agents WHERE public_key IS NOT NULL""")
    conn.execute("""CREATE TRIGGER artifact_key_enrollment AFTER INSERT ON enrolled_agents
        WHEN NEW.public_key IS NOT NULL BEGIN
        INSERT INTO artifact_signing_keys
        (agent_id,host_id,key_id,key_version,public_key,valid_from)
        VALUES (NEW.agent_id,NEW.host_id,panopticon_public_key_id(NEW.public_key),1,
            NEW.public_key,NEW.enrolled_at);
        INSERT INTO response_security_audit VALUES
        (lower(hex(randomblob(16))),NULL,NEW.host_id,'artifact_key_enrolled',
            'agent:' || NEW.agent_id,json_object('agent_id',NEW.agent_id,
                'key_id',panopticon_public_key_id(NEW.public_key),'key_version',1),NEW.enrolled_at);
        END""")
    conn.execute("""CREATE TRIGGER artifact_key_material_immutable
        BEFORE UPDATE ON artifact_signing_keys
        WHEN NEW.agent_id!=OLD.agent_id OR NEW.host_id!=OLD.host_id OR NEW.key_id!=OLD.key_id
        OR NEW.key_version!=OLD.key_version OR NEW.public_key!=OLD.public_key
        OR NEW.valid_from!=OLD.valid_from
        OR (OLD.retired_at IS NOT NULL AND NEW.retired_at IS NOT OLD.retired_at)
        OR (OLD.compromised_at IS NOT NULL AND
            (NEW.compromised_at IS NOT OLD.compromised_at
             OR NEW.compromise_reason IS NOT OLD.compromise_reason))
        BEGIN SELECT RAISE(ABORT,'historical artifact key identity is immutable'); END""")
    conn.execute("""CREATE TRIGGER artifact_key_no_delete BEFORE DELETE ON artifact_signing_keys
        BEGIN SELECT RAISE(ABORT,'historical artifact keys must be retained'); END""")
    conn.execute("""CREATE TABLE artifact_key_rotations (
        agent_id TEXT NOT NULL REFERENCES enrolled_agents(agent_id), request_id TEXT NOT NULL,
        old_key_id TEXT NOT NULL, new_key_id TEXT NOT NULL, new_public_key TEXT NOT NULL,
        payload_digest TEXT NOT NULL, state TEXT NOT NULL CHECK(state IN ('PENDING','APPROVED')),
        created_at TEXT NOT NULL, expires_at TEXT NOT NULL, approved_by TEXT, approved_at TEXT,
        PRIMARY KEY(agent_id,request_id))""")
    conn.execute("""CREATE TABLE artifact_identity_operations (
        actor TEXT NOT NULL, request_id TEXT NOT NULL, payload_digest TEXT NOT NULL,
        result_json TEXT NOT NULL, PRIMARY KEY(actor,request_id))""")
    conn.execute("""CREATE TABLE artifact_manifest_attestations (
        artifact_id TEXT PRIMARY KEY REFERENCES response_artifacts(artifact_id),
        agent_id TEXT NOT NULL, key_id TEXT NOT NULL, key_version INTEGER NOT NULL,
        manifest_json TEXT NOT NULL, verified_at TEXT NOT NULL,
        FOREIGN KEY(agent_id,key_id) REFERENCES artifact_signing_keys(agent_id,key_id))""")
    for operation in ("UPDATE", "DELETE"):
        conn.execute(f"""CREATE TRIGGER artifact_attestation_no_{operation.lower()}
            BEFORE {operation} ON artifact_manifest_attestations
            BEGIN SELECT RAISE(ABORT,'artifact attestation is immutable'); END""")


def _migration_29(conn: sqlite3.Connection) -> None:
    """Bounded resumable artifact sessions; reservations survive process restart."""
    conn.execute("""CREATE TABLE response_artifact_transfers (
        artifact_id TEXT PRIMARY KEY, agent_id TEXT NOT NULL, command_id TEXT NOT NULL,
        host_id TEXT NOT NULL, manifest_json TEXT NOT NULL, manifest_sha256 TEXT NOT NULL,
        content_bytes INTEGER NOT NULL CHECK(content_bytes BETWEEN 1 AND 1048576),
        received_bytes INTEGER NOT NULL DEFAULT 0 CHECK(received_bytes BETWEEN 0 AND content_bytes),
        state TEXT NOT NULL CHECK(state IN ('OPEN','COMPLETE','EXPIRED')),
        admitted_at TEXT NOT NULL, expires_at TEXT NOT NULL,
        FOREIGN KEY(command_id) REFERENCES commands(command_id))""")
    conn.execute(
        "CREATE INDEX ix_artifact_transfer_expiry ON response_artifact_transfers(state,expires_at)"
    )
    conn.execute(
        "CREATE INDEX ix_artifact_transfer_agent ON response_artifact_transfers(agent_id,state)"
    )
    conn.execute(
        "CREATE INDEX ix_artifact_transfer_command ON response_artifact_transfers(command_id,state)"
    )
    conn.execute("""CREATE TABLE response_artifact_chunks (
        artifact_id TEXT NOT NULL REFERENCES response_artifact_transfers(artifact_id),
        offset INTEGER NOT NULL CHECK(offset BETWEEN 0 AND 1048575),
        sha256 TEXT NOT NULL, content BLOB NOT NULL CHECK(length(content) BETWEEN 1 AND 65536),
        PRIMARY KEY(artifact_id,offset))""")
    conn.execute("""CREATE TRIGGER artifact_chunk_no_update
        BEFORE UPDATE ON response_artifact_chunks
        BEGIN SELECT RAISE(ABORT,'accepted artifact chunks cannot change'); END""")
    conn.execute("""CREATE TRIGGER artifact_transfer_identity_immutable
        BEFORE UPDATE ON response_artifact_transfers
        WHEN NEW.artifact_id!=OLD.artifact_id OR NEW.agent_id!=OLD.agent_id
        OR NEW.command_id!=OLD.command_id OR NEW.host_id!=OLD.host_id
        OR NEW.manifest_json!=OLD.manifest_json OR NEW.manifest_sha256!=OLD.manifest_sha256
        OR NEW.content_bytes!=OLD.content_bytes
        BEGIN SELECT RAISE(ABORT,'artifact transfer identity cannot change'); END""")
    conn.execute("""CREATE TABLE response_artifact_transfer_usage (
        id INTEGER PRIMARY KEY CHECK(id=1),
        reserved_bytes INTEGER NOT NULL CHECK(reserved_bytes>=0),
        open_sessions INTEGER NOT NULL CHECK(open_sessions>=0), total_sessions INTEGER NOT NULL)""")
    conn.execute("INSERT INTO response_artifact_transfer_usage VALUES (1,0,0,0)")
    conn.execute("""CREATE TRIGGER artifact_transfer_usage_insert
        AFTER INSERT ON response_artifact_transfers
        BEGIN UPDATE response_artifact_transfer_usage SET
            reserved_bytes=reserved_bytes
                +CASE WHEN NEW.state='OPEN' THEN NEW.content_bytes ELSE 0 END,
            open_sessions=open_sessions+CASE WHEN NEW.state='OPEN' THEN 1 ELSE 0 END,
            total_sessions=total_sessions+1 WHERE id=1; END""")
    conn.execute("""CREATE TRIGGER artifact_transfer_usage_state AFTER UPDATE OF state
        ON response_artifact_transfers BEGIN UPDATE response_artifact_transfer_usage SET
        reserved_bytes=reserved_bytes
            -CASE WHEN OLD.state='OPEN' THEN OLD.content_bytes ELSE 0 END
            +CASE WHEN NEW.state='OPEN' THEN NEW.content_bytes ELSE 0 END,
        open_sessions=open_sessions-CASE WHEN OLD.state='OPEN' THEN 1 ELSE 0 END
            +CASE WHEN NEW.state='OPEN' THEN 1 ELSE 0 END WHERE id=1; END""")
    conn.execute("""CREATE TRIGGER artifact_transfer_no_delete
        BEFORE DELETE ON response_artifact_transfers
        BEGIN SELECT RAISE(ABORT,'artifact transfer history must be retained'); END""")


def _migration_30(conn: sqlite3.Connection) -> None:
    """Artifact access policy 1: explicit credential-bound scopes; no legacy grants."""
    conn.execute("""CREATE TABLE artifact_access_grants (
        grant_id TEXT PRIMARY KEY,
        analyst_id TEXT NOT NULL REFERENCES analyst_credentials(analyst_id),
        credential_digest TEXT NOT NULL, host_id TEXT NOT NULL,
        alert_id TEXT NOT NULL REFERENCES alerts(alert_id),
        policy_version INTEGER NOT NULL CHECK(policy_version=1),
        granted_by TEXT NOT NULL, reason TEXT NOT NULL, created_at TEXT NOT NULL,
        revoked_at TEXT, revoked_by TEXT, revoke_reason TEXT,
        CHECK((revoked_at IS NULL AND revoked_by IS NULL AND revoke_reason IS NULL)
           OR (revoked_at IS NOT NULL AND revoked_by IS NOT NULL
               AND revoke_reason IS NOT NULL)))""")
    conn.execute("""CREATE UNIQUE INDEX artifact_access_active
        ON artifact_access_grants(analyst_id,credential_digest,host_id,alert_id)
        WHERE revoked_at IS NULL""")
    conn.execute("""CREATE TRIGGER artifact_access_identity_immutable
        BEFORE UPDATE ON artifact_access_grants
        WHEN NEW.grant_id!=OLD.grant_id OR NEW.analyst_id!=OLD.analyst_id
        OR NEW.credential_digest!=OLD.credential_digest OR NEW.host_id!=OLD.host_id
        OR NEW.alert_id!=OLD.alert_id OR NEW.policy_version!=OLD.policy_version
        OR NEW.granted_by!=OLD.granted_by OR NEW.reason!=OLD.reason
        OR NEW.created_at!=OLD.created_at
        OR OLD.revoked_at IS NOT NULL OR NEW.revoked_at IS NULL
        BEGIN SELECT RAISE(ABORT,'artifact access history is immutable'); END""")
    conn.execute("""CREATE TRIGGER artifact_access_no_delete BEFORE DELETE ON artifact_access_grants
        BEGIN SELECT RAISE(ABORT,'artifact access history must be retained'); END""")
    conn.execute("""CREATE TABLE artifact_access_operations (
        actor TEXT NOT NULL, request_id TEXT NOT NULL, payload_digest TEXT NOT NULL,
        result_json TEXT NOT NULL, created_at TEXT NOT NULL, PRIMARY KEY(actor,request_id))""")
    for operation in ("UPDATE", "DELETE"):
        conn.execute(f"""CREATE TRIGGER artifact_access_operations_no_{operation.lower()}
            BEFORE {operation} ON artifact_access_operations
            BEGIN SELECT RAISE(ABORT,'artifact access operation is immutable'); END""")


def _migration_31(conn: sqlite3.Connection) -> None:
    """Idempotent analyst acknowledgements after browser evidence verification."""
    conn.execute("""CREATE TABLE artifact_view_receipts (
        analyst_id TEXT NOT NULL, credential_digest TEXT NOT NULL, request_id TEXT NOT NULL,
        artifact_id TEXT NOT NULL REFERENCES response_artifacts(artifact_id),
        manifest_sha256 TEXT NOT NULL,
        operation TEXT NOT NULL CHECK(operation IN ('view','download')),
        recorded_at TEXT NOT NULL, PRIMARY KEY(analyst_id,credential_digest,request_id))""")
    for operation in ("UPDATE", "DELETE"):
        conn.execute(f"""CREATE TRIGGER artifact_view_no_{operation.lower()}
            BEFORE {operation} ON artifact_view_receipts
            BEGIN SELECT RAISE(ABORT,'artifact view history is immutable'); END""")


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
    _migration_19,
    _migration_20,
    _migration_21,
    _migration_22,
    _migration_23,
    _migration_24,
    _migration_25,
    _migration_26,
    _migration_27,
    _migration_28,
    _migration_29,
    _migration_30,
    _migration_31,
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
        "record_id",
        "agent_id",
        "host_id",
        "kind",
        "category",
        "observed_at",
        "received_at",
        "schema_version",
        "raw_sha256",
        "raw_json",
    }
    tables = {row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    alert_columns = {row["name"] for row in conn.execute("PRAGMA table_info(alerts)")}
    if (
        columns != expected
        or tables
        & {
            "endpoint_records_legacy_v13",
            "endpoint_latest",
            "incidents",
        }
        or alert_columns & {"detection_source", "incident_id"}
    ):
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
    from manager.audit_chain import register

    register(conn)
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
