"""Transactional response audit chain. Hashes detect edits; exported anchors detect rewrites.

SQLite triggers cover every existing writer, including direct INSERT callers. A
legacy_import record authenticates only the snapshot observed during migration.
It does not assert that the pre-migration event was historically authentic.
"""

import base64
import hashlib
import json
import os
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, utils

from manager import command_signing
from manager.timeutil import iso_now

ZERO = "0" * 64
FIELDS = (
    "sequence",
    "previous_hash",
    "source",
    "source_id",
    "event",
    "actor",
    "request_id",
    "command_id",
    "asset_id",
    "occurred_at",
    "payload_json",
    "legacy_import",
)
SOURCES = {
    "command_audit": "audit_id",
    "response_decision_audit": "event_id",
    "response_artifact_custody": "artifact_id,sequence",
}


def canonical(value):
    return json.dumps(
        value, sort_keys=True, ensure_ascii=False, separators=(",", ":"), allow_nan=False
    )


def event_hash(*values):
    record = dict(zip(FIELDS, values, strict=True))
    record["payload_json"] = json.loads(record["payload_json"])
    return hashlib.sha256(b"panopticon-response-audit/1\n" + canonical(record).encode()).hexdigest()


def register(conn):
    conn.create_function("panopticon_audit_hash", len(FIELDS), event_hash, deterministic=True)


def _snapshot_sql(table, prefix):
    # Table/column names are compile-time migration constants, never client input.
    columns = {
        "command_audit": ("audit_id", "command_id", "event", "actor", "detail", "occurred_at"),
        "response_decision_audit": (
            "event_id",
            "response_id",
            "event",
            "actor",
            "detail",
            "occurred_at",
        ),
        "response_artifact_custody": (
            "artifact_id",
            "sequence",
            "event",
            "actor",
            "occurred_at",
            "detail",
            "previous_hash",
            "event_hash",
        ),
    }[table]
    return "json_object(" + ",".join(f"'{c}',{prefix}.{c}" for c in columns) + ")"


def install(conn):
    """Migration 27: retain explicit legacy provenance and cover all response audit writers."""
    conn.execute("""CREATE TABLE response_audit_ledger (
        sequence INTEGER PRIMARY KEY, previous_hash TEXT NOT NULL,
        source TEXT NOT NULL, source_id TEXT NOT NULL, event TEXT NOT NULL,
        actor TEXT NOT NULL, request_id TEXT, command_id TEXT, asset_id TEXT,
        occurred_at TEXT NOT NULL, payload_json TEXT NOT NULL,
        legacy_import INTEGER NOT NULL CHECK(legacy_import IN (0,1)),
        event_hash TEXT NOT NULL, UNIQUE(source,source_id))""")
    for field in ("request_id", "actor", "asset_id", "occurred_at"):
        conn.execute(
            f"CREATE INDEX ix_response_audit_{field} ON response_audit_ledger({field},sequence)"
        )
    conn.execute("""CREATE TABLE response_audit_identity (
        id INTEGER PRIMARY KEY CHECK(id=1), ledger_id TEXT NOT NULL)""")
    from uuid import uuid4

    conn.execute("INSERT INTO response_audit_identity VALUES (1,?)", (str(uuid4()),))
    conn.execute("""CREATE TABLE response_audit_checkpoints (
        checkpoint_id TEXT PRIMARY KEY, sequence INTEGER NOT NULL,
        document_json TEXT NOT NULL, authorization_json TEXT NOT NULL,
        created_at TEXT NOT NULL, request_key TEXT NOT NULL UNIQUE)""")

    # Historical source snapshots are labelled at storage time, not merely in documentation.
    # Preserve their source-row identity and deterministic migration ordering.
    for source, key in SOURCES.items():
        keys = key.split(",")
        rows = conn.execute(f"SELECT * FROM {source} ORDER BY occurred_at,{key}")
        for raw in rows:
            row = dict(raw)
            source_id = ":".join(str(row[k]) for k in keys)
            request_id, command_id, asset_id = _links(conn, source, row)
            append(
                conn,
                source,
                source_id,
                row["event"],
                row["actor"],
                request_id,
                command_id,
                asset_id,
                row["occurred_at"],
                canonical(row),
                legacy_import=1,
            )

    for source, key in SOURCES.items():
        if source == "command_audit":
            source_id = "NEW.audit_id"
            command = "NEW.command_id"
            request = (
                "(SELECT response_id FROM response_actions WHERE command_id=NEW.command_id "
                "OR 'resp-' || response_id=NEW.command_id)"
            )
            asset = (
                "(SELECT json_extract(command_json,'$.host_id') FROM commands "
                "WHERE command_id=NEW.command_id)"
            )
        elif source == "response_decision_audit":
            source_id = "NEW.event_id"
            request = "NEW.response_id"
            command = "(SELECT command_id FROM response_actions WHERE response_id=NEW.response_id)"
            asset = (
                "(SELECT COALESCE(ra.requested_host_id,a.host_id) FROM response_actions ra "
                "LEFT JOIN alerts a ON a.alert_id=ra.alert_id WHERE ra.response_id=NEW.response_id)"
            )
        else:
            source_id = "NEW.artifact_id || ':' || NEW.sequence"
            command = (
                "(SELECT command_id FROM response_artifacts WHERE artifact_id=NEW.artifact_id)"
            )
            request = f"(SELECT response_id FROM response_actions WHERE command_id={command})"
            asset = "(SELECT host_id FROM response_artifacts WHERE artifact_id=NEW.artifact_id)"
        values = (
            "COALESCE((SELECT MAX(sequence) FROM response_audit_ledger),0)+1",
            "COALESCE((SELECT event_hash FROM response_audit_ledger "
            f"ORDER BY sequence DESC LIMIT 1),'{ZERO}')",
            f"'{source}'",
            source_id,
            "NEW.event",
            "NEW.actor",
            request,
            command,
            asset,
            "NEW.occurred_at",
            _snapshot_sql(source, "NEW"),
            "0",
        )
        # A source INSERT and its chain entry commit or roll back together. Failure
        # to register the hash function refuses the write instead of losing audit.
        sql_values = ",".join(values)
        conn.execute(f"""CREATE TRIGGER chain_{source} AFTER INSERT ON {source}
            BEGIN INSERT INTO response_audit_ledger ({",".join(FIELDS)},event_hash)
            VALUES ({sql_values},panopticon_audit_hash({sql_values})); END""")
    conn.execute(f"""CREATE TRIGGER response_audit_guard BEFORE INSERT ON response_audit_ledger
        WHEN NEW.sequence != COALESCE((SELECT MAX(sequence) FROM response_audit_ledger),0)+1
        OR NEW.previous_hash != COALESCE((SELECT event_hash FROM response_audit_ledger
            ORDER BY sequence DESC LIMIT 1),'{ZERO}')
        OR NEW.event_hash != panopticon_audit_hash({",".join("NEW." + f for f in FIELDS)})
        OR NEW.legacy_import != 0
        BEGIN SELECT RAISE(ABORT,'invalid response audit chain append'); END""")
    for table in (
        *SOURCES,
        "response_audit_ledger",
        "response_audit_checkpoints",
        "response_audit_identity",
    ):
        for operation in ("UPDATE", "DELETE"):
            conn.execute(f"""CREATE TRIGGER IF NOT EXISTS chain_no_{operation.lower()}_{table}
                BEFORE {operation} ON {table}
                BEGIN SELECT RAISE(ABORT,'response audit is immutable (append-only)'); END""")


def _links(conn, source, row):
    if source == "response_decision_audit":
        linked = conn.execute(
            """SELECT ra.response_id,ra.command_id,
            COALESCE(ra.requested_host_id,a.host_id) AS host_id FROM response_actions ra
            LEFT JOIN alerts a ON a.alert_id=ra.alert_id WHERE ra.response_id=?""",
            (row["response_id"],),
        ).fetchone()
    else:
        command_id = row.get("command_id")
        if source == "response_artifact_custody":
            command_id = conn.execute(
                "SELECT command_id FROM response_artifacts WHERE artifact_id=?",
                (row["artifact_id"],),
            ).fetchone()[0]
        linked = conn.execute(
            """SELECT ra.response_id,c.command_id,
            json_extract(c.command_json,'$.host_id') AS host_id FROM commands c
            LEFT JOIN response_actions ra ON ra.command_id=c.command_id
                OR 'resp-' || ra.response_id=c.command_id WHERE c.command_id=?""",
            (command_id,),
        ).fetchone()
    return tuple(linked) if linked else (None, None, None)


def append(
    conn,
    source,
    source_id,
    event,
    actor,
    request_id,
    command_id,
    asset_id,
    occurred_at,
    payload_json,
    *,
    legacy_import=0,
):
    previous = conn.execute(
        "SELECT sequence,event_hash FROM response_audit_ledger ORDER BY sequence DESC LIMIT 1"
    ).fetchone()
    values = (
        previous[0] + 1 if previous else 1,
        previous[1] if previous else ZERO,
        source,
        source_id,
        event,
        actor,
        request_id,
        command_id,
        asset_id,
        occurred_at,
        payload_json,
        legacy_import,
    )
    conn.execute(
        f"INSERT INTO response_audit_ledger ({','.join(FIELDS)},event_hash) "
        f"VALUES ({','.join('?' for _ in range(13))})",
        (*values, event_hash(*values)),
    )


def verify(conn, *, require_chained_history=False):
    """Verify the chain and exact source snapshots, including source coverage.

    This detects local corruption; an attacker rewriting the whole database can
    only be detected against an independently retained signed checkpoint.
    """
    previous, sequence, legacy = ZERO, 0, 0
    seen = {name: 0 for name in SOURCES}
    for raw in conn.execute("SELECT * FROM response_audit_ledger ORDER BY sequence"):
        row = dict(raw)
        sequence += 1
        if (
            row["sequence"] != sequence
            or row["previous_hash"] != previous
            or row["event_hash"] != event_hash(*(row[f] for f in FIELDS))
        ):
            raise ValueError(f"response audit chain disagreement at sequence {sequence}")
        source = row["source"]
        if source not in SOURCES:
            raise ValueError("unknown response audit source")
        payload = json.loads(row["payload_json"])
        keys = SOURCES[source].split(",")
        original = conn.execute(
            f"SELECT * FROM {source} WHERE " + " AND ".join(f"{key}=?" for key in keys),
            tuple(payload[key] for key in keys),
        ).fetchone()
        if original is None or canonical(dict(original)) != canonical(payload):
            raise ValueError(f"response audit source disagreement at sequence {sequence}")
        if (
            row["source_id"] != ":".join(str(payload[k]) for k in keys)
            or row["event"] != payload["event"]
            or row["actor"] != payload["actor"]
            or row["occurred_at"] != payload["occurred_at"]
        ):
            raise ValueError("response audit source identity disagreement")
        seen[source] += 1
        if row["legacy_import"]:
            # Verify the migration snapshot's integrity, but never count it as
            # an authenticated post-migration event. Strict history consumers
            # must refuse rather than silently treating it as equivalent.
            if require_chained_history:
                raise ValueError("legacy history cannot satisfy chained-event provenance")
            legacy += 1
        previous = row["event_hash"]
    for table, count in seen.items():
        if conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0] != count:
            raise ValueError("response audit source coverage disagreement")
    return {
        "schema_version": "1",
        "sequence": sequence,
        "head_hash": previous,
        "legacy_import_count": legacy,
        "chain_verified_count": sequence - legacy,
        "complete_history_verified": legacy == 0,
        "historical_authenticity": "legacy snapshots are not retroactively authenticated",
    }


def checkpoint(conn, *, request_key, actor):
    """Caller holds BEGIN IMMEDIATE. Export the result to an independent trust store."""
    previous = conn.execute(
        "SELECT checkpoint_id,document_json,authorization_json "
        "FROM response_audit_checkpoints WHERE request_key=?",
        (request_key,),
    ).fetchone()
    if previous:
        return {
            "checkpoint_id": previous[0],
            "document": json.loads(previous[1]),
            "authorization": json.loads(previous[2]),
        }
    configured = os.environ.get("PANOPTICON_AUDIT_SIGNING_KEY")
    if not configured:
        raise command_signing.SigningUnavailable("audit checkpoint signing key is not configured")
    signer = command_signing.load_key_file(Path(configured))
    summary = verify(conn)
    document = {
        **summary,
        "ledger_id": conn.execute(
            "SELECT ledger_id FROM response_audit_identity WHERE id=1"
        ).fetchone()[0],
        "created_at": iso_now(),
        "created_by": actor,
        "request_key": request_key,
    }
    encoded = b"panopticon-response-audit-checkpoint/1\n" + canonical(document).encode()
    authorization = signer.sign_bytes(encoded)
    identifier = hashlib.sha256(encoded).hexdigest()
    conn.execute(
        "INSERT INTO response_audit_checkpoints VALUES (?,?,?,?,?,?)",
        (
            identifier,
            summary["sequence"],
            canonical(document),
            canonical(authorization),
            document["created_at"],
            request_key,
        ),
    )
    return {"checkpoint_id": identifier, "document": document, "authorization": authorization}


def verify_checkpoint(conn, anchor, public_point):
    """Verify against an explicit independently trusted public key and retained anchor."""
    document, authorization = anchor["document"], anchor["authorization"]
    if authorization.get("algorithm") != "ES256" or authorization.get(
        "key_id"
    ) != command_signing.key_id(public_point):
        raise ValueError("audit checkpoint signing identity disagrees")
    encoded = b"panopticon-response-audit-checkpoint/1\n" + canonical(document).encode()
    try:
        raw = base64.b64decode(authorization["signature"], validate=True)
        if len(raw) != 64:
            raise ValueError("invalid checkpoint signature length")
        signature = utils.encode_dss_signature(
            int.from_bytes(raw[:32], "big"), int.from_bytes(raw[32:], "big")
        )
        ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), public_point).verify(
            signature, encoded, ec.ECDSA(hashes.SHA256())
        )
    except (InvalidSignature, KeyError, TypeError) as exc:
        raise ValueError("invalid audit checkpoint signature") from exc
    if anchor["checkpoint_id"] != hashlib.sha256(encoded).hexdigest():
        raise ValueError("audit checkpoint digest disagrees")
    if (
        document["ledger_id"]
        != conn.execute("SELECT ledger_id FROM response_audit_identity WHERE id=1").fetchone()[0]
    ):
        raise ValueError("audit checkpoint belongs to a different ledger")
    summary = verify(conn)
    head = conn.execute(
        "SELECT event_hash FROM response_audit_ledger WHERE sequence=?", (document["sequence"],)
    ).fetchone()
    if (head[0] if head else ZERO) != document["head_hash"] or summary["sequence"] < document[
        "sequence"
    ]:
        raise ValueError("audit checkpoint no longer matches retained history")
    return summary
