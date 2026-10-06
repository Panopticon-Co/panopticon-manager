"""Durable storage and sequence accounting for Linux endpoint records.

Tables are created here with ``CREATE TABLE IF NOT EXISTS`` rather than as numbered migrations on
purpose: another in-flight change set already claims migrations 12 to 16 for the Windows endpoint
records, and two branches both adding "migration 12" would leave databases whose version number
means different things. These tables are namespaced ``linux_endpoint_*`` and never altered in place.

Each sensor numbers its records per boot (``seq``). The store keeps, per (agent, sensor, boot)
stream, the first sequence seen, the highest, and the contiguous prefix. ``acked_through`` is that
contiguous prefix: the sensor may discard its durable log up to it, and nothing beyond it, so a
record that never arrived is retransmitted instead of silently lost.
"""

from __future__ import annotations

import json
import sqlite3

_SCHEMA = """
CREATE TABLE IF NOT EXISTS linux_endpoint_records (
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
);
CREATE UNIQUE INDEX IF NOT EXISTS ix_linux_endpoint_stream_seq
    ON linux_endpoint_records (agent_id, sensor_id, boot_id, seq);
CREATE INDEX IF NOT EXISTS ix_linux_endpoint_host_time
    ON linux_endpoint_records (host_id, event_time);
CREATE TABLE IF NOT EXISTS linux_endpoint_streams (
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
);
CREATE TABLE IF NOT EXISTS linux_endpoint_health (
    host_id     TEXT PRIMARY KEY,
    agent_id    TEXT NOT NULL,
    record_id   TEXT NOT NULL,
    event_time  TEXT NOT NULL,
    received_at TEXT NOT NULL,
    health_json TEXT NOT NULL
);
"""

MAX_MISSING_RANGES = 16


def ensure_schema(conn: sqlite3.Connection) -> None:
    conn.executescript(_SCHEMA)


class StoredRecord:
    """The fields of a validated record that storage and accounting need."""

    __slots__ = ("record_id", "sensor_id", "boot_id", "seq", "host_id", "record_type",
                 "type", "event_time", "digest", "raw", "health")

    def __init__(self, record: dict, digest: str, raw: str) -> None:
        self.record_id = record["id"]
        self.sensor_id = record["sensor"]["id"]
        self.boot_id = record["host"]["boot_id"]
        self.seq = record["seq"]
        self.host_id = record["host"]["id"]
        self.record_type = record["record_type"]
        self.type = record["type"]
        self.event_time = record["time"]
        self.digest = digest
        self.raw = raw
        self.health = record.get("health") if record["record_type"] == "health" else None


def _seqs_above(conn: sqlite3.Connection, agent_id: str, sensor_id: str, boot_id: str,
                floor: int):
    return conn.execute(
        "SELECT seq FROM linux_endpoint_records WHERE agent_id=? AND sensor_id=? AND boot_id=? "
        "AND seq > ? ORDER BY seq",
        (agent_id, sensor_id, boot_id, floor),
    )


def _missing_ranges(conn: sqlite3.Connection, agent_id: str, sensor_id: str, boot_id: str,
                    acked_through: int) -> list[list[int]]:
    ranges: list[list[int]] = []
    expected = acked_through + 1
    for row in _seqs_above(conn, agent_id, sensor_id, boot_id, acked_through):
        if row["seq"] > expected:
            ranges.append([expected, row["seq"] - 1])
            if len(ranges) >= MAX_MISSING_RANGES:
                break
        expected = row["seq"] + 1
    return ranges


def _insert(conn: sqlite3.Connection, agent_id: str, rec: StoredRecord, now: str) -> None:
    conn.execute(
        "INSERT INTO linux_endpoint_records (agent_id, record_id, sensor_id, boot_id, seq, "
        "host_id, record_type, type, event_time, ingested_at, digest, raw_json) "
        "VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
        (agent_id, rec.record_id, rec.sensor_id, rec.boot_id, rec.seq, rec.host_id,
         rec.record_type, rec.type, rec.event_time, now, rec.digest, rec.raw),
    )
    if rec.health is None:
        return
    conn.execute(
        "INSERT INTO linux_endpoint_health (host_id, agent_id, record_id, event_time, "
        "received_at, health_json) VALUES (?,?,?,?,?,?) "
        "ON CONFLICT(host_id) DO UPDATE SET agent_id=excluded.agent_id, "
        "record_id=excluded.record_id, event_time=excluded.event_time, "
        "received_at=excluded.received_at, health_json=excluded.health_json "
        "WHERE excluded.event_time >= linux_endpoint_health.event_time",
        (rec.host_id, agent_id, rec.record_id, rec.event_time, now,
         json.dumps(rec.health, separators=(",", ":"))),
    )


def _advance_stream(conn: sqlite3.Connection, agent_id: str, sensor_id: str, boot_id: str,
                    host_id: str, now: str) -> dict:
    bounds = conn.execute(
        "SELECT MIN(seq) AS lo, MAX(seq) AS hi, COUNT(*) AS n FROM linux_endpoint_records "
        "WHERE agent_id=? AND sensor_id=? AND boot_id=?",
        (agent_id, sensor_id, boot_id),
    ).fetchone()
    prior = conn.execute(
        "SELECT first_seq, acked_through FROM linux_endpoint_streams "
        "WHERE agent_id=? AND sensor_id=? AND boot_id=?",
        (agent_id, sensor_id, boot_id),
    ).fetchone()
    # The first record ever seen on a stream fixes where accounting starts, so a log that begins
    # above 1 (older records were acknowledged before this Manager existed) is not blamed for
    # records it never offered. A later arrival below that start moves the start down and re-opens
    # the prefix from there.
    first_seq = bounds["lo"] if prior is None else min(prior["first_seq"], bounds["lo"])
    acked = first_seq - 1 if prior is None else prior["acked_through"]
    if prior is not None and first_seq < prior["first_seq"]:
        acked = first_seq - 1
    for row in _seqs_above(conn, agent_id, sensor_id, boot_id, acked):
        if row["seq"] != acked + 1:
            break
        acked += 1
    conn.execute(
        "INSERT INTO linux_endpoint_streams (agent_id, sensor_id, boot_id, host_id, first_seq, "
        "highest_seq, acked_through, record_count, updated_at) VALUES (?,?,?,?,?,?,?,?,?) "
        "ON CONFLICT(agent_id, sensor_id, boot_id) DO UPDATE SET first_seq=excluded.first_seq, "
        "highest_seq=excluded.highest_seq, acked_through=excluded.acked_through, "
        "record_count=excluded.record_count, updated_at=excluded.updated_at",
        (agent_id, sensor_id, boot_id, host_id, first_seq, bounds["hi"], acked, bounds["n"], now),
    )
    return {
        "sensor_id": sensor_id,
        "boot_id": boot_id,
        "acked_through_seq": acked,
        "highest_seq": bounds["hi"],
        "missing_ranges": _missing_ranges(conn, agent_id, sensor_id, boot_id, acked),
    }


def store(conn: sqlite3.Connection, agent_id: str, records: list[StoredRecord], now: str) -> dict:
    """Insert ``records`` (already validated and bound to the agent) and return the accounting.

    Must run inside the caller's transaction. A record whose id already exists is a duplicate when
    its bytes are identical and a conflict when they are not; a different record claiming an
    occupied (stream, seq) slot is also a conflict. Conflicts are never overwritten.
    """
    accepted = duplicates = 0
    conflicts: list[str] = []
    touched: dict[tuple[str, str], str] = {}
    for rec in records:
        existing = conn.execute(
            "SELECT digest FROM linux_endpoint_records WHERE agent_id=? AND record_id=?",
            (agent_id, rec.record_id),
        ).fetchone()
        if existing is not None:
            if existing["digest"] == rec.digest:
                duplicates += 1
                # A pure retransmission still needs the current acknowledgement.
                touched[(rec.sensor_id, rec.boot_id)] = rec.host_id
            else:
                conflicts.append(rec.record_id)
            continue
        slot = conn.execute(
            "SELECT 1 FROM linux_endpoint_records "
            "WHERE agent_id=? AND sensor_id=? AND boot_id=? AND seq=?",
            (agent_id, rec.sensor_id, rec.boot_id, rec.seq),
        ).fetchone()
        if slot is not None:
            conflicts.append(rec.record_id)
            continue
        _insert(conn, agent_id, rec, now)
        accepted += 1
        touched[(rec.sensor_id, rec.boot_id)] = rec.host_id

    streams = [
        _advance_stream(conn, agent_id, sensor_id, boot_id, host_id, now)
        for (sensor_id, boot_id), host_id in touched.items()
    ]
    return {"accepted": accepted, "duplicates": duplicates, "conflicts": conflicts,
            "streams": streams}
