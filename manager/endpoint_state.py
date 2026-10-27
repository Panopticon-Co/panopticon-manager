"""Canonical state ordering is proof-scoped, never selected by client clock.

Receipts are not freshness proofs. A latest-in-order projection may still be an
offline backlog. This module deliberately labels observation freshness unknown.
"""

from fastapi import HTTPException


def observe_generation(conn, record):
    generation = record.provenance.collector_generation
    if generation is None:
        return None
    agent = record.endpoint.agent_id
    installation = record.endpoint.installation_id
    epoch = record.provenance.collector_epoch
    existing = conn.execute(
        "SELECT collector_epoch FROM endpoint_generations "
        "WHERE agent_id=? AND installation_id=? AND generation=?",
        (agent, installation, generation),
    ).fetchone()
    if existing is not None and existing["collector_epoch"] != epoch:
        # Cloned/reset counters must not give a nondeterministic state authority.
        raise HTTPException(
            409, "collector generation fork; evidence retained without acknowledgment"
        )
    if existing is None:
        conn.execute(
            "INSERT INTO endpoint_generations VALUES (?,?,?,?)",
            (agent, installation, generation, epoch),
        )
    active = conn.execute(
        "SELECT * FROM endpoint_active_streams WHERE agent_id=?", (agent,)
    ).fetchone()
    if active is None:
        conn.execute(
            "INSERT INTO endpoint_active_streams VALUES (?,?,?,?)",
            (agent, installation, generation, epoch),
        )
    elif active["installation_id"] == installation and int(generation) > int(active["generation"]):
        conn.execute(
            "UPDATE endpoint_active_streams SET generation=?,collector_epoch=? WHERE agent_id=?",
            (generation, epoch, agent),
        )
    return conn.execute(
        "SELECT * FROM endpoint_active_streams WHERE agent_id=?", (agent,)
    ).fetchone()


def project_state(conn, record, line, active):
    if record.kind not in {"health", "state"}:
        return
    generation = record.provenance.collector_generation
    existing = conn.execute(
        "SELECT generation,sequence FROM endpoint_latest "
        "WHERE agent_id=? AND category=? AND kind=?",
        (record.endpoint.agent_id, record.category, record.kind),
    ).fetchone()
    if generation is None:
        if active is not None or (existing and existing["generation"] is not None):
            return  # Unordered legacy projection never displaces proved ordering.
    else:
        if (
            active["installation_id"] != record.endpoint.installation_id
            or active["generation"] != generation
        ):
            return  # Preserve history, but never reactivate an old/forked installation.
        if existing and existing["generation"] is not None:
            previous = (int(existing["generation"]), int(existing["sequence"]))
            incoming = (int(generation), int(record.provenance.sequence))
            if incoming <= previous:
                return
    conn.execute(
        "INSERT INTO endpoint_latest(agent_id,category,kind,observed_at,record_id,raw_json,"
        "installation_id,generation,collector_epoch,sequence) VALUES (?,?,?,?,?,?,?,?,?,?) "
        "ON CONFLICT(agent_id,category,kind) DO UPDATE SET observed_at=excluded.observed_at,"
        "record_id=excluded.record_id,raw_json=excluded.raw_json,installation_id=excluded.installation_id,"
        "generation=excluded.generation,collector_epoch=excluded.collector_epoch,sequence=excluded.sequence",
        (
            record.endpoint.agent_id,
            record.category,
            record.kind,
            record.observed_at,
            record.record_id,
            line,
            record.endpoint.installation_id,
            generation,
            record.provenance.collector_epoch,
            record.provenance.sequence,
        ),
    )


def projection_status(row, active):
    if row["generation"] is None:
        ordering = "unverified"
    elif active is None or row["installation_id"] != active["installation_id"]:
        ordering = "inactive_installation"
    elif (
        row["generation"] != active["generation"]
        or row["collector_epoch"] != active["collector_epoch"]
    ):
        ordering = "superseded"
    else:
        ordering = "current"
    return {
        "record_id": row["record_id"],
        "ordering": ordering,
        "observation_freshness": "unverified",
        "freshness_reason": "receipt is not a live observation proof",
    }
