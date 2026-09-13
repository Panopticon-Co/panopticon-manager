"""Closed, authenticated endpoint command queue. No arbitrary execution fields exist.

The closed action enum and the Command/CommandResult typed contract
(including per-action target-schema validation) are no longer defined here
-- they are owned by the vendored panopticon-response-engine package (see
docs/adr/006-response-engine-package-extraction.md) and just re-exported
from this module so existing imports (``from manager.routers.commands import
Command``) keep working unchanged."""

from __future__ import annotations

import hmac
import json
import os
import sqlite3
from datetime import datetime, timezone
from uuid import uuid4

from fastapi import APIRouter, Header, HTTPException
from response_engine.contract import Action, Command, CommandResult

from manager import db
from manager.auth import require_agent_token
from manager.timeutil import iso_now

router = APIRouter()

__all__ = [
    "Action",
    "Command",
    "CommandResult",
    "accept",
    "authorize_and_enqueue",
    "enqueue",
    "poll",
    "router",
    "submit_result",
]


def _audit(conn, command_id: str, event: str, actor: str, detail: str | None = None) -> None:
    conn.execute(
        "INSERT INTO command_audit (audit_id, command_id, event, actor, detail, occurred_at) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        (str(uuid4()), command_id, event, actor, detail, iso_now()),
    )


def authorize_and_enqueue(
    conn, command: "Command", actor: str, alert_id: str | None = None
) -> None:
    """Shared path for both the raw POST /api/v1/commands endpoint and the
    Response Engine (manager/detection/response.py) -- one place validates
    the target agent, writes the commands row, and audits creation, so the
    two callers can never drift into different behavior. Raises
    HTTPException on any rejection; callers propagate it as-is.

    Manages its own BEGIN IMMEDIATE/commit/rollback only when called
    top-level (conn.in_transaction is False) -- e.g. the raw endpoint below,
    or an analyst-authorize request. When called from inside an
    already-open transaction (the automatic AUTO_SAFE path, invoked from
    manager/detection/worker.py's per-event transaction), it just executes
    as part of that ambient transaction and leaves commit/rollback to the
    caller, since sqlite3 does not support nested transactions.
    """
    if command.expires_at <= datetime.now(command.expires_at.tzinfo):
        raise HTTPException(status_code=422, detail="command expired")
    enrolled = conn.execute(
        "SELECT host_id FROM enrolled_agents WHERE agent_id = ? AND revoked_at IS NULL",
        (command.agent_id,),
    ).fetchone()
    if enrolled is None:
        raise HTTPException(status_code=422, detail="target agent is not enrolled")
    payload = command.model_dump(mode="json")
    payload.update(
        {
            "schema_version": "1",
            "host_id": str(enrolled["host_id"]),
            "created_at": datetime.now(timezone.utc).isoformat(),
        }
    )
    owns_transaction = not conn.in_transaction
    if owns_transaction:
        conn.execute("BEGIN IMMEDIATE")
    try:
        conn.execute(
            "INSERT INTO commands (command_id, agent_id, command_json, created_at, "
            "expires_at, alert_id, lifecycle_state) VALUES (?, ?, ?, ?, ?, ?, 'AUTHORIZED')",
            (
                command.command_id,
                command.agent_id,
                json.dumps(payload, separators=(",", ":")),
                iso_now(),
                command.expires_at.isoformat(),
                alert_id,
            ),
        )
        _audit(conn, command.command_id, "created", actor)
        if owns_transaction:
            conn.commit()
    except sqlite3.IntegrityError:
        if owns_transaction:
            conn.rollback()
        raise HTTPException(status_code=409, detail="command_id already exists")
    except Exception:
        if owns_transaction:
            conn.rollback()
        raise


@router.post("/api/v1/commands")
async def enqueue(command: Command, x_panopticon_command_token: str = Header(...)) -> dict:
    expected = os.environ.get("PANOPTICON_COMMAND_TOKEN")
    if not expected or not hmac.compare_digest(expected, x_panopticon_command_token):
        raise HTTPException(status_code=401, detail="command authorization required")
    authorize_and_enqueue(db.connect(), command, "system:command-token")
    return {"command_id": command.command_id, "queued": True}


_OPEN_LIFECYCLE_STATES = ("PENDING", "AUTHORIZED", "DISPATCHED", "ACCEPTED")


def _expire_stale_commands(conn: sqlite3.Connection, now: str) -> None:
    """Flips any commands.lifecycle_state still PENDING/AUTHORIZED/DISPATCHED
    past their expires_at to EXPIRED. Without this, an unpolled or
    unanswered command simply becomes unpollable/unresultable forever with
    no lifecycle record of why -- callers run this inline on read paths
    (poll, result submission) rather than via a separate scheduler, since
    Manager has no background-job infrastructure and none is justified for
    this. Must run inside the caller's already-open transaction."""
    placeholders = ", ".join("?" for _ in _OPEN_LIFECYCLE_STATES)
    rows = conn.execute(
        f"SELECT command_id FROM commands WHERE lifecycle_state IN ({placeholders}) "
        "AND expires_at <= ?",
        (*_OPEN_LIFECYCLE_STATES, now),
    ).fetchall()
    for row in rows:
        conn.execute(
            "UPDATE commands SET lifecycle_state = 'EXPIRED' WHERE command_id = ?",
            (row["command_id"],),
        )
        _audit(conn, str(row["command_id"]), "expired", "system:expiry-sweep")


@router.get("/api/v1/agents/{agent_id}/commands")
async def poll(agent_id: str, authorization: str | None = Header(default=None)) -> dict:
    require_agent_token(agent_id, authorization)
    conn = db.connect()
    now = datetime.now(timezone.utc).isoformat()
    conn.execute("BEGIN IMMEDIATE")
    try:
        _expire_stale_commands(conn, now)
        rows = conn.execute(
            "SELECT command_id, command_json FROM commands WHERE agent_id = ? "
            "AND delivered_at IS NULL AND expires_at > ? ORDER BY created_at LIMIT 32",
            (agent_id, now),
        ).fetchall()
        for row in rows:
            conn.execute(
                "UPDATE commands SET delivered_at = ?, lifecycle_state = 'DISPATCHED' "
                "WHERE command_id = ?",
                (now, row["command_id"]),
            )
            _audit(conn, str(row["command_id"]), "dispatched", f"agent:{agent_id}")
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    return {"commands": [json.loads(str(row["command_json"])) for row in rows]}


@router.post("/api/v1/agents/{agent_id}/commands/{command_id}/accept")
async def accept(
    agent_id: str, command_id: str, authorization: str | None = Header(default=None)
) -> dict:
    """DISPATCHED -> ACCEPTED: the endpoint has received and validated the
    command and is about to execute it, but has not yet finished. This is
    optional acknowledgement, not a second incompatible protocol -- an agent
    that never calls this (e.g. one that only implements the original
    poll/result exchange) can still submit a result directly from
    DISPATCHED; submit_result() below accepts a result from either DISPATCHED
    or ACCEPTED. Idempotent: accepting an already-ACCEPTED command, or one
    that has already reached a terminal state (raced with expiry, or a
    result already landed), is a no-op success rather than an error, so a
    retrying agent never gets stuck on a 4xx it can't resolve."""
    require_agent_token(agent_id, authorization)
    conn = db.connect()
    now = datetime.now(timezone.utc).isoformat()
    conn.execute("BEGIN IMMEDIATE")
    try:
        _expire_stale_commands(conn, now)
        command = conn.execute(
            "SELECT agent_id, lifecycle_state FROM commands WHERE command_id = ?",
            (command_id,),
        ).fetchone()
        if command is None or str(command["agent_id"]) != agent_id:
            raise HTTPException(status_code=422, detail="command does not belong to agent")
        if command["lifecycle_state"] == "DISPATCHED":
            conn.execute(
                "UPDATE commands SET lifecycle_state = 'ACCEPTED' WHERE command_id = ?",
                (command_id,),
            )
            _audit(conn, command_id, "accepted", f"agent:{agent_id}")
        conn.commit()
    except HTTPException:
        conn.rollback()
        raise
    except Exception:
        conn.rollback()
        raise
    return {"command_id": command_id, "accepted": True}


@router.post("/api/v1/agents/{agent_id}/command-results")
async def submit_result(
    agent_id: str, result: CommandResult, authorization: str | None = Header(default=None)
) -> dict:
    require_agent_token(agent_id, authorization)
    conn = db.connect()
    now = datetime.now(timezone.utc).isoformat()
    conn.execute("BEGIN IMMEDIATE")
    try:
        _expire_stale_commands(conn, now)
        command = conn.execute(
            "SELECT agent_id, command_json, expires_at, lifecycle_state FROM commands "
            "WHERE command_id = ?",
            (result.command_id,),
        ).fetchone()
        if command is None or str(command["agent_id"]) != agent_id:
            raise HTTPException(status_code=422, detail="command does not belong to agent")
        expires_at = datetime.fromisoformat(str(command["expires_at"]))
        if expires_at <= datetime.now(expires_at.tzinfo):
            raise HTTPException(status_code=422, detail="command expired")
        queued = json.loads(str(command["command_json"]))
        if (
            result.correlation_id is not None
            and result.correlation_id != queued.get("correlation_id")
        ):
            raise HTTPException(status_code=422, detail="result correlation does not match command")
        # A command accepts exactly one outcome. A result is legal from either
        # DISPATCHED (no explicit accept/ack call) or ACCEPTED (the agent
        # acknowledged receipt first via accept() above) -- both represent
        # "the agent has this command and hasn't reported an outcome yet".
        # Once lifecycle_state has left both (a first result already landed,
        # or the sweep above just expired it), a second, differently-
        # result_id'd submission must never flip the state again -- that
        # would let a duplicate or replayed result overwrite a real terminal
        # outcome. The submission is still accepted/audited (so a
        # misbehaving or retrying agent gets a normal 200, not an error it
        # might retry-loop on) but never mutates state.
        if command["lifecycle_state"] not in ("DISPATCHED", "ACCEPTED"):
            _audit(
                conn,
                result.command_id,
                "duplicate_result_ignored",
                f"agent:{agent_id}",
                result.outcome,
            )
            conn.commit()
            return {"result_id": result.result_id, "accepted": True}
        inserted = conn.execute(
            "INSERT OR IGNORE INTO command_results "
            "(result_id, command_id, agent_id, outcome, detail, received_at) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (
                result.result_id,
                result.command_id,
                agent_id,
                result.outcome,
                result.detail,
                iso_now(),
            ),
        ).rowcount
        if inserted:
            final_state = {
                "succeeded": "SUCCEEDED",
                "failed": "FAILED",
                "rejected": "REJECTED",
            }[result.outcome]
            conn.execute(
                "UPDATE commands SET lifecycle_state = ? WHERE command_id = ?",
                (final_state, result.command_id),
            )
        _audit(conn, result.command_id, "result_received", f"agent:{agent_id}", result.outcome)
        conn.commit()
    except HTTPException:
        conn.rollback()
        raise
    except Exception:
        conn.rollback()
        raise
    return {"result_id": result.result_id, "accepted": True}
