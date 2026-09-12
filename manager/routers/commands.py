"""Closed, authenticated endpoint command queue. No arbitrary execution fields exist."""

from __future__ import annotations

import hmac
import json
import os
import sqlite3
from datetime import datetime, timezone
from typing import Literal
from uuid import uuid4

from fastapi import APIRouter, Header, HTTPException
from pydantic import BaseModel, ConfigDict, Field, model_validator

from manager import db
from manager.auth import require_agent_token
from manager.timeutil import iso_now

router = APIRouter()
Action = Literal[
    "KILL_PROCESS",
    "COLLECT_PROCESS_INFO",
    "COLLECT_NETWORK_CONNECTIONS",
    "COLLECT_FILE",
    "QUARANTINE_FILE",
    "ISOLATE_HOST",
    "RELEASE_HOST_ISOLATION",
]


class Command(BaseModel):
    model_config = ConfigDict(extra="forbid")
    command_id: str = Field(min_length=1, max_length=128)
    agent_id: str = Field(min_length=1, max_length=128)
    action: Action
    expires_at: datetime
    target: dict = Field(default_factory=dict, max_length=16)
    correlation_id: str = Field(default_factory=lambda: str(uuid4()), min_length=1, max_length=128)

    @model_validator(mode="after")
    def enforce_closed_target_schema(self) -> "Command":
        process_actions = {"KILL_PROCESS", "COLLECT_PROCESS_INFO"}
        file_actions = {"COLLECT_FILE", "QUARANTINE_FILE"}
        if self.action in process_actions:
            if set(self.target) != {"pid", "start_time_ticks"}:
                raise ValueError("process action target must contain only pid and start_time_ticks")
            if not all(
                isinstance(self.target[key], int)
                and not isinstance(self.target[key], bool)
                and self.target[key] > 0
                for key in ("pid", "start_time_ticks")
            ):
                raise ValueError("process action target values must be positive integers")
        elif self.action in file_actions:
            if set(self.target) != {"path"} or not isinstance(self.target["path"], str):
                raise ValueError("file action target must contain only a path")
            if not self.target["path"] or len(self.target["path"]) > 4096:
                raise ValueError("file action path is invalid")
        elif self.target:
            raise ValueError("this action does not accept a target")
        return self


def _audit(conn, command_id: str, event: str, actor: str, detail: str | None = None) -> None:
    conn.execute(
        "INSERT INTO command_audit (audit_id, command_id, event, actor, detail, occurred_at) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        (str(uuid4()), command_id, event, actor, detail, iso_now()),
    )


class CommandResult(BaseModel):
    model_config = ConfigDict(extra="forbid")
    result_id: str = Field(min_length=1, max_length=128)
    command_id: str = Field(min_length=1, max_length=128)
    outcome: Literal["succeeded", "rejected", "failed"]
    detail: str | None = Field(default=None, max_length=512)
    correlation_id: str | None = Field(default=None, min_length=1, max_length=128)


@router.post("/api/v1/commands")
async def enqueue(command: Command, x_panopticon_command_token: str = Header(...)) -> dict:
    expected = os.environ.get("PANOPTICON_COMMAND_TOKEN")
    if not expected or not hmac.compare_digest(expected, x_panopticon_command_token):
        raise HTTPException(status_code=401, detail="command authorization required")
    if command.expires_at <= datetime.now(command.expires_at.tzinfo):
        raise HTTPException(status_code=422, detail="command expired")
    conn = db.connect()
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
    conn.execute("BEGIN IMMEDIATE")
    try:
        conn.execute(
            "INSERT INTO commands (command_id, agent_id, command_json, created_at, expires_at) "
            "VALUES (?, ?, ?, ?, ?)",
            (
                command.command_id,
                command.agent_id,
                json.dumps(payload, separators=(",", ":")),
                iso_now(),
                command.expires_at.isoformat(),
            ),
        )
        _audit(conn, command.command_id, "created", "system:command-token")
        conn.commit()
    except sqlite3.IntegrityError:
        conn.rollback()
        raise HTTPException(status_code=409, detail="command_id already exists")
    except Exception:
        conn.rollback()
        raise
    return {"command_id": command.command_id, "queued": True}


@router.get("/api/v1/agents/{agent_id}/commands")
async def poll(agent_id: str, authorization: str | None = Header(default=None)) -> dict:
    require_agent_token(agent_id, authorization)
    conn = db.connect()
    now = datetime.now(timezone.utc).isoformat()
    conn.execute("BEGIN IMMEDIATE")
    try:
        rows = conn.execute(
            "SELECT command_id, command_json FROM commands WHERE agent_id = ? "
            "AND delivered_at IS NULL AND expires_at > ? ORDER BY created_at LIMIT 32",
            (agent_id, now),
        ).fetchall()
        for row in rows:
            conn.execute(
                "UPDATE commands SET delivered_at = ? WHERE command_id = ?",
                (now, row["command_id"]),
            )
            _audit(conn, str(row["command_id"]), "dispatched", f"agent:{agent_id}")
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    return {"commands": [json.loads(str(row["command_json"])) for row in rows]}


@router.post("/api/v1/agents/{agent_id}/command-results")
async def submit_result(
    agent_id: str, result: CommandResult, authorization: str | None = Header(default=None)
) -> dict:
    require_agent_token(agent_id, authorization)
    conn = db.connect()
    command = conn.execute(
        "SELECT agent_id, command_json, expires_at FROM commands WHERE command_id = ?",
        (result.command_id,),
    ).fetchone()
    if command is None or str(command["agent_id"]) != agent_id:
        raise HTTPException(status_code=422, detail="command does not belong to agent")
    expires_at = datetime.fromisoformat(str(command["expires_at"]))
    if expires_at <= datetime.now(expires_at.tzinfo):
        raise HTTPException(status_code=422, detail="command expired")
    queued = json.loads(str(command["command_json"]))
    if result.correlation_id is not None and result.correlation_id != queued.get("correlation_id"):
        raise HTTPException(status_code=422, detail="result correlation does not match command")
    conn.execute(
        "INSERT OR IGNORE INTO command_results "
        "(result_id, command_id, agent_id, outcome, detail, received_at) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        (result.result_id, result.command_id, agent_id, result.outcome, result.detail, iso_now()),
    )
    _audit(conn, result.command_id, "result_received", f"agent:{agent_id}", result.outcome)
    conn.commit()
    return {"result_id": result.result_id, "accepted": True}
