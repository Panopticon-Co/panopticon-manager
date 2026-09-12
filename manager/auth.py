"""Agent enrollment and bearer-token verification primitives."""

from __future__ import annotations

import hashlib
import hmac
import os
import secrets

from fastapi import HTTPException

from manager import db
from manager.timeutil import iso_now


def _digest(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def enroll(agent_id: str, host_id: str, bootstrap_token: str) -> str:
    expected = os.environ.get("PANOPTICON_ENROLLMENT_TOKEN")
    if not expected or not hmac.compare_digest(bootstrap_token, expected):
        raise HTTPException(status_code=401, detail="invalid enrollment credential")
    token = secrets.token_urlsafe(32)
    conn = db.connect()
    conn.execute("BEGIN IMMEDIATE")
    try:
        conn.execute(
            "INSERT OR REPLACE INTO enrolled_agents (agent_id, host_id, token_digest, enrolled_at, revoked_at) VALUES (?, ?, ?, ?, NULL)",
            (agent_id, host_id, _digest(token), iso_now()),
        )
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    return token


def require_agent_token(agent_id: str, authorization: str | None) -> None:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="agent authentication required")
    token = authorization.removeprefix("Bearer ")
    if not token or len(token) > 512:
        raise HTTPException(status_code=401, detail="agent authentication required")
    row = db.connect().execute(
        "SELECT token_digest FROM enrolled_agents WHERE agent_id = ? AND revoked_at IS NULL", (agent_id,)
    ).fetchone()
    if row is None or not hmac.compare_digest(str(row["token_digest"]), _digest(token)):
        raise HTTPException(status_code=401, detail="agent authentication required")
