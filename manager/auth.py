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
            "INSERT OR REPLACE INTO enrolled_agents "
            "(agent_id, host_id, token_digest, enrolled_at, revoked_at) "
            "VALUES (?, ?, ?, ?, NULL)",
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
    row = (
        db.connect()
        .execute(
            "SELECT token_digest FROM enrolled_agents WHERE agent_id = ? AND revoked_at IS NULL",
            (agent_id,),
        )
        .fetchone()
    )
    if row is None or not hmac.compare_digest(str(row["token_digest"]), _digest(token)):
        raise HTTPException(status_code=401, detail="agent authentication required")


def enroll_analyst(analyst_id: str, bootstrap_token: str) -> str:
    """Same bootstrap-secret-gated pattern as enroll(), for a distinct
    identity space (analyst_credentials, not enrolled_agents) so an
    analyst's authorization actions in command_audit carry a real
    per-caller actor rather than the shared command-creation token."""
    expected = os.environ.get("PANOPTICON_ANALYST_ENROLLMENT_TOKEN")
    if not expected or not hmac.compare_digest(bootstrap_token, expected):
        raise HTTPException(status_code=401, detail="invalid analyst enrollment credential")
    token = secrets.token_urlsafe(32)
    conn = db.connect()
    conn.execute("BEGIN IMMEDIATE")
    try:
        conn.execute(
            "INSERT OR REPLACE INTO analyst_credentials "
            "(analyst_id, token_digest, created_at, revoked_at) VALUES (?, ?, ?, NULL)",
            (analyst_id, _digest(token), iso_now()),
        )
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    return token


def require_analyst_token(authorization: str | None) -> str:
    """Returns the authenticated analyst_id, so callers can record a real
    actor identity rather than a static string."""
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="analyst authentication required")
    token = authorization.removeprefix("Bearer ")
    if not token or len(token) > 512:
        raise HTTPException(status_code=401, detail="analyst authentication required")
    rows = db.connect().execute(
        "SELECT analyst_id, token_digest FROM analyst_credentials WHERE revoked_at IS NULL"
    ).fetchall()
    digest = _digest(token)
    for row in rows:
        if hmac.compare_digest(str(row["token_digest"]), digest):
            return str(row["analyst_id"])
    raise HTTPException(status_code=401, detail="analyst authentication required")
