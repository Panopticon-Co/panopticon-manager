"""Agent enrollment and bearer-token verification primitives."""

from __future__ import annotations

import base64
import hashlib
import hmac
import logging
import os
import secrets
import sqlite3
from datetime import datetime, timedelta, timezone

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from fastapi import HTTPException

from manager import db
from manager.timeutil import iso_now

_log = logging.getLogger("manager.auth")

# Raw uncompressed NIST P-256 point: 0x04 || X (32 bytes) || Y (32 bytes).
_PUBLIC_KEY_RAW_LENGTH = 65
_NONCE_RAW_LENGTH = 32
_NONCE_TTL_SECONDS = 300


def _digest(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _iso(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%S.") + f"{dt.microsecond // 1000:03d}Z"


def _decode_b64(value: str, field: str) -> bytes:
    try:
        return base64.b64decode(value, validate=True)
    except Exception as exc:
        raise HTTPException(status_code=422, detail=f"{field} is not valid base64") from exc


def issue_enrollment_challenge() -> tuple[str, str]:
    """Mints a one-time, short-TTL nonce for enrollment proof-of-possession.
    Returns (nonce_b64, expires_at). The nonce is stored server-side and
    consumed exactly once by verify_and_consume_nonce -- this is the concrete
    defense against replaying a captured enrollment request indefinitely."""
    nonce_bytes = secrets.token_bytes(_NONCE_RAW_LENGTH)
    nonce_b64 = base64.b64encode(nonce_bytes).decode("ascii")
    now = datetime.now(timezone.utc)
    expires_at = _iso(now + timedelta(seconds=_NONCE_TTL_SECONDS))
    conn = db.connect()
    conn.execute("BEGIN IMMEDIATE")
    try:
        conn.execute(
            "INSERT INTO enrollment_nonces (nonce, created_at, expires_at, consumed_at) "
            "VALUES (?, ?, ?, NULL)",
            (nonce_b64, _iso(now), expires_at),
        )
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    return nonce_b64, expires_at


def _consume_nonce(conn: sqlite3.Connection, nonce_b64: str) -> None:
    """Atomically claims a nonce for use exactly once. Raises 401 if the
    nonce does not exist, is already consumed, or has expired -- all three
    are indistinguishable to the caller by design, so an attacker probing
    for "which nonces exist" learns nothing from the error alone."""
    now_iso = _iso(datetime.now(timezone.utc))
    row = conn.execute(
        "SELECT expires_at, consumed_at FROM enrollment_nonces WHERE nonce = ?", (nonce_b64,)
    ).fetchone()
    if row is None or row["consumed_at"] is not None or row["expires_at"] < now_iso:
        raise HTTPException(status_code=401, detail="invalid or expired enrollment challenge")
    updated = conn.execute(
        "UPDATE enrollment_nonces SET consumed_at = ? WHERE nonce = ? AND consumed_at IS NULL",
        (now_iso, nonce_b64),
    ).rowcount
    if updated != 1:
        # Lost a race with a concurrent consumer of the same nonce -- treat
        # exactly like "already consumed", never let two callers both win.
        raise HTTPException(status_code=401, detail="invalid or expired enrollment challenge")


def _verify_proof_of_possession(public_key_b64: str, nonce_b64: str, signature_b64: str) -> None:
    """Verifies that whoever sent this enrollment request holds the private
    key matching public_key_b64, by checking an ECDSA/P-256/SHA-256
    signature over the raw nonce bytes. Raises 401 on any failure (bad
    encoding, wrong curve, invalid point, signature mismatch) -- proof of
    possession is all-or-nothing, never partially trusted."""
    public_key_raw = _decode_b64(public_key_b64, "public_key")
    if len(public_key_raw) != _PUBLIC_KEY_RAW_LENGTH or public_key_raw[0:1] != b"\x04":
        raise HTTPException(
            status_code=401, detail="public_key must be an uncompressed P-256 point"
        )
    nonce_raw = _decode_b64(nonce_b64, "nonce")
    signature_raw = _decode_b64(signature_b64, "signature")
    try:
        public_key = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), public_key_raw)
        public_key.verify(signature_raw, nonce_raw, ec.ECDSA(hashes.SHA256()))
    except (InvalidSignature, ValueError) as exc:
        _log.warning("enrollment proof-of-possession failed: %s", type(exc).__name__)
        raise HTTPException(status_code=401, detail="invalid proof of possession") from exc


def enroll(
    agent_id: str,
    host_id: str,
    bootstrap_token: str,
    *,
    public_key: str,
    nonce: str,
    signature: str,
) -> str:
    """Provisions a brand-new agent_id only. ``INSERT`` (not ``INSERT OR
    REPLACE``) against ``agent_id``'s PRIMARY KEY deliberately rejects
    re-enrolling an agent_id that already has any row here -- live or
    revoked. The shared PANOPTICON_ENROLLMENT_TOKEN bootstrap secret is
    necessarily fleet-wide, so a version of this function that silently
    overwrote an existing agent_id's host_id/token_digest would let anyone
    holding that one shared secret hijack a specific, already-trusted
    agent's identity (rebinding it to an attacker-chosen host_id and minting
    themselves a fresh bearer token for it) with no audit trail
    distinguishing that from a first-time enrollment. There is currently no
    revoke-then-re-enroll flow; that is a separate, not-yet-built feature,
    not a reason to weaken this check.

    Phase 13 adds cryptographic proof of possession: the caller must supply
    a public_key it generated locally and a signature over a nonce this
    server issued moments ago via issue_enrollment_challenge(), proving it
    holds the matching private key. The bootstrap token alone is no longer
    sufficient to mint a working identity -- it authorizes *attempting*
    enrollment, the signature proves *which* key that identity is bound to.

    Also enforces host_id uniqueness among currently-active (non-revoked)
    agents: a bootstrap token holder could previously enroll an unrelated
    new agent_id claiming an already-trusted endpoint's host_id verbatim,
    since only agent_id had a uniqueness constraint. A revoked endpoint's
    host_id remains free for a legitimate re-image/re-enrollment.
    """
    expected = os.environ.get("PANOPTICON_ENROLLMENT_TOKEN")
    if not expected or not hmac.compare_digest(bootstrap_token, expected):
        raise HTTPException(status_code=401, detail="invalid enrollment credential")

    conn = db.connect()
    conn.execute("BEGIN IMMEDIATE")
    try:
        _consume_nonce(conn, nonce)
        _verify_proof_of_possession(public_key, nonce, signature)

        existing_host = conn.execute(
            "SELECT agent_id FROM enrolled_agents WHERE host_id = ? AND revoked_at IS NULL",
            (host_id,),
        ).fetchone()
        if existing_host is not None and existing_host["agent_id"] != agent_id:
            conn.rollback()
            raise HTTPException(
                status_code=409, detail="host_id is already claimed by an active agent"
            )

        token = secrets.token_urlsafe(32)
        conn.execute(
            "INSERT INTO enrolled_agents "
            "(agent_id, host_id, token_digest, enrolled_at, revoked_at, public_key) "
            "VALUES (?, ?, ?, ?, NULL, ?)",
            (agent_id, host_id, _digest(token), iso_now(), public_key),
        )
        conn.commit()
    except HTTPException:
        conn.rollback()
        raise
    except sqlite3.IntegrityError as exc:
        conn.rollback()
        raise HTTPException(status_code=409, detail="agent_id is already enrolled") from exc
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
