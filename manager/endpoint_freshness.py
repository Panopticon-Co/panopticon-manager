"""Bounded authenticated capture age, independent of wall clocks.

This proves recent capture according to the authenticated endpoint, not truthful
sensor coverage, native event age, hardware attestation or a durable live lease.
Process-scoped clocks deliberately become unverified across Manager restarts.
"""

import hashlib
import json
import os
import re
import secrets
import time

from fastapi import HTTPException

SERVER_EPOCH = secrets.token_hex(32)
CHALLENGE_NS = 15_000_000_000
FRESH_MS = 90_000
CLOCK_GUARD_MS = (
    100  # Conservative tick quantization allowance; OS matrix still needs qualification.
)

_uptime = None
if os.name == "nt":
    import ctypes

    _uptime = ctypes.WinDLL("kernel32", use_last_error=True).GetTickCount64
    _uptime.argtypes = []
    _uptime.restype = ctypes.c_uint64


def clock_ns():
    """Elapsed time including suspend; unsupported platforms cannot bless age."""
    if _uptime is not None:
        return int(_uptime()) * 1_000_000
    if hasattr(time, "CLOCK_BOOTTIME"):
        try:
            return time.clock_gettime_ns(time.CLOCK_BOOTTIME)
        except OSError:
            return None
    return None


def issue(conn, agent_id):
    nonce = secrets.token_hex(32)
    issued = clock_ns()
    if issued is None:
        raise HTTPException(
            503, "suspend-aware freshness clock unavailable; telemetry remains supported"
        )
    conn.execute("BEGIN IMMEDIATE")
    try:
        conn.execute(
            "INSERT INTO endpoint_freshness_challenges VALUES (?,?,?,?,0) "
            "ON CONFLICT(agent_id) DO UPDATE SET nonce_digest=excluded.nonce_digest,"
            "server_epoch=excluded.server_epoch,issued_ns=excluded.issued_ns,consumed=0",
            (agent_id, hashlib.sha256(nonce.encode()).hexdigest(), SERVER_EPOCH, str(issued)),
        )
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    return {"nonce": nonce, "valid_for_ms": CHALLENGE_NS // 1_000_000}


def consume(conn, agent_id, nonce, context_text):
    if (
        not nonce
        or not re.fullmatch(r"[0-9a-f]{64}", nonce)
        or not context_text
        or len(context_text) > 2048
    ):
        return None
    # A malformed optional proof cannot poison the telemetry batch or upgrade
    # unknown age into freshness. Exactly one challenge is retained per agent.
    try:

        def unique_pairs(values):
            result = {}
            for key, value in values:
                if key in result:
                    raise ValueError("duplicate capture context key")
                result[key] = value
            return result

        context = json.loads(context_text, object_pairs_hook=unique_pairs)
        if not isinstance(context, dict) or set(context) != {
            "installation_id",
            "boot_id",
            "collector_generation",
            "collector_epoch",
            "send_uptime_ms",
        }:
            return None
        for field in ("collector_generation", "send_uptime_ms"):
            if not isinstance(context[field], str) or not re.fullmatch(
                r"0|[1-9][0-9]{0,19}", context[field]
            ):
                return None
            if int(context[field]) > 2**64 - 1:
                return None
        if not isinstance(context["boot_id"], str) or not re.fullmatch(
            r"boot_[0-9a-f]{64}", context["boot_id"]
        ):
            return None
        if not isinstance(context["installation_id"], str) or not re.fullmatch(
            r"[0-9a-f]{64}", context["installation_id"]
        ):
            return None
        if not isinstance(context["collector_epoch"], str) or not re.fullmatch(
            r"epoch_[0-9a-f]{64}", context["collector_epoch"]
        ):
            return None
    except (ValueError, TypeError, RecursionError):
        return None
    row = conn.execute(
        "SELECT * FROM endpoint_freshness_challenges WHERE agent_id=?", (agent_id,)
    ).fetchone()
    now = clock_ns()
    if now is None:
        return None
    if (
        row is None
        or row["consumed"]
        or row["server_epoch"] != SERVER_EPOCH
        or row["nonce_digest"] != hashlib.sha256(nonce.encode()).hexdigest()
    ):
        return None
    elapsed = now - int(row["issued_ns"])
    if not 0 <= elapsed <= CHALLENGE_NS:
        return None
    conn.execute(
        "UPDATE endpoint_freshness_challenges SET consumed=1 WHERE agent_id=?", (agent_id,)
    )
    return {**context, "elapsed_ms": (elapsed + 999_999) // 1_000_000, "received_ns": now}


def record_age(conn, record, proof):
    provenance = record.provenance
    if (
        proof is None
        or provenance.capture_clock != "windows_uptime_ms"
        or provenance.capture_uptime_ms is None
    ):
        return
    if (
        record.endpoint.installation_id != proof["installation_id"]
        or record.endpoint.boot_id != proof["boot_id"]
        or provenance.collector_generation != proof["collector_generation"]
        or provenance.collector_epoch != proof["collector_epoch"]
    ):
        return
    delta = int(proof["send_uptime_ms"]) - int(provenance.capture_uptime_ms)
    upper = delta + proof["elapsed_ms"] + CLOCK_GUARD_MS
    if delta < 0 or upper > 2**64 - 1:
        return
    inserted = conn.execute(
        "INSERT OR IGNORE INTO endpoint_capture_age VALUES (?,?,?,?,?)",
        (
            record.endpoint.agent_id,
            record.record_id,
            SERVER_EPOCH,
            str(proof["received_ns"]),
            str(upper),
        ),
    )
    return inserted.rowcount == 1


def status(conn, agent_id, record_id):
    row = conn.execute(
        "SELECT * FROM endpoint_capture_age WHERE agent_id=? AND record_id=?", (agent_id, record_id)
    ).fetchone()
    result = {
        "capture_freshness": "unverified",
        "capture_age_upper_bound_ms": None,
        "capture_age_provenance": "no valid one-use boot-scoped endpoint proof",
    }
    if row is None or row["server_epoch"] != SERVER_EPOCH:
        return result
    now = clock_ns()
    if now is None:
        return result
    elapsed = now - int(row["received_ns"])
    if elapsed < 0:
        return result
    age = int(row["age_upper_bound_ms"]) + (elapsed + 999_999) // 1_000_000
    return {
        "capture_freshness": "fresh" if age <= FRESH_MS else "stale",
        "capture_age_upper_bound_ms": str(age),
        "capture_age_provenance": "authenticated endpoint report and one-use server challenge",
    }
