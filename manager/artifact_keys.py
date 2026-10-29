"""Enrollment-bound historical artifact keys. Compromise flags never erase evidence."""

import base64
import hashlib
from datetime import datetime, timezone
from uuid import uuid4

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, utils
from fastapi import HTTPException
from response_engine.artifacts import ArtifactManifest, artifact_signing_input

from manager import audit_chain, command_signing
from manager.timeutil import iso_now


def server_time(value):
    # Python 3.10 does not accept RFC3339's Z suffix in fromisoformat().
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.utcoffset() is None:
        raise ValueError("artifact key timestamp requires a timezone")
    return parsed


def public_point(encoded):
    try:
        raw = base64.b64decode(encoded, validate=True)
        if len(raw) != 65 or raw[0] != 4:
            raise ValueError("not an uncompressed P-256 point")
        ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), raw)
        return raw
    except (ValueError, TypeError) as exc:
        raise ValueError("invalid artifact public key") from exc


def public_key_id(encoded):
    return command_signing.key_id(public_point(encoded))


def verify_signature(encoded_key, signature, data):
    try:
        raw = base64.b64decode(signature, validate=True)
        if len(raw) != 64:
            return False
        key = ec.EllipticCurvePublicKey.from_encoded_point(
            ec.SECP256R1(), public_point(encoded_key)
        )
        key.verify(
            utils.encode_dss_signature(
                int.from_bytes(raw[:32], "big"), int.from_bytes(raw[32:], "big")
            ),
            data,
            ec.ECDSA(hashes.SHA256()),
        )
        return True
    except (InvalidSignature, ValueError, TypeError):
        return False


def record(conn, event, actor, asset, request_id, detail):
    conn.execute(
        "INSERT INTO response_security_audit VALUES (?,?,?,?,?,?,?)",
        (str(uuid4()), request_id, asset, event, actor, audit_chain.canonical(detail), iso_now()),
    )


def current(conn, agent_id):
    return conn.execute(
        """SELECT k.* FROM artifact_signing_keys k JOIN enrolled_agents e
        ON e.agent_id=k.agent_id AND e.host_id=k.host_id AND e.revoked_at IS NULL
        WHERE k.agent_id=? AND k.retired_at IS NULL AND k.compromised_at IS NULL
        ORDER BY k.key_version DESC LIMIT 1""",
        (agent_id,),
    ).fetchone()


def rotation_input(*, agent_id, host_id, request_id, nonce, expires_at, old_key_id, new_public_key):
    fields = {
        "agent_id": agent_id,
        "host_id": host_id,
        "request_id": request_id,
        "nonce": nonce,
        "expires_at": expires_at,
        "old_key_id": old_key_id,
        "new_key_id": public_key_id(new_public_key),
        "new_public_key": new_public_key,
    }
    result = bytearray(b"panopticon-artifact-key-rotation/1\n")
    for name, value in fields.items():
        data = value.encode()
        result.extend(name.encode() + b":" + str(len(data)).encode() + b":" + data + b"\n")
    return bytes(result)


def request_rotation(conn, agent_id, request):
    digest = hashlib.sha256(audit_chain.canonical(request).encode()).hexdigest()
    prior = conn.execute(
        "SELECT * FROM artifact_key_rotations WHERE agent_id=? AND request_id=?",
        (agent_id, request["request_id"]),
    ).fetchone()
    if prior:
        if prior["payload_digest"] != digest:
            raise HTTPException(409, "rotation retry identity binds another request")
        return {"request_id": prior["request_id"], "state": prior["state"], "replayed": True}
    old = current(conn, agent_id)
    if old is None or old["key_id"] != request["old_key_id"]:
        raise HTTPException(409, "no matching active artifact key")
    try:
        new_id = public_key_id(request["new_public_key"])
    except ValueError as exc:
        raise HTTPException(422, "invalid new artifact public key") from exc
    if conn.execute(
        "SELECT 1 FROM artifact_signing_keys WHERE agent_id=? AND key_id=?", (agent_id, new_id)
    ).fetchone():
        raise HTTPException(409, "historical artifact keys cannot be reactivated")
    nonce = conn.execute(
        "SELECT expires_at,consumed_at FROM enrollment_nonces WHERE nonce=?", (request["nonce"],)
    ).fetchone()
    if (
        nonce is None
        or nonce["consumed_at"] is not None
        or server_time(nonce["expires_at"]) <= datetime.now(timezone.utc)
    ):
        raise HTTPException(401, "invalid rotation challenge")
    encoded = rotation_input(
        agent_id=agent_id,
        host_id=old["host_id"],
        request_id=request["request_id"],
        nonce=request["nonce"],
        expires_at=nonce["expires_at"],
        old_key_id=old["key_id"],
        new_public_key=request["new_public_key"],
    )
    if not (
        verify_signature(old["public_key"], request["old_signature"], encoded)
        and verify_signature(request["new_public_key"], request["new_signature"], encoded)
    ):
        raise HTTPException(403, "rotation requires proof of old and new private keys")
    conn.execute(
        "UPDATE enrollment_nonces SET consumed_at=? WHERE nonce=?", (iso_now(), request["nonce"])
    )
    conn.execute(
        """INSERT INTO artifact_key_rotations
        (agent_id,request_id,old_key_id,new_key_id,new_public_key,payload_digest,state,created_at,expires_at)
        VALUES (?,?,?,?,?,?,'PENDING',?,?)""",
        (
            agent_id,
            request["request_id"],
            old["key_id"],
            new_id,
            request["new_public_key"],
            digest,
            iso_now(),
            nonce["expires_at"],
        ),
    )
    record(
        conn,
        "artifact_key_rotation_requested",
        "agent:" + agent_id,
        old["host_id"],
        request["request_id"],
        {"old_key_id": old["key_id"], "new_key_id": new_id},
    )
    return {"request_id": request["request_id"], "state": "PENDING", "replayed": False}


def approve_rotation(conn, agent_id, request_id, actor):
    row = conn.execute(
        "SELECT * FROM artifact_key_rotations WHERE agent_id=? AND request_id=?",
        (agent_id, request_id),
    ).fetchone()
    if row is None:
        raise HTTPException(404, "artifact key rotation unavailable")
    if row["state"] == "APPROVED":
        return {"request_id": request_id, "state": "APPROVED", "replayed": True}
    if server_time(row["expires_at"]) <= datetime.now(timezone.utc):
        raise HTTPException(409, "artifact key rotation approval window expired")
    old = current(conn, agent_id)
    if old is None or old["key_id"] != row["old_key_id"]:
        raise HTTPException(409, "artifact key binding changed before approval")
    now = iso_now()
    conn.execute(
        "UPDATE artifact_signing_keys SET retired_at=? WHERE agent_id=? AND key_id=?",
        (now, agent_id, old["key_id"]),
    )
    conn.execute(
        "INSERT INTO artifact_signing_keys "
        "(agent_id,host_id,key_id,key_version,public_key,valid_from) VALUES (?,?,?,?,?,?)",
        (
            agent_id,
            old["host_id"],
            row["new_key_id"],
            old["key_version"] + 1,
            row["new_public_key"],
            now,
        ),
    )
    conn.execute(
        "UPDATE artifact_key_rotations SET state='APPROVED',approved_by=?,approved_at=? "
        "WHERE agent_id=? AND request_id=?",
        (actor, now, agent_id, request_id),
    )
    record(
        conn,
        "artifact_key_rotation_approved",
        actor,
        old["host_id"],
        request_id,
        {"old_key_id": old["key_id"], "new_key_id": row["new_key_id"]},
    )
    return {"request_id": request_id, "state": "APPROVED", "replayed": False}


def verify_manifest(conn, agent_id, manifest, *, admitted_at=None):
    """Retired keys only finish sessions admitted before retirement. Compromised keys never do."""
    value = ArtifactManifest.model_validate(manifest)
    if value.agent_id != agent_id:
        raise HTTPException(403, "artifact signing agent disagrees")
    key = conn.execute(
        """SELECT k.*,e.revoked_at FROM artifact_signing_keys k
        JOIN enrolled_agents e ON e.agent_id=k.agent_id AND e.host_id=k.host_id
        WHERE k.agent_id=? AND k.key_id=?""",
        (agent_id, value.authorization.key_id),
    ).fetchone()
    if key is None or key["host_id"] != value.host_id:
        raise HTTPException(403, "artifact signer is not enrolled for this endpoint")
    if key["revoked_at"] is not None or key["compromised_at"] is not None:
        raise HTTPException(403, "artifact signing identity is revoked or compromised")
    if key["retired_at"] is not None and (
        admitted_at is None
        or server_time(admitted_at) > server_time(key["retired_at"])
    ):
        raise HTTPException(403, "retired key cannot admit a new artifact transfer")
    try:
        signing_bytes = artifact_signing_input(manifest)
    except ValueError as exc:
        raise HTTPException(422, "artifact manifest has invalid UTF-8 signing fields") from exc
    if not verify_signature(key["public_key"], value.authorization.signature, signing_bytes):
        raise HTTPException(422, "artifact manifest signature disagrees")
    return dict(key)


def key_status(row):
    return (
        "compromised_key"
        if row["compromised_at"]
        else "retired_key"
        if row["retired_at"]
        else "active_key"
    )


def retained_status(conn, artifact_id):
    row = conn.execute(
        """SELECT a.key_id,a.key_version,a.verified_at,k.public_key,
        k.retired_at,k.compromised_at,k.compromise_reason FROM artifact_manifest_attestations a
        JOIN artifact_signing_keys k ON k.agent_id=a.agent_id AND k.key_id=a.key_id
        WHERE a.artifact_id=?""",
        (artifact_id,),
    ).fetchone()
    return (
        {**dict(row), "trust_status": key_status(row), "signature_state": "verified_at_ingest"}
        if row
        else {"trust_status": "unsigned_legacy", "signature_state": "unverified"}
    )
