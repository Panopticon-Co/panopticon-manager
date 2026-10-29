"""Artifact access policy 1: role eligibility AND exact live credential/case/host grant."""

import hashlib
import json
from uuid import uuid4

from fastapi import HTTPException
from response_engine.access import AnalystPermission, permissions_for

from manager.artifact_keys import record
from manager.auth import require_analyst_permission
from manager.response_artifacts import canonical
from manager.timeutil import iso_now

POLICY_VERSION = 1
PUBLIC_COLUMNS = (
    "grant_id,analyst_id,host_id,alert_id,policy_version,granted_by,reason,created_at,"
    "revoked_at,revoked_by,revoke_reason"
)


def can_read(conn, analyst_id, host_id, alert_id):
    if not analyst_id or not host_id or not alert_id:
        return False
    identity = conn.execute(
        "SELECT role,token_digest FROM analyst_credentials "
        "WHERE analyst_id=? AND revoked_at IS NULL",
        (analyst_id,),
    ).fetchone()
    return bool(
        identity is not None
        and AnalystPermission.ARTIFACT_READ in permissions_for(identity["role"])
        and conn.execute(
            "SELECT 1 FROM artifact_access_grants WHERE analyst_id=? AND credential_digest=? "
            "AND host_id=? AND alert_id=? AND policy_version=? AND revoked_at IS NULL",
            (analyst_id, identity["token_digest"], host_id, alert_id, POLICY_VERSION),
        ).fetchone()
        is not None
    )


def can_read_command(conn, analyst_id, command_id):
    row = conn.execute(
        "SELECT alert_id,json_extract(command_json,'$.host_id') AS host_id "
        "FROM commands WHERE command_id=?",
        (command_id,),
    ).fetchone()
    return bool(row and can_read(conn, analyst_id, row["host_id"], row["alert_id"]))


def require_artifact(conn, artifact_id, authorization):
    # Called inside the retrieval transaction, never trusts a browser-provided identity.
    analyst = require_analyst_permission(authorization, "artifact:read")
    row = conn.execute(
        "SELECT a.*,c.alert_id,ra.response_id FROM response_artifacts a "
        "JOIN commands c ON c.command_id=a.command_id "
        "LEFT JOIN response_actions ra ON ra.command_id=a.command_id WHERE a.artifact_id=?",
        (artifact_id,),
    ).fetchone()
    if row is None:
        raise HTTPException(404, "artifact unavailable")
    if not can_read(conn, analyst, row["host_id"], row["alert_id"]):
        raise HTTPException(403, "artifact requires an explicit case and endpoint access grant")
    return analyst, row


def operate(conn, actor, kind, value, grant_id=None):
    payload = {"operation": kind, "grant_id": grant_id, **value}
    digest = hashlib.sha256(canonical(payload).encode()).hexdigest()
    previous = conn.execute(
        "SELECT payload_digest,result_json FROM artifact_access_operations "
        "WHERE actor=? AND request_id=?",
        (actor, value["request_id"]),
    ).fetchone()
    if previous is not None:
        if previous["payload_digest"] != digest:
            raise HTTPException(409, "artifact access request ID already used for another payload")
        return json.loads(previous["result_json"])
    if kind == "grant":
        identity = conn.execute(
            "SELECT token_digest,role FROM analyst_credentials "
            "WHERE analyst_id=? AND revoked_at IS NULL",
            (value["analyst_id"],),
        ).fetchone()
        if identity is None or AnalystPermission.ARTIFACT_READ not in permissions_for(
            identity["role"]
        ):
            raise HTTPException(403, "recipient is not an active artifact reader")
        case = conn.execute(
            "SELECT host_id FROM alerts WHERE alert_id=?", (value["alert_id"],)
        ).fetchone()
        if case is None or case["host_id"] != value["host_id"]:
            raise HTTPException(403, "case and endpoint scope do not match")
        existing = conn.execute(
            "SELECT grant_id FROM artifact_access_grants WHERE analyst_id=? "
            "AND credential_digest=? AND host_id=? AND alert_id=? AND revoked_at IS NULL",
            (value["analyst_id"], identity["token_digest"], value["host_id"], value["alert_id"]),
        ).fetchone()
        grant_id = existing["grant_id"] if existing else str(uuid4())
        if existing is None:
            conn.execute(
                "INSERT INTO artifact_access_grants "
                "(grant_id,analyst_id,credential_digest,host_id,alert_id,policy_version,"
                "granted_by,reason,created_at) VALUES (?,?,?,?,?,?,?,?,?)",
                (
                    grant_id,
                    value["analyst_id"],
                    identity["token_digest"],
                    value["host_id"],
                    value["alert_id"],
                    POLICY_VERSION,
                    actor,
                    value["reason"],
                    iso_now(),
                ),
            )
        changed = existing is None
    else:
        existing = conn.execute(
            "SELECT * FROM artifact_access_grants WHERE grant_id=?", (grant_id,)
        ).fetchone()
        if existing is None:
            raise HTTPException(404, "artifact access grant unavailable")
        changed = existing["revoked_at"] is None
        if changed:
            conn.execute(
                "UPDATE artifact_access_grants SET revoked_at=?,revoked_by=?,revoke_reason=? "
                "WHERE grant_id=?",
                (iso_now(), actor, value["reason"], grant_id),
            )
    result = dict(
        conn.execute(
            f"SELECT {PUBLIC_COLUMNS} FROM artifact_access_grants WHERE grant_id=?", (grant_id,)
        ).fetchone()
    )
    result = {"schema_version": "1", "grant": result, "changed": changed}
    record(
        conn,
        "artifact_access_granted" if kind == "grant" else "artifact_access_revoked",
        actor,
        result["grant"]["host_id"],
        value["request_id"],
        {
            "grant_id": grant_id,
            "analyst_id": result["grant"]["analyst_id"],
            "alert_id": result["grant"]["alert_id"],
            "policy_version": POLICY_VERSION,
            "reason": value["reason"],
            "changed": changed,
        },
    )
    conn.execute(
        "INSERT INTO artifact_access_operations VALUES (?,?,?,?,?)",
        (actor, value["request_id"], digest, canonical(result), iso_now()),
    )
    return result
