"""Individual-identity controls for versioned collection policy and bounded runs."""

import json
from typing import Literal

from fastapi import APIRouter, Header, HTTPException, Query
from pydantic import BaseModel, ConfigDict, Field, StrictInt
from response_engine.triage import AutoTriagePolicy, default_policy

from manager import db
from manager.artifact_keys import record
from manager.auth import analyst_access, require_analyst_permission
from manager.auto_triage import cancel_run, guard, reconcile
from manager.timeutil import iso_now
from manager.triage_store import asset_for, policy_for

router = APIRouter(prefix="/api/v1/triage")
ID = r"^[A-Za-z0-9._:-]+$"


class Change(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    request_id: str = Field(min_length=1, max_length=128, pattern=ID)
    expected_version: StrictInt = Field(ge=0, le=2147483646)


class PolicyChange(Change):
    policy: AutoTriagePolicy


class AssetChange(Change):
    host_id: str = Field(min_length=1, max_length=256)
    asset_class: Literal["standard", "critical", "unknown"]
    reason: str = Field(min_length=1, max_length=512, pattern=r"\S")


class Cancel(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    reason: str = Field(min_length=1, max_length=512, pattern=r"\S")


def admin_change(request, authorization, operation):
    actor = "analyst:" + require_analyst_permission(authorization, "triage:manage")
    conn = db.connect()
    conn.execute("BEGIN IMMEDIATE")
    try:
        require_analyst_permission(authorization, "triage:manage")
        payload = json.dumps({"operation": operation, **request.model_dump()}, sort_keys=True)
        prior = conn.execute("SELECT * FROM triage_admin_requests WHERE actor=? AND request_id=?",
                             (actor, request.request_id)).fetchone()
        if prior:
            if prior["payload_json"] != payload:
                raise HTTPException(409, "retry identity already binds another policy change")
            result = json.loads(prior["result_json"])
        else:
            if operation == "policy":
                policy = request.policy
                previous = policy_for(conn, policy.rule_id)
                version = previous["version"] if previous else 0
                if version != request.expected_version or policy.version != version + 1:
                    raise HTTPException(409, "policy revision changed; refresh before saving")
                conn.execute("INSERT INTO triage_policy_revisions VALUES (?,?,?,?,?)", (
                    policy.rule_id, policy.version, policy.model_dump_json(), actor, iso_now(),
                ))
                conn.execute("INSERT INTO triage_policy_heads VALUES (?,?) "
                             "ON CONFLICT(rule_id) DO UPDATE SET version=excluded.version",
                             (policy.rule_id, policy.version))
                result = {"policy": policy.model_dump()}
                asset = None
            else:
                if not conn.execute("SELECT 1 FROM enrolled_agents WHERE host_id=? "
                                    "AND revoked_at IS NULL", (request.host_id,)).fetchone():
                    raise HTTPException(422, "asset must be an actively enrolled host")
                _, version = asset_for(conn, request.host_id)
                if version != request.expected_version:
                    raise HTTPException(409, "asset classification changed; refresh before saving")
                conn.execute("INSERT INTO triage_asset_classes VALUES (?,?,?,?,?) "
                             "ON CONFLICT(host_id) DO UPDATE SET asset_class=excluded.asset_class,"
                             "version=excluded.version,actor=excluded.actor,"
                             "updated_at=excluded.updated_at",
                             (request.host_id, request.asset_class, version + 1, actor, iso_now()))
                result = {"host_id": request.host_id, "asset_class": request.asset_class,
                          "version": version + 1}
                asset = request.host_id
            record(conn, "auto_triage_" + operation + "_changed", actor, asset,
                   request.request_id, {"access_policy_version": 3, **request.model_dump()})
            conn.execute("INSERT INTO triage_admin_requests VALUES (?,?,?,?)",
                         (actor, request.request_id, payload, json.dumps(result)))
        conn.commit()
        return result
    except Exception:
        conn.rollback()
        raise


@router.get("/policies")
async def policies(authorization: str | None = Header(None)):
    require_analyst_permission(authorization, "triage:manage")
    conn = db.connect()
    rules = conn.execute("SELECT rule_id FROM triage_policy_heads UNION SELECT rule_id FROM alerts "
                         "ORDER BY rule_id LIMIT 200").fetchall()
    hosts = conn.execute("SELECT host_id FROM enrolled_agents WHERE revoked_at IS NULL "
                         "ORDER BY host_id LIMIT 200").fetchall()
    return {"policies": [policy_for(conn, r[0]) or default_policy(r[0]).model_dump()
                         for r in rules],
            "configured_rules": [r[0] for r in conn.execute(
                "SELECT rule_id FROM triage_policy_heads ORDER BY rule_id LIMIT 200")],
            "assets": [{"host_id": r[0], "asset_class": asset_for(conn, r[0])[0],
                        "version": asset_for(conn, r[0])[1]} for r in hosts],
            "notice": "Unconfigured rules are disabled. New policies start at revision 1."}


@router.post("/policies")
async def save_policy(request: PolicyChange, authorization: str | None = Header(None)):
    return admin_change(request, authorization, "policy")


@router.post("/assets")
async def save_asset(request: AssetChange, authorization: str | None = Header(None)):
    return admin_change(request, authorization, "asset")


@router.get("/runs")
async def runs(authorization: str | None = Header(None),
               limit: int = Query(50, ge=1, le=100), offset: int = Query(0, ge=0, le=1000000)):
    access = analyst_access(authorization)
    if not {"response:request", "response:decide"} & set(access["permissions"]):
        raise HTTPException(403, "response operator permission required")
    conn = db.connect()
    conn.execute("BEGIN IMMEDIATE")
    try:
        reconcile(conn)
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    rows = conn.execute("SELECT alert_id,rule_id,policy_version,asset_class,host_id,created_at,"
                        "deadline,cancelled_at FROM triage_runs ORDER BY created_at DESC "
                        "LIMIT ? OFFSET ?", (limit, offset)).fetchall()
    result = []
    for row in rows:
        items = conn.execute(
            "SELECT i.action,i.decision,i.reason,i.reserved_bytes,i.response_id,"
            "ra.lifecycle_state,c.lifecycle_state AS command_state FROM triage_items i "
            "LEFT JOIN response_actions ra ON ra.response_id=i.response_id "
            "LEFT JOIN commands c ON c.command_id=ra.command_id WHERE i.alert_id=? "
            "ORDER BY i.action", (row["alert_id"],),
        ).fetchall()
        result.append({**dict(row), "items": [
            {**dict(item), "live_blocker": guard(conn, response_id=item["response_id"])
             if item["response_id"] and (item["lifecycle_state"] == "PENDING"
             or item["command_state"] in {"AUTHORIZED", "DISPATCHED"}) else None}
            for item in items]})
    return {"runs": result, "next_offset": offset + limit if len(rows) == limit else None}


@router.post("/runs/{alert_id}/cancel")
async def cancel(alert_id: str, request: Cancel, authorization: str | None = Header(None)):
    actor = "analyst:" + require_analyst_permission(authorization, "response:decide")
    conn = db.connect()
    conn.execute("BEGIN IMMEDIATE")
    try:
        require_analyst_permission(authorization, "response:decide")
        result = cancel_run(conn, alert_id, actor, request.reason)
        conn.commit()
        return result
    except Exception:
        conn.rollback()
        raise
