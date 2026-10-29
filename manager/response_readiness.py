"""Observed contact and advisory preflight; never inferred native capability or success."""

import json
from datetime import datetime, timezone

from fastapi import HTTPException

from manager import command_signing
from manager.analyst_response import resolve_manual_target
from manager.linux_response_evidence import sensor_report
from manager.response_profile import current_profile, policy_block


def channel_readiness(conn, agent_id):
    enrolled = conn.execute(
        "SELECT agent_id,host_id,revoked_at FROM enrolled_agents WHERE agent_id=?", (agent_id,)
    ).fetchone()
    if enrolled is None:
        raise HTTPException(404, "no enrolled endpoint with that id")
    row = conn.execute(
        "SELECT last_polled_at,delivery_mode,command_auth FROM agent_response_channels "
        "WHERE agent_id=?",
        (agent_id,),
    ).fetchone()
    age = None
    if row is not None:
        observed = datetime.fromisoformat(row["last_polled_at"])
        age = max(0, int((datetime.now(timezone.utc) - observed).total_seconds()))
    report = sensor_report(conn, agent_id, enrolled["host_id"])
    profile = current_profile(conn, agent_id, enrolled["host_id"])
    return {
        "runtime_profile": profile,
        "sensor_report": report,
        "agent_id": agent_id,
        "host_id": enrolled["host_id"],
        "enrollment_active": enrolled["revoked_at"] is None,
        "contact_state": "unknown" if age is None else "recent" if age <= 300 else "stale",
        "last_polled_at": row["last_polled_at"] if row else None,
        "seconds_since_poll": age,
        "delivery_mode": row["delivery_mode"] if row else None,
        "command_auth": row["command_auth"] if row else None,
        "native_capabilities": "current_report"
        if profile["state"] == "recent"
        else "reported_snapshot"
        if report and report["response_providers"]
        else "not_reported",
        "execution_mode": profile["report"]["mode"] if profile["state"] == "recent" else "unknown",
        "command_authority": command_signing.readiness(),
    }


def response_preflight(conn, row, access, separate_approver):
    checks = []

    def check(name, state, detail):
        checks.append({"check": name, "state": state, "detail": detail})

    check(
        "approval_permission",
        "pass" if "response:decide" in access["permissions"] else "block",
        "Approver permission is required.",
    )
    check(
        "pending",
        "pass" if row["lifecycle_state"] == "PENDING" else "block",
        "Only pending recommendations can be authorized.",
    )
    if separate_approver and row["requested_by"] == "analyst:" + access["analyst_id"]:
        check("independent_approval", "block", "A different analyst must approve this request.")
    target = json.loads(row["target_json"])
    agent_id = None
    host_id = None
    try:
        agent_id, host_id, resolved = resolve_manual_target(
            conn, row["alert_id"], row["action"], target
        )
        if resolved != target or (
            row["requested_agent_id"] is not None
            and (agent_id != row["requested_agent_id"] or host_id != row["requested_host_id"])
        ):
            raise HTTPException(409, "retained endpoint binding changed")
        check("retained_target", "pass", "Retained target agrees with current enrollment.")
    except HTTPException as exc:
        check("retained_target", "block", str(exc.detail))
    readiness = channel_readiness(conn, agent_id) if agent_id is not None else None
    authority = readiness["command_authority"] if readiness else command_signing.readiness()
    if authority["state"] == "unavailable" or (
        readiness and readiness["command_auth"] == "ES256" and authority["state"] != "ready"
    ):
        check("command_authority", "block", "Required command signing authority is unavailable.")
    else:
        check(
            "command_authority",
            "pass" if authority["state"] == "ready" else "warning",
            "Signing is ready."
            if authority["state"] == "ready"
            else "Signing is not configured; legacy delivery remains unsigned.",
        )
    if readiness is None or readiness["contact_state"] != "recent":
        check("channel_contact", "warning", "No recent authenticated command poll is observed.")
    if readiness is not None:
        profile = readiness["runtime_profile"]
        blocker = policy_block(profile, row["action"], target)
        check(
            "runtime_policy",
            "block" if blocker else "pass" if profile["state"] == "recent" else "warning",
            blocker or "Runtime policy report: " + profile["state"],
        )
    current = readiness and readiness["runtime_profile"]["state"] == "recent"
    check(
        "native_support",
        "pass" if current else "warning",
        "Recent endpoint-reported policy is available; "
        "native execution is still verified per command."
        if current
        else "Current native action support and enforcement mode are unknown; "
        "retained sensor snapshots are advisory.",
    )
    return {
        "response_id": row["response_id"],
        "action": row["action"],
        "target": target,
        "agent_id": agent_id,
        "host_id": host_id,
        "readiness": readiness,
        "advisory": True,
        "allowed_to_authorize": not any(c["state"] == "block" for c in checks),
        "checks": checks,
    }
