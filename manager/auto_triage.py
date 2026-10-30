"""Collection-only detection workflows; all writes join the caller's transaction."""

import json
from datetime import datetime, timedelta, timezone

from fastapi import HTTPException
from response_engine.triage import (
    ARTIFACT_RESERVATION_BYTES,
    AUTO_TRIAGE_ACTOR,
    COLLECT_ACTIONS,
    AutoTriagePolicy,
    BudgetUsage,
    EndpointCapability,
    evaluate,
)

from manager.analyst_response import resolve_manual_target
from manager.artifact_keys import current, record
from manager.response_profile import current_profile, policy_block
from manager.timeutil import iso_now
from manager.triage_store import asset_for, policy_for


def endpoint(conn, agent, host):
    profile = current_profile(conn, agent, host)
    report = profile["report"] or {}
    return EndpointCapability(
        platform=report.get("platform", "linux"), recent=profile["state"] == "recent",
        mode=report.get("mode", "off"), implemented_actions=report.get("implemented_actions", []),
        allowed_actions=report.get("allowed_actions", []), authenticated_command_channel=True,
        collection_acceptance_gate=report.get("require_collection_acceptance") is True,
        artifact_protocol=report.get("artifact_protocol") if current(conn, agent) else None,
    )


def usage(conn, agent, alert, policy, *, exclude_action=None):
    cutoff = (datetime.now(timezone.utc) - timedelta(
        seconds=policy.budget.endpoint_window_seconds)).isoformat()
    rows = conn.execute(
        "SELECT i.alert_id,i.action,i.reserved_bytes,r.agent_id,r.created_at,"
        "ra.lifecycle_state AS response_state,c.lifecycle_state AS command_state "
        "FROM triage_items i JOIN triage_runs r ON r.alert_id=i.alert_id "
        "LEFT JOIN response_actions ra ON ra.response_id=i.response_id "
        "LEFT JOIN commands c ON c.command_id=ra.command_id WHERE i.reserved_bytes>0 "
        "AND (r.created_at>=? OR ra.lifecycle_state='PENDING' "
        "OR c.lifecycle_state IN ('AUTHORIZED','DISPATCHED','ACCEPTED'))", (cutoff,),
    ).fetchall()
    values = BudgetUsage().model_dump()
    for row in rows:
        if row["alert_id"] == alert and row["action"] == exclude_action:
            continue
        if row["alert_id"] == alert:
            values["actions_for_alert"] += 1
            values["bytes_for_alert"] += row["reserved_bytes"]
        if row["agent_id"] == agent and row["created_at"] >= cutoff:
            values["actions_in_endpoint_window"] += 1
            values["bytes_in_endpoint_window"] += row["reserved_bytes"]
        if row["response_state"] == "PENDING" or row["command_state"] in {
            "AUTHORIZED", "DISPATCHED", "ACCEPTED",
        }:
            values["active_global"] += 1
            values["active_for_endpoint"] += row["agent_id"] == agent
    return BudgetUsage(**values)


def collection_target(conn, alert, action):
    """Only retained evidence supplies a target; conflicting file sources fail closed."""
    target = {}
    if action == "COLLECT_FILE":
        record = json.loads(conn.execute(
            "SELECT alert_json FROM alerts WHERE alert_id=?", (alert,),
        ).fetchone()[0])
        recommendation = record.get("active_response") or {}
        evidence = record.get("evidence") or {}
        file = evidence.get("file") or {} if isinstance(evidence, dict) else {}
        paths = [value for value in (
            recommendation.get("target_file") if isinstance(recommendation, dict) else None,
            file.get("path") if isinstance(file, dict) else None,
        ) if value is not None]
        if not paths or any(not isinstance(p, str) or p != paths[0] for p in paths):
            raise HTTPException(422, "alert file target is missing or ambiguous")
        target = {"path": paths[0]}
    return resolve_manual_target(conn, alert, action, target)


def start(conn, alert):
    """Called within the existing alert+response audit SAVEPOINT. Replays are no-ops."""
    from manager.detection.response import _insert_response_action, authorize_response_action

    alert_id = alert["alert_id"]
    retained = conn.execute("SELECT * FROM alerts WHERE alert_id=?", (alert_id,)).fetchone()
    if retained is None:
        return False
    configuration = policy_for(conn, retained["rule_id"])
    if configuration is None:
        return False
    if conn.execute("SELECT 1 FROM triage_runs WHERE alert_id=?", (alert_id,)).fetchone():
        return True
    policy = AutoTriagePolicy.model_validate(configuration)
    # Unbound alerts are kept as detections; they cannot mint endpoint work.
    enrolled = conn.execute(
        "SELECT host_id FROM enrolled_agents WHERE agent_id=? AND revoked_at IS NULL",
        (retained["agent_id"],),
    ).fetchone()
    host = retained["host_id"] or (enrolled[0] if enrolled else "unknown")
    asset, asset_version = asset_for(conn, host)
    now = datetime.now(timezone.utc)
    conn.execute("INSERT INTO triage_runs VALUES (?,?,?,?,?,?,?,?,?,?,NULL)", (
        alert_id, policy.rule_id, policy.version, policy.model_dump_json(),
        retained["agent_id"] or "unknown", host, asset, asset_version, now.isoformat(),
        (now + timedelta(seconds=policy.budget.workflow_ttl_seconds)).isoformat(),
    ))
    capability = endpoint(conn, retained["agent_id"], host)
    for action in COLLECT_ACTIONS:
        target, target_error = {}, None
        try:
            agent, bound_host, target = collection_target(conn, alert_id, action)
            if (agent, bound_host) != (retained["agent_id"], host):
                raise HTTPException(409, "endpoint binding changed")
            blocker = policy_block(current_profile(conn, agent, host), action, target)
            if blocker:
                raise HTTPException(409, blocker)
        except HTTPException as exc:
            target_error = str(exc.detail)
        decision = evaluate(
            policy, action, asset, capability, usage(conn, retained["agent_id"], alert_id, policy),
            process_identity_verified=target_error is None and "boot_id" in target,
            file_path=target.get("path"),
        )
        if target_error is not None and decision.decision != "skip":
            decision = decision.model_copy(update={"decision": "skip", "reason": "invalid_target"})
        response_id = None
        if decision.decision != "skip":
            response_id = _insert_response_action(
                conn, alert_id=alert_id, action=action,
                tier="AUTO_SAFE" if decision.decision == "auto_dispatch" else "ANALYST_APPROVAL",
                state="PENDING", target=target, reason=decision.reason, actor=AUTO_TRIAGE_ACTOR,
            )
            conn.execute(
                "UPDATE response_actions SET origin='auto_triage',requested_by=?,request_reason=?,"
                "requested_agent_id=?,requested_host_id=? WHERE response_id=?",
                (AUTO_TRIAGE_ACTOR, decision.reason, retained["agent_id"], host, response_id),
            )
        conn.execute("INSERT INTO triage_items VALUES (?,?,?,?,?,?,?)", (
            alert_id, action, decision.decision, decision.reason, json.dumps(target),
            ARTIFACT_RESERVATION_BYTES if response_id else 0, response_id,
        ))
        record(conn, "auto_triage_created" if response_id else "auto_triage_skipped",
               AUTO_TRIAGE_ACTOR, host, response_id or alert_id,
               {**decision.model_dump(), "alert_id": alert_id, "target_error": target_error})
        if decision.decision == "auto_dispatch":
            authorize_response_action(conn, response_id, AUTO_TRIAGE_ACTOR)
    return True


def guard(conn, *, command_id=None, response_id=None):
    """Same live-policy guard at approval, dispatch and endpoint acceptance."""
    item = conn.execute(
        "SELECT i.*,r.rule_id,r.policy_version,r.agent_id,r.host_id,r.asset_class,r.asset_version,"
        "r.deadline,r.cancelled_at FROM triage_items i JOIN triage_runs r "
        "ON r.alert_id=i.alert_id WHERE i.response_id=? OR 'resp-' || i.response_id=?",
        (response_id, command_id),
    ).fetchone()
    if item is None:
        return None
    if item["cancelled_at"]:
        return "triage_run_cancelled"
    if datetime.fromisoformat(item["deadline"]) <= datetime.now(timezone.utc):
        return "triage_deadline_expired"
    configuration = policy_for(conn, item["rule_id"])
    if not configuration or configuration["version"] != item["policy_version"]:
        return "triage_policy_revision_changed"
    if asset_for(conn, item["host_id"]) != (item["asset_class"], item["asset_version"]):
        return "triage_asset_classification_changed"
    policy = AutoTriagePolicy.model_validate(configuration)
    try:
        agent, host, target = collection_target(conn, item["alert_id"], item["action"])
    except HTTPException:
        return "triage_target_no_longer_valid"
    if (agent, host, target) != (
        item["agent_id"], item["host_id"], json.loads(item["target_json"]),
    ):
        return "triage_target_binding_changed"
    if policy_block(current_profile(conn, agent, host), item["action"], target):
        return "triage_runtime_policy_changed"
    result = evaluate(
        policy, item["action"], item["asset_class"], endpoint(conn, agent, host),
        usage(conn, agent, item["alert_id"], policy, exclude_action=item["action"]),
        process_identity_verified="boot_id" in target, file_path=target.get("path"),
    )
    return result.reason if result.decision != item["decision"] else None


def deadline(conn, response_id):
    row = conn.execute(
        "SELECT r.deadline FROM triage_items i JOIN triage_runs r ON r.alert_id=i.alert_id "
        "WHERE i.response_id=?", (response_id,),
    ).fetchone()
    return datetime.fromisoformat(row[0]) if row else None


def reconcile(conn, agent_id=None):
    """Retire permanently invalid queued work through existing decision/cancel writers."""
    from manager.detection.response import reject_response_action

    rows = conn.execute(
        "SELECT i.response_id,ra.lifecycle_state,c.lifecycle_state AS command_state "
        "FROM triage_items i JOIN triage_runs r ON r.alert_id=i.alert_id "
        "JOIN response_actions ra ON ra.response_id=i.response_id "
        "LEFT JOIN commands c ON c.command_id=ra.command_id "
        "WHERE (ra.lifecycle_state='PENDING' OR c.lifecycle_state='AUTHORIZED') "
        "AND (? IS NULL OR r.agent_id=?)", (agent_id, agent_id),
    ).fetchall()
    permanent = {"triage_run_cancelled", "triage_deadline_expired",
                 "triage_policy_revision_changed",
                 "triage_asset_classification_changed", "triage_target_no_longer_valid",
                 "triage_target_binding_changed"}
    for row in rows:
        blocker = guard(conn, response_id=row["response_id"])
        if blocker in permanent:
            if row["lifecycle_state"] == "PENDING":
                reject_response_action(conn, row["response_id"], AUTO_TRIAGE_ACTOR, blocker)
            else:
                cancel_queued(conn, row["response_id"], AUTO_TRIAGE_ACTOR, blocker)


def dispatchable(conn, command_id, selected_runs):
    item = conn.execute("SELECT alert_id FROM triage_items WHERE 'resp-' || response_id=?",
                        (command_id,)).fetchone()
    if item is None:
        return True
    if guard(conn, command_id=command_id):
        return False
    other = conn.execute(
        "SELECT 1 FROM triage_items i JOIN response_actions ra ON ra.response_id=i.response_id "
        "JOIN commands c ON c.command_id=ra.command_id WHERE i.alert_id=? AND c.command_id!=? "
        "AND c.lifecycle_state IN ('DISPATCHED','ACCEPTED')", (item[0], command_id),
    ).fetchone()
    if other or item[0] in selected_runs:
        return False
    selected_runs.add(item[0])
    return True


def cancel_queued(conn, response_id, actor, reason):
    """Shared by the existing queued request cancellation and workflow cancellation."""
    from manager.response_audit import record_decision
    from manager.routers.commands import _audit

    row = conn.execute(
        "SELECT c.command_id,c.lifecycle_state FROM response_actions ra JOIN commands c "
        "ON c.command_id=ra.command_id WHERE ra.response_id=?", (response_id,),
    ).fetchone()
    if row is None:
        raise HTTPException(404, "response has no queued command")
    if row["lifecycle_state"] == "CANCELLED":
        return
    if row["lifecycle_state"] != "AUTHORIZED":
        raise HTTPException(409, "only commands awaiting dispatch can be cancelled")
    conn.execute("UPDATE commands SET lifecycle_state='CANCELLED' WHERE command_id=?",
                 (row["command_id"],))
    _audit(conn, row["command_id"], "cancelled", actor, reason)
    record_decision(conn, response_id, "cancelled", actor, {"reason": reason})


def cancel_run(conn, alert_id, actor, reason):
    from manager.detection.response import reject_response_action

    run = conn.execute("SELECT * FROM triage_runs WHERE alert_id=?", (alert_id,)).fetchone()
    if run is None:
        raise HTTPException(404, "triage run not found")
    if not run["cancelled_at"]:
        conn.execute("UPDATE triage_runs SET cancelled_at=? WHERE alert_id=?",
                     (iso_now(), alert_id))
        for item in conn.execute(
            "SELECT ra.response_id,ra.lifecycle_state,c.lifecycle_state AS command_state "
            "FROM triage_items i JOIN response_actions ra ON ra.response_id=i.response_id "
            "LEFT JOIN commands c ON c.command_id=ra.command_id WHERE i.alert_id=?", (alert_id,),
        ).fetchall():
            if item["lifecycle_state"] == "PENDING":
                reject_response_action(conn, item["response_id"], actor, reason)
            elif item["command_state"] == "AUTHORIZED":
                cancel_queued(conn, item["response_id"], actor, reason)
        record(conn, "auto_triage_run_cancelled", actor, run["host_id"], alert_id,
               {"rule_id": run["rule_id"], "policy_version": run["policy_version"],
                "reason": reason})
    return {"alert_id": alert_id, "cancelled": True,
            "notice": "Queued work stopped. Delivered work may already have started."}
