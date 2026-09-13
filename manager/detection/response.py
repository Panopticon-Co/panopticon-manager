"""Response Engine: the only code path that turns a detection/alert into a
typed command. See docs/adr/004-response-engine.md for the full design.

Detection Engine never executes a response -- it only recommends one. The
recommendation itself is computed upstream, inside vendor/eyedetect, by
ActiveResponseEngine.resolve_action (see
vendor/eyedetect/src/alerting/active_response.py) while the full triggering
event is still in scope, and is carried on the resulting Alert as
``alert.active_response`` -- this module never re-derives it and never
receives the raw event itself (AlertSink.emit, manager/detection/factory.py,
is called with only the Alert). This module translates that recommendation
onto the closed 7-action Command enum, classifies its approval tier, and
either enqueues it immediately (AUTO_SAFE) or stages it for analyst
authorization (ANALYST_APPROVAL) via response_actions. Nothing here ever
calls an OS API directly -- only authorize_and_enqueue(), the same path the
raw command-creation endpoint uses.
"""

from __future__ import annotations

import json
import logging
import sqlite3
from datetime import datetime, timedelta, timezone
from typing import Any
from uuid import uuid4

from fastapi import HTTPException

from manager.routers.commands import Command, authorize_and_enqueue
from manager.timeutil import iso_now

_log = logging.getLogger(__name__)

# Every response_action gets this long to be authorized before it's simply
# left PENDING forever with no operator action -- not auto-executed, just
# bounded so a stale one doesn't linger indefinitely in the queue view.
_DEFAULT_COMMAND_TTL = timedelta(minutes=15)

# Locked decisions (see the approved implementation plan): KILL_PROCESS,
# ISOLATE_HOST, and RELEASE_HOST_ISOLATION always require analyst approval.
# COLLECT_PROCESS_INFO/COLLECT_NETWORK_CONNECTIONS are read-only and safe to
# auto-enqueue. COLLECT_FILE and QUARANTINE_FILE default to requiring
# approval too -- COLLECT_FILE has no operator-configured path allowlist
# implemented yet (a real path-scoped AUTO_SAFE carve-out is future work,
# not something to fake now), and QUARANTINE_FILE is not read-only.
_TIERS: dict[str, str] = {
    "COLLECT_PROCESS_INFO": "AUTO_SAFE",
    "COLLECT_NETWORK_CONNECTIONS": "AUTO_SAFE",
    "COLLECT_FILE": "ANALYST_APPROVAL",
    "QUARANTINE_FILE": "ANALYST_APPROVAL",
    "KILL_PROCESS": "ANALYST_APPROVAL",
    "ISOLATE_HOST": "ANALYST_APPROVAL",
    "RELEASE_HOST_ISOLATION": "ANALYST_APPROVAL",
}


def classify_tier(action: str) -> str:
    return _TIERS.get(action, "ANALYST_APPROVAL")


def translate_recommendation(
    action: str, active_response: dict[str, Any]
) -> tuple[str, dict[str, Any], str] | None:
    """Maps eyedetect's ActiveResponseAction.action vocabulary onto the
    closed 7-action Command enum. Returns (command_action, target,
    decided_reason) or None if no command can safely be produced --
    callers must never guess a target when this returns None.
    """
    if action == "TERMINATE_PROCESS":
        # ActiveResponseAction (vendor/eyedetect/src/alerting/active_response.py)
        # never carries start_time_ticks -- the Linux agent's gate requires
        # it to prevent PID-reuse, so this always fails closed rather than
        # ever guessing a start time. Fixing this requires an upstream
        # schema change, not a workaround here.
        return None
    if action == "ISOLATE_HOST":
        return "ISOLATE_HOST", {}, "direct mapping"
    if action == "BLOCK_FIREWALL_IP":
        # Locked decision: no 8th action. Coarser than per-IP blocking, but
        # stays within the closed, security-reviewed action set.
        return (
            "ISOLATE_HOST",
            {},
            "BLOCK_FIREWALL_IP has no equivalent action; downgraded to ISOLATE_HOST",
        )
    return None


def on_alert_created(conn: sqlite3.Connection, alert: Any) -> None:
    """Called from AlertSink.emit (manager/detection/factory.py) right
    after a *new* alert row is durably written (never for a replayed/
    crash-recovered duplicate -- the caller checks insert_alert's return
    value first, so this never double-creates a response_actions row for
    the same alert_id). Builds at most one response_actions row per alert.

    Never raises: the caller (AlertSink.emit) runs inside the detection
    worker's single BEGIN IMMEDIATE per event (manager/detection/worker.py
    process_claimed) -- an uncaught exception here would roll back that
    transaction and silently discard the alert that was just written, not
    just the response action. The whole body is therefore guarded; any
    unexpected failure is swallowed and simply means no response_actions
    row was staged for this alert.
    """
    try:
        _on_alert_created(conn, alert)
    except Exception:
        _log.exception(
            "Response Engine failed to process alert %r", getattr(alert, "alert_id", alert)
        )


def _on_alert_created(conn: sqlite3.Connection, alert: Any) -> None:
    record = alert.to_dict() if hasattr(alert, "to_dict") else alert
    active_response = record.get("active_response")
    if not active_response:
        return
    eyedetect_action = active_response.get("action")
    if not eyedetect_action:
        return
    mapped = translate_recommendation(eyedetect_action, active_response)
    response_id = str(uuid4())
    now = iso_now()
    if mapped is None:
        conn.execute(
            "INSERT INTO response_actions (response_id, alert_id, action, tier, lifecycle_state, "
            "target_json, command_id, created_at, authorized_at, authorized_by, decided_reason) "
            "VALUES (?, ?, ?, ?, 'REJECTED', ?, NULL, ?, NULL, NULL, ?)",
            (
                response_id,
                record["alert_id"],
                eyedetect_action,
                "AUTO_SAFE",
                json.dumps(active_response),
                now,
                f"no safe command mapping for {eyedetect_action}",
            ),
        )
        return
    command_action, command_target, decided_reason = mapped
    tier = classify_tier(command_action)
    conn.execute(
        "INSERT INTO response_actions (response_id, alert_id, action, tier, lifecycle_state, "
        "target_json, command_id, created_at, authorized_at, authorized_by, decided_reason) "
        "VALUES (?, ?, ?, ?, 'PENDING', ?, NULL, ?, NULL, NULL, ?)",
        (
            response_id,
            record["alert_id"],
            command_action,
            tier,
            json.dumps(command_target),
            now,
            decided_reason,
        ),
    )
    if tier == "AUTO_SAFE":
        try:
            authorize_response_action(conn, response_id, actor="system:response-engine")
        except HTTPException as exc:
            conn.execute(
                "UPDATE response_actions SET lifecycle_state = 'REJECTED', decided_reason = ? "
                "WHERE response_id = ? AND lifecycle_state = 'PENDING'",
                (f"automatic authorization failed: {exc.detail}", response_id),
            )


def authorize_response_action(conn: sqlite3.Connection, response_id: str, actor: str) -> None:
    """Turns a PENDING (or re-authorizes an AUTO_SAFE) response_actions row
    into a real, dispatchable command via the same authorize_and_enqueue()
    the raw command-creation endpoint uses. Raises whatever
    authorize_and_enqueue raises (e.g. HTTPException) if the underlying
    command creation is rejected -- callers decide how to surface that.
    """
    row = conn.execute(
        "SELECT alert_id, action, target_json FROM response_actions "
        "WHERE response_id = ? AND lifecycle_state = 'PENDING'",
        (response_id,),
    ).fetchone()
    if row is None:
        return
    alert = conn.execute(
        "SELECT agent_id FROM alerts WHERE alert_id = ?", (row["alert_id"],)
    ).fetchone()
    if alert is None or alert["agent_id"] is None:
        conn.execute(
            "UPDATE response_actions SET lifecycle_state = 'REJECTED', decided_reason = ? "
            "WHERE response_id = ?",
            ("originating alert has no agent_id to target", response_id),
        )
        return
    command_id = f"resp-{response_id}"
    command = Command(
        command_id=command_id,
        agent_id=str(alert["agent_id"]),
        action=row["action"],
        expires_at=datetime.now(timezone.utc) + _DEFAULT_COMMAND_TTL,
        target=json.loads(row["target_json"]),
    )
    authorize_and_enqueue(conn, command, actor, alert_id=row["alert_id"])
    conn.execute(
        "UPDATE response_actions SET lifecycle_state = 'AUTHORIZED', command_id = ?, "
        "authorized_at = ?, authorized_by = ? WHERE response_id = ?",
        (command_id, iso_now(), actor, response_id),
    )


def reject_response_action(
    conn: sqlite3.Connection, response_id: str, actor: str, reason: str
) -> None:
    conn.execute(
        "UPDATE response_actions SET lifecycle_state = 'REJECTED', authorized_by = ?, "
        "decided_reason = ? WHERE response_id = ? AND lifecycle_state = 'PENDING'",
        (actor, reason, response_id),
    )
