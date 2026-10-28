"""Alert-scoped manual response; endpoint identity is derived from retained evidence."""

import json
from datetime import datetime, timedelta, timezone
from uuid import uuid4

from fastapi import HTTPException
from pydantic import ValidationError
from response_engine.contract import Command
from response_engine.recommendation import translate_recommendation


def resolve_manual_target(conn, alert_id, action, target):
    row = conn.execute(
        "SELECT a.agent_id,a.host_id,a.alert_json,e.host_id AS enrolled_host "
        "FROM alerts a JOIN enrolled_agents e ON e.agent_id=a.agent_id "
        "WHERE a.alert_id=? AND e.revoked_at IS NULL",
        (alert_id,),
    ).fetchone()
    if row is None:
        raise HTTPException(422, "alert must belong to an actively enrolled endpoint")
    record = json.loads(row["alert_json"])
    if not isinstance(record, dict):
        raise HTTPException(422, "invalid retained alert context")
    context = record.get("endpoint_context")
    if row["host_id"] is not None and row["host_id"] != row["enrolled_host"]:
        raise HTTPException(409, "alert and enrolled host binding disagree")
    if context is not None:
        endpoint = context.get("endpoint", {}) if isinstance(context, dict) else {}
        if not isinstance(endpoint, dict):
            raise HTTPException(422, "invalid retained endpoint context")
        if (
            endpoint.get("agent_id") != row["agent_id"]
            or endpoint.get("host_id") != row["enrolled_host"]
        ):
            raise HTTPException(409, "canonical endpoint binding disagrees with enrollment")
    if action in {"KILL_PROCESS", "COLLECT_PROCESS_INFO"}:
        recommendation = record.get("active_response") or {}
        if not isinstance(recommendation, dict):
            raise HTTPException(422, "invalid retained process recommendation")
        if context is not None:
            subject = context.get("subject", {}) if isinstance(context, dict) else {}
            if not isinstance(subject, dict):
                raise HTTPException(422, "invalid retained process subject")
            ticks = subject.get("native_creation_ticks")
            recommendation = {
                "target_pid": subject.get("observed_pid"),
                "target_start_time_ticks": int(ticks)
                if isinstance(ticks, str)
                and ticks.isascii()
                and ticks.isdecimal()
                and len(ticks) <= 20
                else None,
            }
        mapped = translate_recommendation(
            "TERMINATE_PROCESS" if action == "KILL_PROCESS" else action,
            recommendation,
            context,
        )
        if mapped is None or (target and target != mapped[1]):
            raise HTTPException(422, "process target must match verified alert identity")
        target = mapped[1]
    try:
        command = Command(
            command_id=str(uuid4()),
            agent_id=row["agent_id"],
            action=action,
            schema_version="2" if "boot_id" in target else "1",
            target=target,
            expires_at=datetime.now(timezone.utc) + timedelta(minutes=15),
        )
    except ValidationError as exc:
        raise HTTPException(422, "invalid target for response action") from exc
    return row["agent_id"], row["enrolled_host"], command.target
