"""Simulation adapter: previews a policy-selected response without any effect
on a host (docs/AUTOMATED_RESPONSE.md).

It re-validates the translated target against the closed command contract,
exactly as a real dispatch would, and describes what the endpoint would be
asked to do. It never writes a ``commands`` row, never contacts an agent and
never claims an outcome: a simulated containment is recorded as
``simulated``, which the incident status reports as *simulated*, never as
*contained*.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from pydantic import ValidationError
from response_engine.contract import Command

_EFFECTS = {
    "KILL_PROCESS": "terminate process pid={pid} (start_time_ticks={start_time_ticks})",
    "COLLECT_PROCESS_INFO": "collect information for pid={pid}",
    "COLLECT_NETWORK_CONNECTIONS": "collect current network connections",
    "COLLECT_FILE": "collect file {path}",
    "QUARANTINE_FILE": "quarantine file {path}",
    "ISOLATE_HOST": "isolate the host's network (management channel retained)",
    "RELEASE_HOST_ISOLATION": "release host network isolation",
}


def simulate(action: str, target: dict, *, agent_id: str | None, host_id: str | None):
    """Returns ``(status, detail)``: ``("simulated", {...})`` when the command
    would be valid for dispatch, ``("refused", {...})`` otherwise."""
    try:
        command = Command(
            command_id="simulation",
            agent_id=agent_id or "unbound",
            schema_version="2" if "boot_id" in target else "1",
            action=action,
            expires_at=datetime.now(timezone.utc) + timedelta(minutes=1),
            target=target,
        )
    except ValidationError as exc:
        return "refused", {
            "adapter": "simulation",
            "host_effect": "none",
            "error": f"target fails the closed command contract: {exc.errors()[0]['msg']}",
        }
    detail = {
        "adapter": "simulation",
        "host_effect": "none",
        "would": f"{_EFFECTS[command.action].format(**command.target)} on host {host_id}",
        "validated_target": command.target,
    }
    if agent_id is None:
        detail["note"] = "no enrolled agent bound to the alert; a real dispatch would be refused"
    return "simulated", detail
