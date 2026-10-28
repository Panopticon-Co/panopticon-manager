"""Read retained Linux execution reports; never mutate command lifecycle from telemetry."""

import hashlib
import json


def command_evidence(conn, command, agent_id, host_id, *, full_history=False):
    rows = conn.execute(
        "SELECT record_id,host_id,boot_id,event_time,ingested_at,digest,raw_json "
        "FROM linux_endpoint_records WHERE agent_id=? AND type='response.action' "
        "AND json_extract(raw_json,'$.response.command_id')=? "
        "ORDER BY ingested_at,record_id" + ("" if full_history else " LIMIT 21"),
        (agent_id, command["command_id"]),
    ).fetchall()
    items = []
    for row in rows if full_history else rows[:20]:
        raw = json.loads(row["raw_json"])
        report = raw["response"]
        mismatches = []
        if row["host_id"] != host_id:
            mismatches.append("host_id")
        for key in ("action", "correlation_id"):
            if report.get(key) != command.get(key):
                mismatches.append(key)
        target = command.get("target", {})
        if "pid" in target:
            observed = report.get("target", {})
            # Numeric native ticks become strings only at the analyst boundary.
            # Never round-trip a 64-bit token through a browser number.
            if (
                type(observed.get("pid")) is not int
                or observed["pid"] != target["pid"]
                or type(observed.get("start_time_ticks")) is not int
                or str(observed["start_time_ticks"]) != str(target["start_time_ticks"])
            ):
                mismatches.append("process_target")
        if "path" in target and report.get("path") != target["path"]:
            mismatches.append("path")
        if "boot_id" in target:
            digest = "boot_" + hashlib.sha256(row["boot_id"].encode()).hexdigest()
            if digest != target["boot_id"]:
                mismatches.append("boot_id")
        projected = dict(report)
        if isinstance(projected.get("target"), dict):
            projected["target"] = dict(projected["target"])
            if "start_time_ticks" in projected["target"]:
                projected["target"]["start_time_ticks"] = str(
                    projected["target"]["start_time_ticks"]
                )
        item = {
            "record_id": row["record_id"],
            "host_id": row["host_id"],
            "captured_at": row["event_time"],
            "received_at": row["ingested_at"],
            "sha256": row["digest"],
            "provenance": raw["provenance"],
            "linkage": "mismatch" if mismatches else "matched_command",
            "mismatches": mismatches,
            "reported": projected,
        }
        if full_history:
            item["raw_record_json"] = row["raw_json"]
        items.append(item)
    return items, not full_history and len(rows) > 20


def sensor_report(conn, agent_id, host_id):
    row = conn.execute(
        "SELECT record_id,event_time,received_at,health_json FROM linux_endpoint_health "
        "WHERE host_id=? AND agent_id=?",
        (host_id, agent_id),
    ).fetchone()
    if row is None:
        return None
    health = json.loads(row["health_json"])
    providers = [p for p in health.get("providers", []) if p.get("name") == "command_channel"]
    return {
        "record_id": row["record_id"],
        "captured_at": row["event_time"],
        "received_at": row["received_at"],
        "freshness": "unverified",
        "response_providers": [
            {
                "name": p["name"],
                "state": p["state"],
                "reason": p["reason"],
                "capabilities": p["capabilities"],
            }
            for p in providers
        ],
        "execution_mode": "unknown",
    }
