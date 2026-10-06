"""Map a Linux endpoint record (endpoint/1.0) to the detection engine's normalized event.

The engine's rules read the dict ``OfficerIngestionAdapter.transform_officer_event`` produces. This
module produces the same shape for Linux ``process.exec`` records without touching the engine, so
the Linux rules (``rules/linux_process``) evaluate real sensor telemetry. Only what the record
states is mapped: a missing field stays ``None`` and is never guessed.
"""

from __future__ import annotations

from typing import Any

# Record types that become engine events. Everything else is stored and not evaluated yet.
DETECTABLE_TYPES = ("process.exec",)


def _command_line(process: dict) -> str:
    args = process.get("args")
    if isinstance(args, list) and args:
        return " ".join(str(a) for a in args)
    return ""


def to_engine_event(record: dict) -> dict[str, Any] | None:
    if record.get("type") != "process.exec":
        return None
    proc = record.get("process") or {}
    host = record.get("host") or {}
    sensor = record.get("sensor") or {}
    prov = record.get("provenance") or {}
    ancestry = proc.get("ancestry") or []
    parent = ancestry[0] if ancestry and isinstance(ancestry[0], dict) else {}
    executable = (proc.get("executable") or {}) if isinstance(proc.get("executable"), dict) else {}
    digest = (executable.get("hash") or {}) if isinstance(executable.get("hash"), dict) else {}
    sha256 = digest.get("sha256")
    uid = (proc.get("creds") or {}).get("uid")
    user = "root" if uid == 0 else (str(uid) if uid is not None else "")
    host_id = host.get("id", "")
    return {
        "schema_version": record.get("schema_version", "1.0"),
        "event_id": record["id"],
        "timestamp": record.get("time", ""),
        "event_type": "process_create",
        "host_id": host_id,
        "source": {
            "kind": "linux_endpoint",
            "provider": prov.get("provider", ""),
            "channel": prov.get("mechanism"),
            "record_id": record["id"],
        },
        "agent": {"id": sensor.get("id", ""), "version": sensor.get("version", "")},
        "host": {"id": host_id, "hostname": host.get("hostname", host_id), "os": {"family": "linux"}},
        "user": {"name": user, "domain": None, "sid": None, "full": user},
        "process": {
            "entity_id": proc.get("entity_id"),
            "process_guid": proc.get("entity_id"),
            "pid": proc.get("pid"),
            "ppid": proc.get("ppid"),
            "name": proc.get("name"),
            "executable": executable.get("path"),
            "command_line": _command_line(proc),
            "user": user,
            "user_sid": None,
            "file_hash": sha256,
            "sha256": sha256,
            "start_time_ticks": proc.get("start_ticks"),
        },
        "parent": {
            "entity_id": parent.get("entity_id"),
            "process_guid": parent.get("entity_id"),
            "pid": proc.get("ppid"),
            "name": parent.get("name"),
        },
        "file": {"path": executable.get("path"), "hash": sha256},
        "_raw_linux_record": record,
    }
