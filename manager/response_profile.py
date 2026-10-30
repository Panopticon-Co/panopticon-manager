"""Current authenticated runtime reports, independent of delayed telemetry."""

import base64
import json
from datetime import datetime, timezone
from typing import Literal

from fastapi import HTTPException
from pydantic import BaseModel, ConfigDict, Field, StrictBool, model_serializer, model_validator
from response_engine.contract import Action

from manager.wire.linux_endpoint import strict_json

CHANGING = {"KILL_PROCESS", "QUARANTINE_FILE", "ISOLATE_HOST", "RELEASE_HOST_ISOLATION"}


class RuntimeProfile(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    schema_version: Literal["1", "2"]
    platform: Literal["linux", "windows"]
    host_id: str = Field(min_length=1, max_length=256)
    boot_id: str | None = Field(pattern=r"^boot_[0-9a-f]{64}$")
    mode: Literal["off", "dry_run", "enforce"]
    implemented_actions: list[Action] = Field(max_length=7)
    allowed_actions: list[Action] = Field(max_length=7)
    require_boot_binding: StrictBool
    require_signature: StrictBool
    artifact_protocol: Literal["signed-json-v2-resume-v1"] | None = None
    require_collection_acceptance: StrictBool | None = None

    @model_serializer(mode="wrap")
    def versioned_shape(self, handler):
        result = handler(self)
        if self.schema_version == "1":
            result.pop("artifact_protocol", None)
            result.pop("require_collection_acceptance", None)
        return result

    @model_validator(mode="after")
    def coherent_policy(self):
        new_fields = {"artifact_protocol", "require_collection_acceptance"}
        if self.schema_version == "1" and new_fields & self.model_fields_set:
            raise ValueError("legacy profile cannot claim artifact delivery capability")
        if self.schema_version == "2" and (
            not new_fields <= self.model_fields_set or self.require_collection_acceptance is None
        ):
            raise ValueError("profile version 2 must explicitly report artifact protocol")
        for values in (self.implemented_actions, self.allowed_actions):
            if len(values) != len(set(values)):
                raise ValueError("duplicate response action")
        if not set(self.allowed_actions) <= set(self.implemented_actions):
            raise ValueError("allowed actions must be implemented")
        return self


def parse_header(value):
    if value is None:
        return None
    if len(value) > 4096 or not value.isascii():
        raise HTTPException(
            422, "response profile must be Base64 UTF-8 JSON through 4096 header bytes"
        )
    try:
        return RuntimeProfile.model_validate(
            strict_json(base64.b64decode(value, validate=True).decode("utf-8"))
        ).model_dump(mode="json", exclude_unset=True)
    except (ValueError, RecursionError) as exc:
        raise HTTPException(422, "invalid response runtime profile") from exc


def current_profile(conn, agent_id, host_id):
    row = conn.execute(
        "SELECT profile_json,profile_observed_at,profile_host_id FROM agent_response_channels "
        "WHERE agent_id=?",
        (agent_id,),
    ).fetchone()
    if row is None or row["profile_json"] is None:
        return {"state": "unknown", "report": None, "observed_at": None}
    age = (
        datetime.now(timezone.utc) - datetime.fromisoformat(row["profile_observed_at"])
    ).total_seconds()
    state = "recent" if 0 <= age <= 300 else "stale"
    if row["profile_host_id"] != host_id:
        state = "invalidated"
    return {
        "state": state,
        "report": json.loads(row["profile_json"]),
        "observed_at": row["profile_observed_at"],
        "seconds_since_report": max(0, int(age)),
    }


def policy_block(profile, action, target):
    if profile["state"] != "recent":
        return None
    report = profile["report"]
    if report["mode"] == "off":
        return "Endpoint reports response mode off"
    if action not in report["implemented_actions"]:
        return "Endpoint reports action is not implemented"
    if action not in report["allowed_actions"]:
        return "Endpoint policy does not allow this action"
    if report["mode"] == "dry_run" and action in CHANGING:
        return "Endpoint is in dry-run mode; changing actions cannot execute"
    if action in {"KILL_PROCESS", "COLLECT_PROCESS_INFO"}:
        if "boot_id" in target and target["boot_id"] != report["boot_id"]:
            return "Retained process target belongs to a different or unknown endpoint boot"
        if report["require_boot_binding"] and "boot_id" not in target:
            return "Endpoint requires a boot-bound process target"
    return None


def delivery_predicate(profile):
    """Filter blocked work before LIMIT so it cannot starve later eligible commands."""
    if profile["state"] != "recent":
        return "1", []
    report = profile["report"]
    allowed = [
        a
        for a in report["allowed_actions"]
        if report["mode"] != "off" and (report["mode"] != "dry_run" or a not in CHANGING)
    ]
    if not allowed:
        return "0", []
    clause = "json_extract(command_json,'$.action') IN (" + ",".join("?" for _ in allowed) + ")"
    clause += (
        " AND (json_extract(command_json,'$.action') "
        "NOT IN ('KILL_PROCESS','COLLECT_PROCESS_INFO') "
        "OR (json_extract(command_json,'$.target.boot_id') IS NULL AND ?) "
        "OR json_extract(command_json,'$.target.boot_id')=?)"
    )
    return clause, allowed + [not report["require_boot_binding"], report["boot_id"]]
