"""Canonical endpoint records. Payload domains evolve independently of legacy events."""

from __future__ import annotations

import hashlib
import re
from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


class Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


class EndpointIdentity(Strict):
    agent_id: str = Field(min_length=1, max_length=128)
    host_id: str = Field(min_length=1, max_length=128)
    device_id: str = Field(min_length=1, max_length=256)
    installation_id: str = Field(pattern=r"^[0-9a-f]{64}$")
    boot_id: str | None = Field(pattern=r"^boot_[0-9a-f]{64}$")


class Provenance(Strict):
    kind: str = Field(min_length=1, max_length=128)
    provider: str = Field(min_length=1, max_length=512)
    channel: str | None = Field(max_length=512)
    native_record_id: str | None = Field(pattern=r"^(0|[1-9][0-9]{0,19})$")
    native_observation_id: str | None = Field(max_length=128)
    continuity: Literal["unverified", "continuous", "gap", "snapshot"]
    collector_epoch: str = Field(pattern=r"^epoch_[0-9a-f]{64}$")
    collector_generation: str | None = Field(default=None, pattern=r"^[1-9][0-9]{0,19}$")
    capture_clock: str | None = Field(default=None, min_length=1, max_length=64)
    capture_uptime_ms: str | None = Field(default=None, pattern=r"^(0|[1-9][0-9]{0,19})$")
    sequence: str = Field(pattern=r"^[1-9][0-9]{0,19}$")
    received_at: str = Field(
        pattern=r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{3}Z$"
    )
    event_time_ns: str = Field(pattern=r"^-?(0|[1-9][0-9]{0,18})$")

    @field_validator("received_at")
    @classmethod
    def timestamp(cls, value: str) -> str:
        if not re.fullmatch(
            r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{3}Z", value
        ):
            raise ValueError("UTC millisecond timestamp required")
        datetime.fromisoformat(value.replace("Z", "+00:00"))
        return value

    @model_validator(mode="after")
    def bounds(self) -> "Provenance":
        for value in (
            self.sequence,
            self.native_record_id,
            self.collector_generation,
            self.capture_uptime_ms,
        ):
            if value is not None and int(value) > 2**64 - 1:
                raise ValueError("opaque unsigned integer exceeds uint64")
        if (self.capture_clock is None) != (self.capture_uptime_ms is None):
            raise ValueError("capture clock and uptime must be supplied together")
        if not -(2**63) <= int(self.event_time_ns) <= 2**63 - 1:
            raise ValueError("event time exceeds signed nanosecond range")
        return self


class ProcessReference(Strict):
    observed_pid: int = Field(ge=0, le=2**32 - 1)
    entity_id: str | None = Field(pattern=r"^proc_[0-9a-f]{64}$")
    resolution: Literal["native_exact", "source_scoped", "native_unscoped", "unresolved"]
    native_creation_ticks: str | None = Field(pattern=r"^(0|[1-9][0-9]{0,19})$")
    source_guid: str | None = Field(min_length=1, max_length=256)
    boot_id: str | None = Field(pattern=r"^boot_[0-9a-f]{64}$")
    source_namespace: str = Field(min_length=1, max_length=1024)

    @model_validator(mode="after")
    def identity_invariants(self) -> "ProcessReference":
        if self.native_creation_ticks is not None and int(self.native_creation_ticks) > 2**64 - 1:
            raise ValueError("native creation token exceeds uint64")
        if self.resolution == "native_exact" and not (
            self.entity_id
            and self.boot_id
            and self.native_creation_ticks
            and int(self.native_creation_ticks)
        ):
            raise ValueError("native exact identity requires boot and exact creation token")
        if self.resolution == "source_scoped" and not (self.entity_id and self.source_guid):
            raise ValueError("source-scoped identity requires a source GUID")
        if self.resolution in ("unresolved", "native_unscoped") and self.entity_id is not None:
            raise ValueError("unresolved observations cannot invent a process entity")
        return self


class EndpointRecord(Strict):
    schema_version: Literal["1.0"]
    record_id: str = Field(pattern=r"^rec_[0-9a-f]{64}$")
    kind: Literal["observation", "state", "health", "gap", "evidence", "command_result"]
    category: str = Field(min_length=1, max_length=128)
    observed_at: str = Field(
        pattern=r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{3}Z$"
    )
    endpoint: EndpointIdentity
    provenance: Provenance
    subject: ProcessReference | None
    data: dict[str, Any]

    @field_validator("observed_at")
    @classmethod
    def timestamp(cls, value: str) -> str:
        return Provenance.timestamp(value)

    @model_validator(mode="after")
    def scope_invariants(self) -> "EndpointRecord":
        def verify_reference(reference: ProcessReference):
            if reference.boot_id != self.endpoint.boot_id:
                raise ValueError("process reference boot scope disagrees with endpoint")
            if reference.resolution == "native_exact":
                fields = [
                    "native-process-instance-v1",
                    self.endpoint.host_id,
                    self.endpoint.boot_id,
                    str(reference.observed_pid),
                    reference.native_creation_ticks,
                ]
            elif reference.resolution == "source_scoped":
                fields = [
                    "source-process-instance-v1",
                    self.endpoint.host_id,
                    self.endpoint.boot_id or "unknown",
                    reference.source_namespace,
                    str(reference.observed_pid),
                    reference.source_guid,
                ]
            else:
                fields = None
            if fields is not None:
                canonical = "".join(
                    str(len(value.encode("utf-8"))) + ":" + value for value in fields
                )
                expected = "proc_" + hashlib.sha256(canonical.encode("utf-8")).hexdigest()
                if reference.entity_id != expected:
                    raise ValueError("process identity digest disagrees with its exact scope/facts")

        if self.subject is not None:
            verify_reference(self.subject)
            reference = self.subject
            process = self.data.get("process")
            if isinstance(process, dict) and (
                process.get("entity_id") != reference.entity_id
                or process.get("pid") != reference.observed_pid
                or process.get("start_time_ticks") != reference.native_creation_ticks
            ):
                raise ValueError("process payload contradicts authoritative subject reference")
            if isinstance(process, dict):
                parent = process.get("parent")
                if isinstance(parent, dict):
                    parent_raw = parent.get("identity")
                    if parent_raw is not None:
                        parent_reference = ProcessReference.model_validate(parent_raw)
                        verify_reference(parent_reference)
                        if (
                            parent.get("pid") != parent_reference.observed_pid
                            or parent.get("entity_id") != parent_reference.entity_id
                        ):
                            raise ValueError("parent payload contradicts its explicit reference")
                    elif parent.get("entity_id") is not None:
                        raise ValueError("parent entity requires an explicit reference")
        if (
            self.kind == "observation"
            and self.category in {"process", "network", "file", "registry", "image_load"}
            and self.subject is None
        ):
            raise ValueError(
                "process-attributed observation must represent identity uncertainty explicitly"
            )
        if self.kind == "observation" and self.category in {
            "process",
            "network",
            "file",
            "registry",
            "image_load",
        }:
            if (
                not isinstance(self.data.get("process"), dict)
                or not isinstance(self.data.get("event"), dict)
                or self.data["event"].get("category") != self.category
            ):
                raise ValueError("observation payload requires process and matching category")
        if self.kind == "health":
            capabilities = self.data.get("capabilities")
            if not isinstance(capabilities, list) or len(capabilities) > 512:
                raise ValueError("health requires bounded capability coverage")
            known = {"healthy", "degraded", "unavailable", "disabled", "unsupported", "blind"}
            ids = set()
            for capability in capabilities:
                if (
                    not isinstance(capability, dict)
                    or capability.get("state") not in known
                    or not isinstance(capability.get("id"), str)
                ):
                    raise ValueError("invalid capability state")
                if capability["id"] in ids:
                    raise ValueError("duplicate capability identity")
                ids.add(capability["id"])
        return self
