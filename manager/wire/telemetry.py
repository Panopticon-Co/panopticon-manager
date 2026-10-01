"""Pydantic mirror of panopticon-agent/schema/event.schema.json (Schema 0.3,
additive over 0.2). Kept field-for-field identical to that file — required
lists, enums, and patterns below are transcribed from it directly, not
reinvented; a contract test (tests/test_ingest_contract.py) asserts this
model and the JSON Schema accept/reject the same corpora.

``schema_version`` accepts "0.1" in addition to the schema file's own
["0.2", "0.3"] enum, matching OfficerIngestionAdapter.SUPPORTED_SCHEMA_VERSIONS
in the vendored engine — see docs/adr/002-wire-protocol-ack-semantics.md.
"""

from __future__ import annotations

from typing import Annotated, Literal, Optional

from pydantic import BaseModel, ConfigDict, Field, StringConstraints, model_validator

NullableStr = Optional[Annotated[str, StringConstraints(min_length=1)]]

_EVENT_ID_RE = r"^evt_[0-9a-f]{64}$"
_PROCESS_ENTITY_ID_RE = r"^proc_[0-9a-f]{64}$"
_SHA256_RE = r"^[0-9a-f]{64}$"
_TIMESTAMP_RE = r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{3}Z$"

_CATEGORY_TYPES: dict[str, tuple[str, ...]] = {
    # Schema 0.5 added process 'stop' and the dns/process_access/remote_thread/
    # script_block families; everything else is unchanged from 0.3.
    "process": ("start", "stop"),
    "network": ("connect",),
    "file": ("create", "delete", "rename"),
    "registry": ("add_key", "delete_key", "set_value", "rename_key"),
    "image_load": ("load",),
    "dns": ("query",),
    "process_access": ("access",),
    "remote_thread": ("create",),
    "script_block": ("execute",),
}

_HEX_RE = r"^0x[0-9a-fA-F]+$"


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


class EventMeta(_Strict):
    id: str = Field(pattern=_EVENT_ID_RE)
    category: Literal[
        "process", "network", "file", "registry", "image_load",
        "dns", "process_access", "remote_thread", "script_block",
    ]
    type: Annotated[str, StringConstraints(min_length=1)]
    timestamp: str = Field(pattern=_TIMESTAMP_RE)


class SourceMeta(_Strict):
    kind: Literal["etw", "sysmon", "windows_event_log", "linux_procfs"]
    provider: Annotated[str, StringConstraints(min_length=1)]
    channel: NullableStr
    record_id: Optional[int] = Field(ge=0)


class AgentMeta(_Strict):
    id: Annotated[str, StringConstraints(min_length=1)]
    version: Annotated[str, StringConstraints(min_length=1)]


class OsMeta(_Strict):
    name: Annotated[str, StringConstraints(min_length=1)]
    build: Annotated[str, StringConstraints(min_length=1)]


class HostMeta(_Strict):
    id: Annotated[str, StringConstraints(min_length=1)]
    hostname: Annotated[str, StringConstraints(min_length=1)]
    os: OsMeta


class UserMeta(_Strict):
    name: NullableStr
    domain: NullableStr
    sid: NullableStr


class HashMeta(_Strict):
    sha256: Optional[str] = Field(pattern=_SHA256_RE)


class ParentMeta(_Strict):
    entity_id: Optional[str] = Field(pattern=_PROCESS_ENTITY_ID_RE)
    pid: Optional[int] = Field(ge=0, le=4294967295)
    name: NullableStr


class ProcessMeta(_Strict):
    entity_id: str = Field(pattern=_PROCESS_ENTITY_ID_RE)
    pid: int = Field(ge=0, le=4294967295)
    name: NullableStr
    executable: NullableStr
    command_line: NullableStr
    # Optional, nullable, non-negative -- mirrors event.schema.json's
    # nullableStartTimeTicks exactly (an opaque OS-native process-creation
    # token, never a duration/wall-clock value). Omitted here previously,
    # meaning this "field-for-field identical" mirror silently disagreed
    # with the canonical schema: extra="forbid" made this model reject any
    # real event that carried the field the schema itself permits.
    start_time_ticks: Optional[int] = Field(default=None, ge=0)
    parent: ParentMeta
    hash: HashMeta


class NetworkMeta(_Strict):
    direction: Literal["inbound", "outbound"]
    protocol: Optional[Literal["tcp", "udp"]]
    source_ip: NullableStr
    source_port: Optional[int] = Field(ge=0, le=65535)
    destination_ip: NullableStr
    destination_port: Optional[int] = Field(ge=0, le=65535)
    destination_hostname: NullableStr


class FileMeta(_Strict):
    operation: Literal["create", "delete", "rename"]
    path: NullableStr
    target_path: NullableStr
    previous_path: NullableStr
    hash: HashMeta


class RegistryMeta(_Strict):
    operation: Literal["add_key", "delete_key", "set_value", "rename_key"]
    key_path: NullableStr
    value_name: NullableStr
    value_type: NullableStr
    value_data: NullableStr


class ImageLoadMeta(_Strict):
    path: NullableStr
    is_signed: Optional[bool]
    signature_status: NullableStr
    hash: HashMeta


# -- Schema 0.5 family blocks ------------------------------------------


class DnsMeta(_Strict):
    query_name: NullableStr
    query_status: Optional[int] = Field(ge=0, le=4294967295)
    query_results: NullableStr


class TargetMeta(_Strict):
    entity_id: Optional[str] = Field(pattern=_PROCESS_ENTITY_ID_RE)
    pid: Optional[int] = Field(ge=0, le=4294967295)
    executable: NullableStr
    user: NullableStr


class ProcessAccessMeta(_Strict):
    target: TargetMeta
    granted_access: Optional[str] = Field(pattern=_HEX_RE)
    call_trace: NullableStr


class RemoteThreadMeta(_Strict):
    target: TargetMeta
    new_thread_id: Optional[int] = Field(ge=0, le=4294967295)
    start_address: Optional[str] = Field(pattern=_HEX_RE)
    start_module: NullableStr
    start_function: NullableStr


class ScriptBlockMeta(_Strict):
    script_block_id: NullableStr
    message_number: Optional[int] = Field(ge=0, le=4294967295)
    message_total: Optional[int] = Field(ge=0, le=4294967295)
    path: NullableStr
    # text has a 16384-char cap in the JSON Schema; the mirror keeps it nullable
    # and non-empty, and does not re-enforce the length (the agent already did).
    text: NullableStr
    text_length: int = Field(ge=0)
    text_truncated: bool
    text_sha256: Optional[str] = Field(pattern=_SHA256_RE)


class TelemetryEvent(_Strict):
    schema_version: Literal["0.1", "0.2", "0.3", "0.4", "0.5"]
    event: EventMeta
    source: SourceMeta
    agent: AgentMeta
    host: HostMeta
    user: UserMeta
    process: ProcessMeta
    network: Optional[NetworkMeta] = None
    file: Optional[FileMeta] = None
    registry: Optional[RegistryMeta] = None
    image_load: Optional[ImageLoadMeta] = None
    dns: Optional[DnsMeta] = None
    process_access: Optional[ProcessAccessMeta] = None
    remote_thread: Optional[RemoteThreadMeta] = None
    script_block: Optional[ScriptBlockMeta] = None

    @model_validator(mode="after")
    def _category_binds_type_and_family_block(self) -> "TelemetryEvent":
        category = self.event.category
        allowed_types = _CATEGORY_TYPES[category]
        if self.event.type not in allowed_types:
            raise ValueError(
                f"event.type {self.event.type!r} is not valid for event.category "
                f"{category!r} (expected one of {allowed_types})"
            )
        if category != "process" and getattr(self, category) is None:
            raise ValueError(f"event.category {category!r} requires the {category!r} block")
        return self
