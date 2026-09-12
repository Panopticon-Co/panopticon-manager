# Linux telemetry schema 0.4

Schema 0.4 is an additive update to the authoritative endpoint event contract
in `panopticon-agent/schema/event.schema.json`. It preserves every schema 0.2
and 0.3 event and all Windows source kinds.

`source.kind = "linux_procfs"` identifies bounded Linux procfs snapshots. The
provider is `procfs`; `channel` and `record_id` are null because procfs has no
event-log channel or monotonic source record identifier. The existing process
and network event families are reused rather than creating a Linux-only wire
format. This remains a metadata-only interface and does not claim socket PID
attribution.

Manager ingestion accepts schema 0.4 alongside 0.1 through 0.3. The shared
contract test validates both the JSON Schema and the Manager Pydantic mirror,
including rejection of unknown source kinds.

This change defines telemetry validation only. It does not authorize an agent,
add enrollment, or add response command execution.
