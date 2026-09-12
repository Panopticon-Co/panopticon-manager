"""Two-way contract test: manager.wire.telemetry.TelemetryEvent (pydantic) and
panopticon-agent/schema/event.schema.json (the authoritative JSON Schema)
must accept and reject the same corpora. See docs/adr/002.
"""

from __future__ import annotations

import copy
import json
from pathlib import Path

import jsonschema
import pytest
from pydantic import ValidationError

from manager.wire.telemetry import TelemetryEvent

_WORKSPACE_ROOT = Path(__file__).resolve().parents[2]
_SCHEMA_PATH = _WORKSPACE_ROOT / "panopticon-agent" / "schema" / "event.schema.json"
_SAMPLES_DIR = Path(__file__).resolve().parents[1] / "vendor" / "eyedetect" / "samples"

_SCHEMA = json.loads(_SCHEMA_PATH.read_text())


def _sample_events() -> list[dict]:
    events: list[dict] = []
    for path in (
        _SAMPLES_DIR / "officer_live_sample.ndjson",
        _SAMPLES_DIR / "v3" / "mixed_families_sample.ndjson",
    ):
        for line in path.read_text().splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            events.append(json.loads(line))
    return events


@pytest.mark.parametrize("event", _sample_events(), ids=lambda e: e["event"]["id"])
def test_valid_samples_accepted_by_both(event: dict) -> None:
    jsonschema.validate(event, _SCHEMA)  # raises on rejection
    TelemetryEvent.model_validate(event)  # raises on rejection


def _base_process_event() -> dict:
    for event in _sample_events():
        if event["event"]["category"] == "process":
            return copy.deepcopy(event)
    raise AssertionError("no process-category sample found")


def _assert_both_reject(event: dict) -> None:
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(event, _SCHEMA)
    with pytest.raises(ValidationError):
        TelemetryEvent.model_validate(event)


def test_missing_required_field_rejected_by_both() -> None:
    event = _base_process_event()
    del event["host"]
    _assert_both_reject(event)


def test_bad_timestamp_format_rejected_by_both() -> None:
    event = _base_process_event()
    event["event"]["timestamp"] = "2026-08-30 09:14:02"
    _assert_both_reject(event)


def test_bad_event_id_pattern_rejected_by_both() -> None:
    event = _base_process_event()
    event["event"]["id"] = "not-a-valid-event-id"
    _assert_both_reject(event)


def test_unknown_property_rejected_by_both() -> None:
    event = _base_process_event()
    event["unexpected_field"] = "should not be allowed"
    _assert_both_reject(event)


def test_category_type_mismatch_rejected_by_both() -> None:
    event = _base_process_event()
    event["event"]["type"] = "connect"  # valid for network, not process
    _assert_both_reject(event)


def test_linux_procfs_source_is_an_additive_v4_extension() -> None:
    event = _base_process_event()
    event["schema_version"] = "0.4"
    event["source"] = {
        "kind": "linux_procfs",
        "provider": "procfs",
        "channel": None,
        "record_id": None,
    }
    jsonschema.validate(event, _SCHEMA)
    TelemetryEvent.model_validate(event)


def test_unknown_source_kind_is_rejected_by_both() -> None:
    event = _base_process_event()
    event["source"]["kind"] = "linux_untrusted"
    _assert_both_reject(event)
