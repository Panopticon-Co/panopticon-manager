from __future__ import annotations

import json
import uuid
from pathlib import Path

from fastapi.testclient import TestClient

_SAMPLES_DIR = Path(__file__).resolve().parents[1] / "vendor" / "eyedetect" / "samples"
_SAMPLE = _SAMPLES_DIR / "officer_live_sample.ndjson"


def _headers(batch_id: str | None = None) -> dict:
    return {
        "Content-Type": "application/x-ndjson",
        "X-Panopticon-Batch-Id": batch_id or str(uuid.uuid4()),
        "X-Panopticon-Agent-Id": "test-agent",
        "X-Panopticon-Protocol": "1",
    }


def test_happy_path_accepts_every_line(client: TestClient) -> None:
    body = _SAMPLE.read_text()
    line_count = len([line for line in body.splitlines() if line.strip()])

    resp = client.post("/api/v1/ingest", content=body, headers=_headers())

    assert resp.status_code == 200
    data = resp.json()
    assert data["received"] == line_count
    assert data["accepted"] == line_count
    assert data["duplicates"] == 0
    assert data["rejected"] == []


def test_replayed_batch_dedupes_by_event_id(client: TestClient) -> None:
    body = _SAMPLE.read_text()
    headers = _headers()
    first = client.post("/api/v1/ingest", content=body, headers=headers)
    # New batch id, same events.
    second = client.post("/api/v1/ingest", content=body, headers=_headers())

    assert first.status_code == 200
    assert second.status_code == 200
    assert second.json()["accepted"] == 0
    assert second.json()["duplicates"] == first.json()["accepted"]


def test_partial_bad_batch_returns_200_with_rejected_line(client: TestClient) -> None:
    lines = [line for line in _SAMPLE.read_text().splitlines() if line.strip()]
    body = "\n".join(lines) + "\nthis is not json\n"

    resp = client.post("/api/v1/ingest", content=body, headers=_headers())

    assert resp.status_code == 200
    data = resp.json()
    assert data["received"] == len(lines) + 1
    assert data["accepted"] == len(lines)
    assert len(data["rejected"]) == 1
    assert data["rejected"][0]["line"] == len(lines) + 1
    assert data["rejected"][0]["reason"] == "json_invalid"


def test_oversize_batch_is_413(client: TestClient) -> None:
    one_line = next(line for line in _SAMPLE.read_text().splitlines() if line.strip())
    body = "\n".join([one_line] * 1001)

    resp = client.post("/api/v1/ingest", content=body, headers=_headers())

    assert resp.status_code == 413


def test_non_ndjson_content_type_is_422(client: TestClient) -> None:
    resp = client.post(
        "/api/v1/ingest",
        content='{"not": "ndjson"}',
        headers={**_headers(), "Content-Type": "application/json"},
    )

    assert resp.status_code == 422


def test_unsupported_protocol_is_422(client: TestClient) -> None:
    resp = client.post(
        "/api/v1/ingest",
        content=_SAMPLE.read_text(),
        headers={**_headers(), "X-Panopticon-Protocol": "2"},
    )

    assert resp.status_code == 422


def test_linux_procfs_v4_event_is_accepted(client: TestClient) -> None:
    event = json.loads(next(line for line in _SAMPLE.read_text().splitlines() if line.strip()))
    event["schema_version"] = "0.4"
    event["source"] = {
        "kind": "linux_procfs",
        "provider": "procfs",
        "channel": None,
        "record_id": None,
    }
    response = client.post("/api/v1/ingest", content=json.dumps(event) + "\n", headers=_headers())
    assert response.status_code == 200
    assert response.json()["accepted"] == 1
