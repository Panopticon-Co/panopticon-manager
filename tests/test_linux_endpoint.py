"""Linux endpoint record 1.0 ingest: validation, identity binding, acknowledgement, loss.

Fixtures in tests/fixtures/linux_endpoint are real panopticon-sensord output (one per record type)
copied from panopticon-contracts; the helpers re-number them so gap scenarios can be built.
"""

from __future__ import annotations

import copy
import json
import uuid
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from manager.wire import linux_endpoint as wire
from tests.conftest import enroll_test_agent

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "linux_endpoint"
AGENT = "linux-agent-1"
URL = "/api/v2/linux-endpoint/records"


def fixture(name: str) -> dict:
    return json.loads((FIXTURES / f"{name}.json").read_text(encoding="utf-8"))


def numbered(name: str, seq: int, **changes) -> dict:
    record = copy.deepcopy(fixture(name))
    record["seq"] = seq
    for key, value in changes.items():
        record[key] = value
    record["id"] = wire.expected_id(record)
    return record


def body(records: list[dict]) -> str:
    return "\n".join(json.dumps(r, separators=(",", ":")) for r in records) + "\n"


def headers(token: str, agent: str = AGENT, protocol: str = "linux-endpoint/1.0") -> dict:
    return {
        "Content-Type": "application/x-ndjson",
        "Authorization": f"Bearer {token}",
        "X-Panopticon-Agent-Id": agent,
        "X-Panopticon-Batch-Id": str(uuid.uuid4()),
        "X-Panopticon-Protocol": protocol,
    }


@pytest.fixture()
def enrolled(client: TestClient) -> str:
    host_id = fixture("process-exec")["host"]["id"]
    response = enroll_test_agent(client, AGENT, host_id)
    assert response.status_code == 200, response.text
    return response.json()["access_token"]


def test_every_real_record_type_is_accepted(client: TestClient, enrolled: str) -> None:
    names = sorted(p.stem for p in FIXTURES.glob("*.json"))
    records = [numbered(name, seq) for seq, name in enumerate(names, 1)]
    response = client.post(URL, content=body(records), headers=headers(enrolled))
    assert response.status_code == 200, response.text
    data = response.json()
    assert data["accepted"] == len(names) == 38
    assert data["rejected"] == []
    assert data["streams"][0]["acked_through_seq"] == len(names)
    assert data["streams"][0]["missing_ranges"] == []


def test_a_gap_is_reported_and_not_acknowledged_past(client: TestClient, enrolled: str) -> None:
    records = [numbered("process-exec", seq) for seq in (1, 2, 3, 6, 7)]
    stream = client.post(URL, content=body(records), headers=headers(enrolled)).json()["streams"][0]
    assert stream["acked_through_seq"] == 3
    assert stream["highest_seq"] == 7
    assert stream["missing_ranges"] == [[4, 5]]

    fill = [numbered("process-exec", seq) for seq in (4, 5)]
    stream = client.post(URL, content=body(fill), headers=headers(enrolled)).json()["streams"][0]
    assert stream["acked_through_seq"] == 7
    assert stream["missing_ranges"] == []


def test_a_retransmitted_batch_is_deduplicated_and_still_acknowledged(
    client: TestClient, enrolled: str
) -> None:
    records = [numbered("file-create", seq) for seq in (1, 2, 3)]
    client.post(URL, content=body(records), headers=headers(enrolled))
    again = client.post(URL, content=body(records), headers=headers(enrolled)).json()
    assert again["accepted"] == 0
    assert again["duplicates"] == 3
    assert again["streams"][0]["acked_through_seq"] == 3


def test_a_log_that_starts_above_one_is_not_blamed_for_older_records(
    client: TestClient, enrolled: str
) -> None:
    records = [numbered("process-exit", seq) for seq in (500, 501, 502)]
    stream = client.post(URL, content=body(records), headers=headers(enrolled)).json()["streams"][0]
    assert stream["acked_through_seq"] == 502
    assert stream["missing_ranges"] == []


def test_a_different_record_for_an_occupied_id_is_refused_not_overwritten(
    client: TestClient, enrolled: str
) -> None:
    original = numbered("process-exec", 1)
    client.post(URL, content=body([original]), headers=headers(enrolled))
    forged = copy.deepcopy(original)
    forged["process"]["name"] = "forged"
    data = client.post(URL, content=body([forged]), headers=headers(enrolled)).json()
    assert data["accepted"] == 0
    assert [r["reason"] for r in data["rejected"]] == ["id_conflict"]


def test_an_id_that_is_not_derived_from_the_sequence_is_rejected(
    client: TestClient, enrolled: str
) -> None:
    record = numbered("process-exec", 1)
    record["seq"] = 2
    data = client.post(URL, content=body([record]), headers=headers(enrolled)).json()
    assert data["accepted"] == 0
    assert data["rejected"][0]["reason"] == "id_mismatch"


def test_bad_lines_reject_only_themselves(client: TestClient, enrolled: str) -> None:
    good = numbered("process-exec", 1)
    unknown_key = numbered("process-exec", 2, surprise=1)
    duplicate_key = '{"schema_version":"1.0","schema_version":"1.0"}'
    text = body([good, unknown_key]) + duplicate_key + "\nnot json\n"
    data = client.post(URL, content=text, headers=headers(enrolled)).json()
    assert data["accepted"] == 1
    assert sorted(r["reason"] for r in data["rejected"]) == [
        "json_invalid", "json_invalid", "schema_invalid"
    ]


def test_a_record_naming_another_host_fails_the_whole_request(
    client: TestClient, enrolled: str
) -> None:
    record = numbered("process-exec", 1)
    record["host"]["id"] = "someone-elses-host"
    record["id"] = wire.expected_id(record)
    response = client.post(
        URL, content=body([numbered("process-exec", 2), record]), headers=headers(enrolled)
    )
    assert response.status_code == 403
    health = numbered("health", 3)
    client.post(URL, content=body([health]), headers=headers(enrolled))
    # Only the later, legitimate request stored anything.
    stored = client.get(
        f"/api/v2/linux-endpoint/hosts/{health['host']['id']}/health", headers=headers(enrolled)
    )
    assert stored.status_code == 200


def test_authentication_and_protocol_are_required(client: TestClient, enrolled: str) -> None:
    payload = body([numbered("process-exec", 1)])
    assert client.post(URL, content=payload, headers=headers("wrong")).status_code == 401
    assert client.post(
        URL, content=payload, headers=headers(enrolled, protocol="2")
    ).status_code == 422
    plain = headers(enrolled)
    plain["Content-Type"] = "application/json"
    assert client.post(URL, content=payload, headers=plain).status_code == 422


def test_empty_and_oversized_batches_are_refused(client: TestClient, enrolled: str) -> None:
    assert client.post(URL, content="\n\n", headers=headers(enrolled)).status_code == 413
    many = body([numbered("process-exec", seq) for seq in range(1, 1002)])
    assert client.post(URL, content=many, headers=headers(enrolled)).status_code == 413


def test_the_latest_health_record_can_be_read_back_by_its_own_agent(
    client: TestClient, enrolled: str
) -> None:
    health = numbered("health", 9)
    client.post(URL, content=body([health]), headers=headers(enrolled))
    host_id = health["host"]["id"]
    response = client.get(f"/api/v2/linux-endpoint/hosts/{host_id}/health",
                          headers=headers(enrolled))
    assert response.status_code == 200
    assert response.json()["health"]["coverage"] == health["health"]["coverage"]
    other = client.get("/api/v2/linux-endpoint/hosts/another-host/health",
                       headers=headers(enrolled))
    assert other.status_code == 403


def test_an_older_health_record_does_not_replace_a_newer_one(
    client: TestClient, enrolled: str
) -> None:
    newer = numbered("health", 20, time="2030-01-01T00:00:00.000000000Z",
                     observed_time="2030-01-01T00:00:00.000000000Z")
    older = numbered("health", 21, time="2020-01-01T00:00:00.000000000Z",
                     observed_time="2020-01-01T00:00:00.000000000Z")
    client.post(URL, content=body([newer, older]), headers=headers(enrolled))
    response = client.get(
        f"/api/v2/linux-endpoint/hosts/{newer['host']['id']}/health", headers=headers(enrolled)
    )
    assert response.json()["record_id"] == newer["id"]


def test_a_response_record_needs_its_body_and_a_closed_action(client: TestClient, enrolled: str) -> None:
    missing = numbered("response-action-kill", 1)
    del missing["response"]
    unknown = numbered("response-action-kill", 2)
    unknown["response"]["action"] = "RUN_SHELL"
    extra = numbered("response-action-kill", 3)
    extra["response"]["command_line"] = "rm -rf /"
    good = numbered("response-action-kill", 4)
    response = client.post(URL, content=body([missing, unknown, extra, good]), headers=headers(enrolled))
    assert response.status_code == 200, response.text
    data = response.json()
    assert data["accepted"] == 1
    assert [r["reason"] for r in data["rejected"]] == ["schema_invalid"] * 3


def test_a_policy_decision_is_a_recommendation_with_its_subject(client: TestClient, enrolled: str) -> None:
    # A local policy decides; it never acts. A match whose action is not one of the recommendations, that lost
    # the record it is about, or that mixes in change fields, is not a policy record.
    missing = numbered("policy-match", 1)
    del missing["policy"]
    acting = numbered("policy-match", 2)
    acting["policy"]["action"] = "kill"
    orphan = numbered("policy-match", 3)
    del orphan["policy"]["subject"]
    mixed = numbered("policy-change", 4)
    mixed["policy"]["rule_id"] = "tmp-exec"
    good = [numbered("policy-match", 5), numbered("policy-change", 6)]
    response = client.post(URL, content=body([missing, acting, orphan, mixed, *good]), headers=headers(enrolled))
    assert response.status_code == 200, response.text
    data = response.json()
    assert data["accepted"] == 2
    assert [r["reason"] for r in data["rejected"]] == ["schema_invalid"] * 4
