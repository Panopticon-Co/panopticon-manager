from __future__ import annotations

import copy
import hashlib
import json
import subprocess
from pathlib import Path

import pytest

import manager.vendor_path  # noqa: F401  (must precede vendored engine imports)
from manager import db
from manager.wire.endpoint import EndpointRecord
from tests.conftest import enroll_test_agent

FIXTURES = (
    Path(__file__).resolve().parents[2]
    / "panopticon-contracts/fixtures/endpoint-record/1.0/valid.json"
)


def test_native_process_snapshot_preserves_instance_and_descriptor_uncertainty(client):
    import jsonschema
    import pytest
    from panopticon_detection.ingestion.endpoint_adapter import EndpointIngestionAdapter

    executable = (
        FIXTURES.parents[4]
        / "panopticon-agent/build-verify-x64/officer-process-inventory-tests.exe"
    )
    if not executable.is_file():
        pytest.skip("native process-inventory artifact unavailable")
    record = json.loads(
        subprocess.check_output([str(executable), "--emit-live"], text=True, encoding="utf-8")
    )
    EndpointRecord.model_validate(record)
    jsonschema.Draft202012Validator(
        json.loads((FIXTURES.parents[3] / "schema/endpoint-record/1.0.schema.json").read_text())
    ).validate(record)
    assert record["subject"] is None and record["category"] == "process_inventory"
    assert record["data"]["inventory_complete"] is False
    assert record["data"]["parent_instances_verified"] is False
    for row in record["data"]["entries"]:
        assert row["parent_reference"] is None
        assert "unverified" in row["descriptor_instance_relation"]
        query = row["later_pid_query"]
        if "reference" in query:
            for field in ("critical_process", "protection_level"):
                fact = query[field]
                if fact["error_code"] is not None:
                    assert fact["state"] == "unavailable" and fact["value"] is None
                    assert fact["error_domain"] == "Win32"
            critical = query["critical_process"]
            if critical["state"] == "healthy":
                assert isinstance(critical["value"], bool)
            protection = query["protection_level"]
            if protection["error_code"] is None:
                assert isinstance(protection["value"]["raw_protection_level"], str)
            token = query["primary_token"]
            architecture = query["architecture"]
            if architecture["error_code"] is None:
                assert isinstance(architecture["value"]["process_machine"], str)
                assert isinstance(architecture["value"]["native_machine"], str)
                assert architecture["value"]["is_wow64"] is (
                    architecture["value"]["process_machine"] != "0"
                )
            else:
                assert architecture["value"] is None and architecture["error_domain"] == "Win32"
            if "fields" in token:
                assert token["inventory_complete"] is False
                assert token["state"] in {"degraded", "unavailable"}
                assert set(token["fields"]) == {
                    "user", "integrity", "elevation", "elevation_type", "session_id", "statistics"
                }
                for fact in token["fields"].values():
                    if fact["state"] == "unavailable":
                        assert fact["value"] is None and fact["error_domain"]
                user = token["fields"]["user"]
                if user["state"] == "healthy":
                    assert user["value"]["sid"].startswith("S-")
            else:
                assert token["value"] is None and token["error_domain"] == "Win32"
            reference = query["reference"]
            if reference["resolution"] == "native_exact":
                assert isinstance(reference["native_creation_ticks"], str)
                assert int(reference["native_creation_ticks"]) > 0
                assert reference["boot_id"] is not None
            else:
                assert reference["entity_id"] is None
    hdr = headers(client)
    assert post(client, hdr, [record]).json()["accepted"] == 1
    latest = client.get(
        "/api/v2/endpoint/agent-1/latest", headers={"Authorization": hdr["Authorization"]}
    ).json()
    assert latest["records"] == [record]
    transformed = EndpointIngestionAdapter.transform(record)
    assert transformed["process_reference"] is None
    assert transformed["endpoint_data"] == record["data"]


def records() -> list[dict]:
    return json.loads(FIXTURES.read_text(encoding="utf-8"))


def test_native_ip_interface_census_retains_independent_management_state(client):
    import jsonschema
    import pytest
    from panopticon_detection.ingestion.endpoint_adapter import EndpointIngestionAdapter

    executable = (
        FIXTURES.parents[4]
        / "panopticon-agent/build-verify-x64/officer-ip-interface-inventory-tests.exe"
    )
    if not executable.is_file():
        pytest.skip("native IP interface census artifact unavailable")
    captured = json.loads(subprocess.check_output(
        [str(executable), "--emit-live"], encoding="utf-8"
    ))
    validator = jsonschema.Draft202012Validator(
        json.loads((FIXTURES.parents[3] / "schema/endpoint-record/1.0.schema.json").read_text())
    )
    hdr = headers(client)
    reply = post(client, hdr, captured)
    assert reply.status_code == 200 and reply.json()["accepted"] == len(captured)
    for record in captured:
        validator.validate(record)
        assert record["subject"] is None
        retained = client.get(
            f'/api/v2/endpoint/agent-1/records/{record["record_id"]}',
            headers={"Authorization": hdr["Authorization"]},
        )
        exact_body = json.dumps(record, separators=(",", ":")).encode()
        assert retained.content == exact_body
        assert retained.headers["X-Panopticon-Record-Digest"] == hashlib.sha256(
            exact_body
        ).hexdigest()
        transformed = EndpointIngestionAdapter.transform(record)
        assert transformed["process_reference"] is None
        assert transformed["endpoint_data"] == record["data"]
    manifest = captured[-1]["data"]
    assert set(manifest["tables"]) == {"ipv4", "ipv6"}
    assert manifest["inventory_complete"] is False
    assert manifest["interface_lifetimes_verified"] is False
    assert manifest["all_compartments_complete"] is False
    assert manifest["native_allocation_bounded"] is False
    entries = [row for page in captured[1:-1] for row in page["data"]["entries"]]
    assert manifest["entries_delivered"] == str(len(entries))
    for row in entries:
        assert row["source"] == "GetIpInterfaceTable"
        assert row["value"]["interface_instance_reference"] is None
        assert len(row["value"]["flags"]) == 14
        assert isinstance(row["value"]["reported_metric"], str)
        assert row["state"] in {"healthy", "degraded"}
    for key, query in manifest["tables"].items():
        assert query["rows_in_accepted_pages"] == str(sum(
            row["source_table"] == key for row in entries
        ))


def test_native_route_capture_preserves_metric_and_interface_uncertainty(client):
    import jsonschema
    import pytest
    from panopticon_detection.ingestion.endpoint_adapter import EndpointIngestionAdapter

    executable = (
        FIXTURES.parents[4]
        / "panopticon-agent/build-verify-x64/officer-route-inventory-tests.exe"
    )
    if not executable.is_file():
        pytest.skip("native route inventory artifact unavailable")
    captured = json.loads(subprocess.check_output(
        [str(executable), "--emit-live"], encoding="utf-8"
    ))
    validator = jsonschema.Draft202012Validator(
        json.loads((FIXTURES.parents[3] / "schema/endpoint-record/1.0.schema.json").read_text())
    )
    hdr = headers(client)
    reply = post(client, hdr, captured)
    assert reply.status_code == 200 and reply.json()["accepted"] == len(captured)
    for record in captured:
        validator.validate(record)
        assert record["subject"] is None
        retained = client.get(
            f'/api/v2/endpoint/agent-1/records/{record["record_id"]}',
            headers={"Authorization": hdr["Authorization"]},
        )
        exact_body = json.dumps(record, separators=(",", ":")).encode()
        assert retained.content == exact_body
        assert retained.headers["X-Panopticon-Record-Digest"] == hashlib.sha256(
            exact_body
        ).hexdigest()
        transformed = EndpointIngestionAdapter.transform(record)
        assert transformed["process_reference"] is None
        assert transformed["endpoint_data"] == record["data"]
    manifest = captured[-1]["data"]
    assert set(manifest["tables"]) == {"ipv4", "ipv6"}
    assert manifest["inventory_complete"] is False
    assert manifest["all_compartments_complete"] is False
    assert manifest["compartment_reference"] is None
    assert manifest["native_allocation_bounded"] is False
    entries = [row for page in captured[1:-1] for row in page["data"]["entries"]]
    assert manifest["entries_delivered"] == str(len(entries))
    for row in entries:
        assert row["interface_instance_reference"] is None
        assert row["route_instance_reference"] is None
        assert row["effective_route_metric"] is None
        assert isinstance(row["reported_interface_luid"], str)
        assert isinstance(row["reported_metric_offset"], str)
        lookup = row["later_ip_interface_query"]
        assert "unverified" in lookup["route_relation"]
        if lookup["native_query_succeeded"]:
            assert lookup["source"] == "GetIpInterfaceEntry"
            assert lookup["value"]["interface_instance_reference"] is None
            assert len(lookup["value"]["flags"]) == 14
            assert isinstance(lookup["value"]["reported_metric"], str)
            if row["reported_metric_sum"] is not None:
                assert lookup["lookup_key_matches_returned_fields"] is True
                assert row["reported_metric_offset"] != "4294967295"
                assert int(row["reported_metric_sum"]) == (
                    int(row["reported_metric_offset"]) + int(lookup["value"]["reported_metric"])
                )
        else:
            assert lookup["value"] is None and row["reported_metric_sum"] is None
    for key, query in manifest["tables"].items():
        assert query["rows_in_accepted_pages"] == str(sum(
            row["source_table"] == key for row in entries
        ))


def test_native_socket_capture_retains_four_tables_without_process_instance_guessing(client):
    import jsonschema
    import pytest
    from panopticon_detection.ingestion.endpoint_adapter import EndpointIngestionAdapter

    executable = (
        FIXTURES.parents[4]
        / "panopticon-agent/build-verify-x64/officer-socket-inventory-tests.exe"
    )
    if not executable.is_file():
        pytest.skip("native socket inventory artifact unavailable")
    captured = json.loads(subprocess.check_output(
        [str(executable), "--emit-live"], encoding="utf-8"
    ))
    validator = jsonschema.Draft202012Validator(
        json.loads((FIXTURES.parents[3] / "schema/endpoint-record/1.0.schema.json").read_text())
    )
    hdr = headers(client)
    reply = post(client, hdr, captured)
    assert reply.status_code == 200 and reply.json()["accepted"] == len(captured)
    for record in captured:
        validator.validate(record)
        assert record["subject"] is None
        retained = client.get(
            f'/api/v2/endpoint/agent-1/records/{record["record_id"]}',
            headers={"Authorization": hdr["Authorization"]},
        )
        exact_body = json.dumps(record, separators=(",", ":")).encode()
        assert retained.content == exact_body
        assert retained.headers["X-Panopticon-Record-Digest"] == hashlib.sha256(
            exact_body
        ).hexdigest()
        transformed = EndpointIngestionAdapter.transform(record)
        assert transformed["process_reference"] is None
        assert transformed["endpoint_data"] == record["data"]
    manifest = captured[-1]["data"]
    assert set(manifest["tables"]) == {"tcp4", "tcp6", "udp4", "udp6"}
    assert manifest["inventory_complete"] is False and manifest["state"] == "degraded"
    entries = [row for page in captured[1:-1] for row in page["data"]["entries"]]
    assert manifest["entries_delivered"] == str(len(entries))
    for row in entries:
        assert row["process_reference"] is None and row["socket_instance_reference"] is None
        if row["transport"] == "udp":
            assert row["remote_port"] is None and row["tcp_state_symbol"] is None
    for key, query in manifest["tables"].items():
        assert query["rows_in_accepted_pages"] == str(sum(
            row["source_table"] == key for row in entries
        ))


def test_native_loaded_driver_capture_preserves_restricted_visibility(client):
    import pytest

    executable = (
        FIXTURES.parents[4]
        / "panopticon-agent/build-verify-x64/officer-driver-inventory-tests.exe"
    )
    if not executable.is_file():
        pytest.skip("native loaded-driver artifact unavailable")
    captured = json.loads(subprocess.check_output(
        [str(executable), "--emit-live"], encoding="utf-8"
    ))
    hdr = headers(client)
    response = post(client, hdr, captured)
    assert response.status_code == 200 and response.json()["accepted"] == len(captured)
    from panopticon_detection.ingestion.endpoint_adapter import EndpointIngestionAdapter

    for record in captured:
        transformed = EndpointIngestionAdapter.transform(record)
        assert transformed["process_reference"] is None
        assert transformed["endpoint_data"] == record["data"]
        retained = client.get(
            f'/api/v2/endpoint/agent-1/records/{record["record_id"]}',
            headers={"Authorization": hdr["Authorization"]},
        )
        assert retained.json() == record
    manifest = captured[-1]["data"]
    assert manifest["state"] in {"blind", "degraded", "unavailable"}
    if manifest.get("all_reported_addresses_null"):
        assert manifest["state"] == "blind" and manifest["non_null_address_slots"] == "0"


def test_native_service_pages_preserve_configuration_uncertainty_and_original_readback(client):
    import jsonschema
    import pytest
    from panopticon_detection.ingestion.endpoint_adapter import EndpointIngestionAdapter

    executable = (
        FIXTURES.parents[4]
        / "panopticon-agent/build-verify-x64/officer-service-inventory-tests.exe"
    )
    if not executable.is_file():
        pytest.skip("native service inventory artifact unavailable")
    captured = json.loads(
        subprocess.check_output([str(executable), "--emit-live"], text=True, encoding="utf-8")
    )
    validator = jsonschema.Draft202012Validator(
        json.loads((FIXTURES.parents[3] / "schema/endpoint-record/1.0.schema.json").read_text())
    )
    hdr = headers(client)
    assert post(client, hdr, captured).json()["accepted"] == len(captured)
    auth = {"Authorization": hdr["Authorization"]}
    for record in captured:
        validator.validate(record)
        assert record["subject"] is None
        url = f'/api/v2/endpoint/agent-1/records/{record["record_id"]}'
        retained = client.get(url, headers=auth)
        exact_body = json.dumps(record, separators=(",", ":")).encode()
        assert retained.content == exact_body and retained.json() == record
        assert retained.headers["X-Panopticon-Record-Digest"] == hashlib.sha256(
            exact_body
        ).hexdigest()
        transformed = EndpointIngestionAdapter.transform(record)
        assert transformed["process_reference"] is None
        assert transformed["endpoint_data"] == record["data"]
        if record["category"] == "service_inventory_page":
            for entry in record["data"]["entries"]:
                assert entry["process_reference"] is None
                assert entry["service_instance_reference"] is None
                assert "unverified" in entry["descriptor_configuration_relation"]
                config = entry["later_configuration_query"]
                security = entry["later_security_query"]
                assert security["state"] in {"degraded", "unavailable"}
                if security.get("native_query_succeeded"):
                    assert security["value"]["sacl"]["state"] == "unavailable"
                else:
                    assert security["value"] is None and security["error_domain"]
                if "optional_configuration_queries" in config:
                    assert len(config["optional_configuration_queries"]) == 9
                    for fact in config["optional_configuration_queries"].values():
                        assert fact["buffer_byte_limit"] == "8192"
                        if not fact["native_query_succeeded"]:
                            assert fact["value"] is None and fact["error_domain"] == "Win32"
    assert captured[-1]["data"]["inventory_complete"] is False
    assert client.get(url).status_code == 401
    other = enroll_test_agent(client, "other-agent", "other-host").json()["access_token"]
    assert client.get(url, headers={"Authorization": "Bearer " + other}).status_code == 401
    assert client.get(
        "/api/v2/endpoint/agent-1/records/rec_" + "f" * 64, headers=auth
    ).status_code == 404


def test_native_paged_process_capture_retains_and_verifies_all_pages(client, monkeypatch):
    import pytest

    from manager import process_snapshots

    executable = (
        FIXTURES.parents[4]
        / "panopticon-agent/build-verify-x64/officer-process-inventory-tests.exe"
    )
    if not executable.is_file():
        pytest.skip("native paged process producer unavailable")
    captured = json.loads(
        subprocess.check_output([str(executable), "--emit-paged"], text=True, encoding="utf-8")
    )
    begin, manifest = captured[0], captured[-1]
    pages = captured[1:-1]
    assert len(pages) > 1
    hdr = headers(client)
    # A final manifest arriving before its referenced pages must stay incomplete.
    assert post(client, hdr, [begin, manifest]).json()["accepted"] == 2
    url = f'/api/v2/endpoint/agent-1/process-snapshots/{manifest["record_id"]}'
    auth = {"Authorization": hdr["Authorization"]}
    partial = client.get(url, headers=auth).json()
    assert partial["assembly_complete"] is False and partial["enumeration_complete"] is False
    capture_url = f'/api/v2/endpoint/agent-1/process-captures/{begin["record_id"]}'
    discovered = client.get(capture_url, headers=auth).json()
    assert discovered["begin"] == begin
    assert discovered["retained_record_counts"] == {"begin": 1, "manifest": 1}
    assert post(client, hdr, pages).json()["accepted"] == len(pages)
    complete = client.get(url, headers=auth).json()
    assert complete["manifest"] == manifest
    assert complete["assembly_complete"] is True and complete["enumeration_complete"] is True
    assert complete["inventory_complete"] is False
    assert complete["verified_entry_count"] == sum(len(p["data"]["entries"]) for p in pages)
    for index, page in enumerate(pages):
        assert client.get(f"{url}/pages/{index}", headers=auth).json()["record"] == page
        raw = client.get(f'{capture_url}/records/{page["record_id"]}', headers=auth).json()
        assert raw["record"] == page and raw["scope_matches_begin"] is True
    assert client.get(capture_url, headers=auth).json()["retained_record_counts"] == {
        "begin": 1, "manifest": 1, "page": len(pages)
    }
    assert client.get(url).status_code == 401
    assert client.get(f"{url}/pages/{len(pages)}", headers=auth).status_code == 404
    # A manifest pointing at the wrong retained page must not bless retained bytes.
    wrong = copy.deepcopy(manifest)
    wrong["record_id"] = "rec_" + "c" * 64
    wrong["data"]["page_record_ids"] = list(reversed(wrong["data"]["page_record_ids"]))
    assert post(client, hdr, [wrong]).json()["accepted"] == 1
    wrong_url = f'/api/v2/endpoint/agent-1/process-snapshots/{wrong["record_id"]}'
    assert client.get(wrong_url, headers=auth).json()["assembly_complete"] is False
    assert client.get(f"{wrong_url}/pages/0", headers=auth).status_code == 409
    other = enroll_test_agent(client, "other-agent", "other-host").json()["access_token"]
    assert client.get(url, headers={"Authorization": "Bearer " + other}).status_code == 401
    monkeypatch.setattr(process_snapshots, "_VERIFY_BYTES", 1)
    bounded = client.get(url, headers=auth).json()
    assert bounded["assembly_complete"] is False
    assert any(i["reason"] == "aggregate_verification_byte_budget_exceeded"
               for i in bounded["issues"])
    assert client.get(f"{url}/pages/0", headers=auth).json()["record"] == pages[0]


def headers(client) -> dict:
    enrolled = enroll_test_agent(client, "agent-1", "host-1")
    assert enrolled.status_code == 200
    return {
        "Authorization": "Bearer " + enrolled.json()["access_token"],
        "X-Panopticon-Agent-Id": "agent-1",
        "X-Panopticon-Batch-Id": "test-canonical-batch",
        "X-Panopticon-Protocol": "2",
        "Content-Type": "application/x-ndjson",
    }


def post(client, hdr, values):
    return client.post(
        "/api/v2/endpoint/records",
        headers=hdr,
        content="".join(json.dumps(record, separators=(",", ":")) + "\n" for record in values),
    )


def capture_record(role, tag, capture_id=None):
    record = copy.deepcopy(records()[4])
    record["record_id"] = "rec_" + hashlib.sha256(tag.encode()).hexdigest()
    record["kind"] = "state"
    record["category"] = {
        "begin": "process_inventory_begin", "page": "process_inventory_page",
        "manifest": "process_inventory",
    }[role]
    record["data"] = {
        "begin": {"format": "paged_process_inventory_begin_v1"},
        "page": {"capture_id": capture_id, "page_index": "0", "entries": []},
        "manifest": {"format": "paged_process_inventory_v1", "capture_id": capture_id,
                     "page_record_ids": [], "entries_delivered": "0",
                     "enumeration_complete": False, "bound_exceeded": False,
                     "consumer_refused": False},
    }[role]
    return record


def test_unfinished_capture_discovery_paginates_preserved_scope_and_late_manifest(client):
    hdr = headers(client)
    auth = {"Authorization": hdr["Authorization"]}
    begin = capture_record("begin", "unfinished")
    capture_id = begin["record_id"]
    url = f"/api/v2/endpoint/agent-1/process-captures/{capture_id}"
    assert client.get(url, headers=auth).status_code == 404
    assert post(client, hdr, [begin]).json()["accepted"] == 1
    begun = client.get(url, headers=auth).json()
    assert begun["begin"] == begin and begun["manifest_status"] == "not_observed"
    assert begun["inventory_complete"] is False
    assert begun["retained_record_counts"] == {"begin": 1}
    page = capture_record("page", "page", capture_id)
    mismatched = capture_record("page", "different-boot", capture_id)
    mismatched["endpoint"]["boot_id"] = "boot_" + "d" * 64
    malformed = capture_record("page", "invalid-index", capture_id)
    malformed["data"]["page_index"] = "000"
    foreign = capture_record("begin", "other-capture")
    assert post(client, hdr, [page, mismatched, malformed, foreign]).json()["accepted"] == 4
    refs = []
    after = None
    while True:
        params = {"limit": 1}
        if after is not None:
            params["after"] = after
        response = client.get(url, headers=auth, params=params).json()
        refs.extend(response["references"])
        after = response["next_cursor"]
        if after is None:
            break
    assert len(refs) == 4 and len({item["record_id"] for item in refs}) == 4
    indexed = {item["record_id"]: item for item in refs}
    assert indexed[page["record_id"]]["scope_matches_begin"] is True
    assert indexed[mismatched["record_id"]]["scope_matches_begin"] is False
    assert indexed[malformed["record_id"]]["page_index_valid"] is False
    assert foreign["record_id"] not in indexed
    for item in (begin, page, mismatched, malformed):
        retained = client.get(f'{url}/records/{item["record_id"]}', headers=auth).json()
        assert retained["record"] == item
        assert retained["scope_matches_begin"] is (item != mismatched)
    assert client.get(f'{url}/records/{foreign["record_id"]}', headers=auth).status_code == 404
    assert client.get(f'{url}/records/{page["record_id"]}').status_code == 401
    manifest = capture_record("manifest", "late-manifest", capture_id)
    assert post(client, hdr, [manifest]).json()["accepted"] == 1
    assert post(client, hdr, [manifest]).json()["duplicates"] == 1
    final = client.get(url, headers=auth).json()
    assert final["manifest_status"] == "observed_unverified"
    assert final["retained_record_counts"] == {"begin": 1, "page": 3, "manifest": 1}
    assert final["inventory_complete"] is False
    assert client.get(url).status_code == 401
    other_token = enroll_test_agent(client, "other-agent", "other-host").json()["access_token"]
    assert client.get(url, headers={"Authorization": "Bearer " + other_token}).status_code == 401
    assert client.get(url, headers=auth, params={"limit": 257}).status_code == 422
    assert client.get(url, headers=auth, params={"after": "not-a-record"}).status_code == 422
    assert client.get(
        f'/api/v2/endpoint/agent-1/process-captures/{page["record_id"]}', headers=auth
    ).status_code == 422


def test_capture_index_rolls_back_with_immutable_identity_collision(client):
    hdr = headers(client)
    begin = capture_record("begin", "rollback-begin")
    assert post(client, hdr, [begin]).json()["accepted"] == 1
    page = capture_record("page", "rollback-page", begin["record_id"])
    collision = copy.deepcopy(begin)
    collision["data"]["changed"] = True
    assert post(client, hdr, [page, collision]).status_code == 409
    conn = db.connect()
    assert conn.execute(
        "SELECT COUNT(*) FROM endpoint_process_capture_records WHERE record_id=?",
        (page["record_id"],),
    ).fetchone()[0] == 0
    assert conn.execute(
        "SELECT COUNT(*) FROM endpoint_records WHERE record_id=?", (page["record_id"],)
    ).fetchone()[0] == 0


def test_real_cpp_fixtures_match_python_contract():
    for record in records():
        EndpointRecord.model_validate(record)
    executable = (
        Path(__file__).resolve().parents[2]
        / "panopticon-agent/build-verify-x64/officer-endpoint-tests.exe"
    )
    if executable.is_file():
        produced = json.loads(
            subprocess.check_output(
                [str(executable), "--emit-fixtures"], text=True, encoding="utf-8"
            )
        )
        for record in produced:
            EndpointRecord.model_validate(record)
        assert produced[1]["subject"]["entity_id"] == produced[2]["subject"]["entity_id"]
        assert produced[3]["subject"]["entity_id"] is None


def test_parent_reference_and_envelope_category_are_authoritative(client):
    hdr = headers(client)
    values = records()
    values[0]["data"]["process"]["parent"]["entity_id"] = values[0]["subject"]["entity_id"]
    values[1]["data"]["event"]["category"] = "network"
    reply = post(client, hdr, values)
    assert reply.status_code == 200
    assert reply.json()["accepted"] == 4
    assert [x["line"] for x in reply.json()["rejected"]] == [1, 2]


def test_authenticated_ingest_preserves_full_surface_and_deduplicates(client):
    hdr = headers(client)
    values = records()
    response = post(client, hdr, values)
    assert response.status_code == 200, response.text
    assert response.json()["accepted"] == len(values)
    assert response.json()["rejected"] == []
    again = post(client, hdr, values)
    assert again.status_code == 200
    assert again.json()["duplicates"] == len(values)
    rows = db.connect().execute("SELECT raw_json FROM endpoint_records ORDER BY rowid").fetchall()
    assert [json.loads(row["raw_json"]) for row in rows] == values
    latest = client.get(
        "/api/v2/endpoint/agent-1/latest", headers={"Authorization": hdr["Authorization"]}
    )
    assert latest.status_code == 200
    assert {record["kind"] for record in latest.json()["records"]} == {"state", "health"}


def test_missing_auth_and_host_mismatch_never_acknowledge(client):
    hdr = headers(client)
    missing = dict(hdr)
    del missing["Authorization"]
    assert post(client, missing, records()).status_code == 401
    invalid = records()
    invalid[0]["endpoint"]["host_id"] = "another-host"
    assert post(client, hdr, invalid).status_code == 403
    assert db.connect().execute("SELECT COUNT(*) FROM endpoint_records").fetchone()[0] == 0


def test_identity_collision_rolls_back_batch_without_overwriting_evidence(client):
    hdr = headers(client)
    values = records()
    assert post(client, hdr, [values[0]]).status_code == 200
    changed = copy.deepcopy(values[0])
    changed["data"]["tampered"] = True
    collision = post(client, hdr, [values[1], changed])
    assert collision.status_code == 409
    assert db.connect().execute("SELECT COUNT(*) FROM endpoint_records").fetchone()[0] == 1


def test_partial_rejection_accounts_for_exact_line_and_retains_other_records(client):
    hdr = headers(client)
    invalid = records()[0]
    invalid["subject"]["boot_id"] = None
    response = post(client, hdr, [records()[1], invalid])
    assert response.status_code == 200
    receipt = response.json()
    assert receipt["received"] == 2 and receipt["accepted"] == 1
    assert receipt["rejected"][0]["line"] == 2
    assert receipt["rejected"][0]["event_id"] == invalid["record_id"]


def test_unknown_domain_is_preserved_without_legacy_category_restriction(client):
    hdr = headers(client)
    value = records()[-1]
    value["category"] = "scheduled_task"
    value["data"] = {"definition": {"trigger": "logon", "identity": "service-account"}}
    response = post(client, hdr, [value])
    assert response.status_code == 200 and response.json()["accepted"] == 1


def test_strict_json_and_subject_identity_invariants(client):
    hdr = headers(client)
    for body in ('{"schema_version":"1.0","schema_version":"0.3"}\n', '{"value":NaN}\n'):
        response = client.post("/api/v2/endpoint/records", headers=hdr, content=body)
        assert response.status_code == 200
        assert response.json()["accepted"] == 0
        assert response.json()["rejected"][0]["reason"] == "json_invalid"
    invalid = records()[0]
    invalid["subject"]["entity_id"] = "proc_" + "0" * 64
    response = post(client, hdr, [invalid])
    assert response.status_code == 200 and response.json()["accepted"] == 0
    assert "digest" in response.json()["rejected"][0]["detail"]
    contradiction = records()[0]
    contradiction["data"]["process"]["pid"] += 1
    response = post(client, hdr, [contradiction])
    assert response.status_code == 200 and response.json()["accepted"] == 0
    assert "contradicts" in response.json()["rejected"][0]["detail"]


def test_schema_shape_matches_cpp_records():
    import jsonschema

    schema_path = FIXTURES.parents[3] / "schema/endpoint-record/1.0.schema.json"
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    jsonschema.Draft202012Validator.check_schema(schema)
    validator = jsonschema.Draft202012Validator(schema)
    for record in records():
        validator.validate(record)


def test_native_source_gap_is_retained_without_inventing_process_or_loss_units(client):
    import jsonschema
    import pytest
    from panopticon_detection.ingestion.endpoint_adapter import EndpointIngestionAdapter

    executable = (
        FIXTURES.parents[4]
        / "panopticon-agent/build-verify-x64/officer-source-supervisor-tests.exe"
    )
    if not executable.is_file():
        pytest.skip("native source-supervisor artifact unavailable")
    record = json.loads(
        subprocess.check_output([str(executable), "--emit-gap"], text=True, encoding="utf-8")
    )
    EndpointRecord.model_validate(record)
    schema = json.loads(
        (FIXTURES.parents[3] / "schema/endpoint-record/1.0.schema.json").read_text()
    )
    jsonschema.Draft202012Validator(schema).validate(record)
    hdr = headers(client)
    reply = post(client, hdr, [record])
    assert reply.status_code == 200 and reply.json()["accepted"] == 1
    assert post(client, hdr, [record]).json()["duplicates"] == 1
    stored = json.loads(db.connect().execute("SELECT raw_json FROM endpoint_records").fetchone()[0])
    assert stored == record
    transformed = EndpointIngestionAdapter.transform(stored)
    assert transformed["event_type"] == "endpoint_gap_source_loss"
    assert transformed["process_reference"] is None
    assert transformed["process"]["entity_id"] is None
    assert transformed["endpoint_data"]["changes"] == [
        {
            "counter": "events_lost",
            "unit": "events",
            "total": "7",
            "previous": "0",
            "delta": "7",
            "reason": "counter_advanced",
        },
        {
            "counter": "realtime_buffers_lost",
            "unit": "buffers",
            "total": "2",
            "previous": "0",
            "delta": "2",
            "reason": "counter_advanced",
        },
    ]


@pytest.mark.parametrize("mode, count", [("--emit-fixtures", 5), ("--emit-platform", 4)])
def test_native_security_center_reports_preserve_unknown_and_service_fallback(client, mode, count):
    import jsonschema
    from panopticon_detection.ingestion.endpoint_adapter import EndpointIngestionAdapter

    executable = (
        FIXTURES.parents[4] / "panopticon-agent/build-verify-x64/officer-security-center-tests.exe"
    )
    if not executable.is_file():
        pytest.skip("native Security Center artifact unavailable")
    records = json.loads(subprocess.check_output(
        [str(executable), mode], text=True, encoding="utf-8"
    ))
    validator = jsonschema.Draft202012Validator(json.loads(
        (FIXTURES.parents[3] / "schema/endpoint-record/1.0.schema.json").read_text()
    ))
    hdr = headers(client)
    for record in records:
        EndpointRecord.model_validate(record)
        validator.validate(record)
    assert post(client, hdr, records).json()["accepted"] == count
    assert post(client, hdr, records).json()["duplicates"] == count
    for record in records:
        retained = client.get(
            f'/api/v2/endpoint/agent-1/records/{record["record_id"]}',
            headers={"Authorization": hdr["Authorization"]},
        ).json()
        assert retained == record
        transformed = EndpointIngestionAdapter.transform(retained)
        assert transformed["endpoint_data"] == record["data"]
        assert transformed["process_reference"] is None
        assert record["data"]["inventory_complete"] is False
        assert record["data"]["protection_verified"] is False
    if mode == "--emit-fixtures":
        fallback = records[0]["data"]["fields"]["antivirus"]
        assert fallback["hresult_code"] == "1" and fallback["raw_output"] == "2"
        assert fallback["reported_health"] is None and fallback["state"] == "unavailable"
        assert records[0]["data"]["fields"]["internet_settings"]["hresult_code"] == "2147942405"
        assert records[1]["data"]["query_summary"]["queries_not_attempted"] == "6"
        assert records[2]["data"]["query_summary"]["uninterpreted_outputs"] == "6"
        assert records[3]["data"]["state"] == "unavailable"
    else:
        assert records[0]["data"]["platform_compatibility"]["wsc_contract_supported"] is True
        assert records[1]["data"]["state"] == "unsupported"
        field = records[1]["data"]["fields"]["antivirus"]
        assert field["reported_health"] is None and field["native_reported_health"] == "good"
        assert field["hresult_code"] == "0" and field["native_query_state"] == "healthy"
        assert records[2]["data"]["platform_compatibility"]["wsc_contract_supported"] is None
        assert records[3]["data"]["platform_compatibility"]["ntstatus_code"] == "3221225506"


@pytest.mark.parametrize("mode, count", [("--emit-history", 4), ("--emit-retry", 3)])
def test_native_state_capture_transition_history_preserves_outage_and_omission_reports(
    client, mode, count
):
    import jsonschema
    import pytest
    from panopticon_detection.ingestion.endpoint_adapter import EndpointIngestionAdapter

    executable = (
        FIXTURES.parents[4] / "panopticon-agent/build-verify-x64/officer-state-freshness-tests.exe"
    )
    if not executable.is_file():
        pytest.skip("native state-history artifact unavailable")
    records = json.loads(subprocess.check_output(
        [str(executable), mode], text=True, encoding="utf-8"
    ))
    validator = jsonschema.Draft202012Validator(json.loads(
        (FIXTURES.parents[3] / "schema/endpoint-record/1.0.schema.json").read_text()
    ))
    hdr = headers(client)
    for record in records:
        EndpointRecord.model_validate(record)
        validator.validate(record)
    assert post(client, hdr, records).json()["accepted"] == count
    assert post(client, hdr, records).json()["duplicates"] == count
    for record in records:
        retained = client.get(
            f'/api/v2/endpoint/agent-1/records/{record["record_id"]}',
            headers={"Authorization": hdr["Authorization"]},
        ).json()
        assert retained == record
        transformed = EndpointIngestionAdapter.transform(retained)
        assert transformed["endpoint_data"] == record["data"]
        assert transformed["process_reference"] is None
        assert record["data"]["lost_native_events"] is None
    assert records[1]["data"]["current_freshness"]["state"] == "blind"
    assert records[2]["data"]["previous_freshness"]["state"] == "blind"
    assert records[2]["data"]["current_freshness"]["state"] == "healthy"
    if mode == "--emit-history":
        assert records[3]["data"]["omitted_transition_reports"] == "2"


def test_native_state_freshness_retains_stale_and_unknown_capture_evidence(client):
    import jsonschema
    import pytest
    from panopticon_detection.ingestion.endpoint_adapter import EndpointIngestionAdapter

    executable = (
        FIXTURES.parents[4] / "panopticon-agent/build-verify-x64/officer-state-freshness-tests.exe"
    )
    if not executable.is_file():
        pytest.skip("native state-freshness artifact unavailable")
    records = json.loads(subprocess.check_output(
        [str(executable), "--emit-fixtures"], text=True, encoding="utf-8"
    ))
    validator = jsonschema.Draft202012Validator(json.loads(
        (FIXTURES.parents[3] / "schema/endpoint-record/1.0.schema.json").read_text()
    ))
    hdr = headers(client)
    for record in records:
        EndpointRecord.model_validate(record)
        validator.validate(record)
    assert post(client, hdr, records).json()["accepted"] == 7
    assert post(client, hdr, records).json()["duplicates"] == 7
    for record in records:
        retained = client.get(
            f'/api/v2/endpoint/agent-1/records/{record["record_id"]}',
            headers={"Authorization": hdr["Authorization"]},
        ).json()
        assert retained == record
        transformed = EndpointIngestionAdapter.transform(retained)
        assert transformed["endpoint_data"] == record["data"]
        assert transformed["process_reference"] is None
    fresh, stale, delayed, missing, future, disabled, recovered = [r["data"] for r in records]
    assert fresh["host_inventory"]["capture_freshness"]["state"] == "healthy"
    assert stale["host_inventory"]["state"] == delayed["host_inventory"]["state"] == "blind"
    assert delayed["host_inventory"]["capture_freshness"]["commit_age_ms"] == "0"
    assert missing["host_inventory"]["capture_freshness"]["capture_age_ms"] is None
    assert future["host_inventory"]["capture_freshness"]["reason"] == "capture_clock_order_invalid"
    assert disabled["host_inventory"]["state"] == "disabled"
    assert recovered["host_inventory"]["state"] == "degraded"
    assert stale["host_inventory"]["last_committed_query_status"] == {
        "state": "healthy", "native_error_code": "0"
    }


def test_native_firewall_rules_preserve_getters_pages_and_unverified_identity(client):
    import jsonschema
    import pytest
    from panopticon_detection.ingestion.endpoint_adapter import EndpointIngestionAdapter

    executable = (
        FIXTURES.parents[4] / "panopticon-agent/build-verify-x64/officer-firewall-rules-tests.exe"
    )
    if not executable.is_file():
        pytest.skip("native firewall-rule artifact unavailable")
    records = json.loads(subprocess.check_output(
        [str(executable), "--emit-live"], text=True, encoding="utf-8"
    ))
    validator = jsonschema.Draft202012Validator(json.loads(
        (FIXTURES.parents[3] / "schema/endpoint-record/1.0.schema.json").read_text()
    ))
    hdr = headers(client)
    for record in records:
        EndpointRecord.model_validate(record)
        validator.validate(record)
        response = post(client, hdr, [record])
        assert response.status_code == 200 and response.json()["accepted"] == 1
        retained = client.get(
            f'/api/v2/endpoint/agent-1/records/{record["record_id"]}',
            headers={"Authorization": hdr["Authorization"]},
        )
        assert retained.json() == record
        adapted = EndpointIngestionAdapter.transform(record)
        assert adapted["endpoint_data"] == record["data"]
        assert adapted["process_reference"] is None
    manifest = records[-1]["data"]
    pages = records[1:-1]
    assert manifest["page_record_ids"] == [record["record_id"] for record in pages]
    assert int(manifest["entries_delivered"]) == sum(len(page["data"]["entries"]) for page in pages)
    assert manifest["inventory_complete"] is False
    assert manifest["effective_packet_policy_verified"] is False
    for page in pages:
        assert page["data"]["capture_id"] == records[0]["record_id"]
        for row in page["data"]["entries"]:
            assert row["rule_reference"] is None and row["process_reference"] is None
            if row["fields"]:
                assert len(row["fields"]) == 25
                assert set(row["extension_interface_queries"]) == {
                    "QueryInterface(INetFwRule2)", "QueryInterface(INetFwRule3)"
                }
            for fact in row["fields"].values():
                assert fact["error_domain"] == "HRESULT"
                if fact["query_attempted"]:
                    assert isinstance(fact["hresult_code"], str)
                else:
                    assert fact["hresult_code"] is None and fact["value"] is None
                    assert fact["state"] in {"unsupported", "unavailable"}


def test_native_firewall_profile_state_retains_local_scope_hresult_and_unknown_values(client):
    import jsonschema
    import pytest
    from panopticon_detection.ingestion.endpoint_adapter import EndpointIngestionAdapter

    executable = (
        FIXTURES.parents[4]
        / "panopticon-agent/build-verify-x64/officer-firewall-profiles-tests.exe"
    )
    if not executable.is_file():
        pytest.skip("native firewall-profile artifact unavailable")
    record = json.loads(subprocess.check_output(
        [str(executable), "--emit-live"], text=True, encoding="utf-8"
    ))
    EndpointRecord.model_validate(record)
    jsonschema.Draft202012Validator(json.loads(
        (FIXTURES.parents[3] / "schema/endpoint-record/1.0.schema.json").read_text()
    )).validate(record)
    assert record["subject"] is None
    assert record["data"]["inventory_complete"] is False
    assert record["data"]["effective_packet_policy_verified"] is False
    assert record["data"]["rules_collected"] is False
    exclusions = record["data"]["exclusion_query_summary"]
    assert record["data"]["excluded_interfaces_collected"] == (
        exclusions["successful_queries"] == "3" and exclusions["incomplete_queries"] == "0"
    )
    hdr = headers(client)
    reply = post(client, hdr, [record])
    assert reply.status_code == 200 and reply.json()["accepted"] == 1
    assert post(client, hdr, [record]).json()["duplicates"] == 1
    retained = client.get(
        f'/api/v2/endpoint/agent-1/records/{record["record_id"]}',
        headers={"Authorization": hdr["Authorization"]},
    )
    assert retained.json() == record
    adapted = EndpointIngestionAdapter.transform(retained.json())
    assert adapted["endpoint_data"] == record["data"]
    assert adapted["process_reference"] is None
    assert adapted["process"]["entity_id"] is None
    if record["data"]["profiles"]:
        assert [row["profile_type"] for row in record["data"]["profiles"]] == ["1", "2", "4"]
        for row in record["data"]["profiles"]:
            for fact in row["fields"].values():
                assert fact["error_domain"] == "HRESULT"
                assert isinstance(fact["hresult_code"], str)
                if int(fact["hresult_code"]) & 0x80000000:
                    assert fact.get("raw_output") is None and fact["value"] is None


def test_native_source_history_omissions_preserve_unknown_loss_and_original_records(client):
    import jsonschema
    import pytest
    from panopticon_detection.ingestion.endpoint_adapter import EndpointIngestionAdapter

    executable = (
        FIXTURES.parents[4]
        / "panopticon-agent/build-verify-x64/officer-source-supervisor-tests.exe"
    )
    if not executable.is_file():
        pytest.skip("native source-supervisor artifact unavailable")
    records = json.loads(subprocess.check_output(
        [str(executable), "--emit-gap-history"], text=True, encoding="utf-8"
    ))
    validator = jsonschema.Draft202012Validator(json.loads(
        (FIXTURES.parents[3] / "schema/endpoint-record/1.0.schema.json").read_text()
    ))
    for record in records:
        EndpointRecord.model_validate(record)
        validator.validate(record)
    hdr = headers(client)
    reply = post(client, hdr, records)
    assert reply.status_code == 200 and reply.json()["accepted"] == 3
    assert post(client, hdr, records).json()["duplicates"] == 3
    stored = [json.loads(row[0]) for row in db.connect().execute(
        "SELECT raw_json FROM endpoint_records ORDER BY rowid"
    ).fetchall()]
    assert stored == records
    omission = records[-1]["data"]
    assert omission["source_status"] is None
    assert omission["changes"][0]["reason"] == "supervisor_history_bound"
    assert omission["changes"][0]["omitted_gap_reports"] == "2"
    assert omission["changes"][0]["count"] is None
    assert omission["changes"][0]["first_omitted_sample_uptime_ms"] == "30"
    assert omission["changes"][0]["last_omitted_sample_uptime_ms"] == "40"
    for record in stored:
        transformed = EndpointIngestionAdapter.transform(record)
        assert transformed["endpoint_data"] == record["data"]
        assert transformed["process_reference"] is None
        assert transformed["process"]["entity_id"] is None


def test_native_normalization_failure_facts_survive_ingest_and_detection(client):
    import jsonschema
    import pytest
    from panopticon_detection.ingestion.endpoint_adapter import EndpointIngestionAdapter

    executable = (
        FIXTURES.parents[4] / "panopticon-agent/build-verify-x64/officer-source-facts-tests.exe"
    )
    if not executable.is_file():
        pytest.skip("native source-facts artifact unavailable")
    values = json.loads(
        subprocess.check_output([str(executable), "--emit-fixtures"], text=True, encoding="utf-8")
    )
    validator = jsonschema.Draft202012Validator(
        json.loads((FIXTURES.parents[3] / "schema/endpoint-record/1.0.schema.json").read_text())
    )
    for record in values:
        EndpointRecord.model_validate(record)
        validator.validate(record)
    hdr = headers(client)
    reply = post(client, hdr, values)
    assert reply.status_code == 200 and reply.json()["accepted"] == 6
    assert reply.json()["rejected"] == []
    assert post(client, hdr, values).json()["duplicates"] == 6
    stored = [
        json.loads(row[0])
        for row in db.connect().execute("SELECT raw_json FROM endpoint_records ORDER BY rowid")
    ]
    assert stored == values
    transformed = [EndpointIngestionAdapter.transform(record) for record in stored]
    assert {record["event_type"] for record in transformed} == {
        "endpoint_evidence_normalization_failure"
    }
    assert transformed[0]["process"]["start_time_ticks"] == 133700000000000001
    assert transformed[1]["process"]["entity_id"] is None
    assert transformed[1]["endpoint_data"]["source_facts"]["process"]["process_guid"] == {
        "encoding": "hex",
        "bytes": "ff",
        "byte_length": "1",
    }
    assert (
        transformed[0]["endpoint_data"]["source_facts"]["process"]["sha256"]
        == "invalid-source-hash"
    )
    assert transformed[3]["endpoint_data"]["source_facts"]["registry"]["value_data"] == "a\x00b"
    assert (
        transformed[5]["endpoint_data"]["source_facts"]["event_time_ns"] == "-9223372036854775808"
    )


def test_live_native_host_state_is_projected_without_guessing_unknown_fields(client):
    import jsonschema
    import pytest
    from panopticon_detection.ingestion.endpoint_adapter import EndpointIngestionAdapter

    executable = (
        FIXTURES.parents[4] / "panopticon-agent/build-verify-x64/officer-host-inventory-tests.exe"
    )
    if not executable.is_file():
        pytest.skip("native host-inventory artifact unavailable")
    record = json.loads(
        subprocess.check_output([str(executable), "--emit-live"], text=True, encoding="utf-8")
    )
    EndpointRecord.model_validate(record)
    jsonschema.Draft202012Validator(
        json.loads((FIXTURES.parents[3] / "schema/endpoint-record/1.0.schema.json").read_text())
    ).validate(record)
    hdr = headers(client)
    reply = post(client, hdr, [record])
    assert reply.status_code == 200 and reply.json()["accepted"] == 1
    latest = client.get(
        "/api/v2/endpoint/agent-1/latest", headers={"Authorization": hdr["Authorization"]}
    ).json()
    assert latest["records"] == [record]
    assert latest["projection_status"][0]["ordering"] == "current"
    assert latest["projection_status"][0]["observation_freshness"] == "unverified"
    assert record["data"]["inventory_complete"] is False
    for name in ("virtualization",):
        assert record["data"]["fields"][name]["state"] == "unavailable"
        assert record["data"]["fields"][name]["value"] is None
    storage = record["data"]["fields"]["storage"]
    audit = record["data"]["fields"]["system_audit_policy"]
    if audit["value"] is None:
        assert audit["state"] == "unavailable" and audit["error_domain"] == "Win32"
        assert isinstance(audit["error_code"], str)
    else:
        assert audit["state"] in {"healthy", "degraded"}
        assert audit["value"]["per_user_policy_complete"] is False
        assert audit["value"]["security_log_delivery_verified"] is False
        assert len(audit["value"]["subcategories"]) <= 256
        for row in audit["value"]["subcategories"]:
            assert isinstance(row["flags"]["raw_mask"], str)
            assert row["subcategory_guid"].startswith("{")
    if storage["value"] is not None:
        assert storage["state"] == "degraded"
        assert storage["value"]["physical_disks_complete"] is False
        assert storage["value"]["encryption_state_complete"] is False
        for volume in storage["value"]["volumes"]:
            if volume["space"]["state"] == "healthy":
                for key in ("free_bytes_available_to_caller", "total_bytes_available_to_caller",
                            "total_free_bytes"):
                    assert isinstance(volume["space"]["value"][key], str)
                    assert int(volume["space"]["value"][key]) >= 0
    tpm = record["data"]["fields"]["tpm"]
    entra = record["data"]["fields"]["entra_join"]
    for fact in (tpm, entra):
        assert fact["state"] in {"healthy", "degraded", "unavailable", "unsupported"}
        assert fact["error_domain"] in {"TBS_RESULT", "HRESULT", "WIN32"}
        if fact["state"] in {"unavailable", "unsupported"}:
            assert fact["value"] is None
    if tpm["state"] in {"healthy", "degraded"}:
        assert isinstance(tpm["value"]["compatible_device_found"], bool)
        assert "attestation not queried" in tpm["scope"]
    if entra["state"] in {"healthy", "degraded"}:
        assert entra["all_users_complete"] is False and entra["all_tenants_complete"] is False
        if entra["query_status_code"] != "0":
            assert entra["value"]["join_kind"] == "unknown"
            assert entra["state"] == "degraded" and entra["error_code"] is None
    transformed = EndpointIngestionAdapter.transform(record)
    assert transformed["event_type"] == "endpoint_state_host_inventory"
    assert transformed["process_reference"] is None
    assert transformed["endpoint_data"] == record["data"]


def test_native_defender_status_preserves_typed_raw_properties_and_provider_refusal(client):
    import jsonschema
    from panopticon_detection.ingestion.endpoint_adapter import EndpointIngestionAdapter

    executable = (
        FIXTURES.parents[4] / "panopticon-agent/build-verify-x64/officer-defender-status-tests.exe"
    )
    if not executable.is_file():
        pytest.skip("native Defender status artifact unavailable")
    values = json.loads(subprocess.check_output(
        [str(executable), "--emit-fixtures"], text=True, encoding="utf-8"
    ))
    validator = jsonschema.Draft202012Validator(json.loads(
        (FIXTURES.parents[3] / "schema/endpoint-record/1.0.schema.json").read_text()
    ))
    hdr = headers(client)
    for record in values:
        EndpointRecord.model_validate(record)
        validator.validate(record)
    assert post(client, hdr, values).json()["accepted"] == 4
    assert post(client, hdr, values).json()["duplicates"] == 4
    for record in values:
        retained = client.get(
            f'/api/v2/endpoint/agent-1/records/{record["record_id"]}',
            headers={"Authorization": hdr["Authorization"]},
        ).json()
        assert retained == record
        projected = EndpointIngestionAdapter.transform(retained)
        assert projected["event_type"] == "endpoint_state_defender_status"
        assert projected["endpoint_data"] == record["data"]
        assert projected["process_reference"] is None
        assert record["data"]["inventory_complete"] is False
        assert record["data"]["protection_verified"] is False
    assert values[1]["data"]["native_steps"][0]["hresult_code"] == "2147549446"
    cases = values[2]["data"]["decoder_cases"]
    assert cases[0]["value"] is False and cases[1]["value"] is True
    assert cases[2]["value"] is None and cases[2]["raw_scalar"] == "1"
    assert cases[3]["value"] == "4294967295" and cases[4]["value"] == "65535"
    assert cases[5]["value"] is None and cases[5]["raw_scalar"] == "65535"
    assert cases[10]["value"] == "a\x00b"
    assert cases[12]["timestamp_normalized"] is False
    assert cases[13]["raw_text"]["bytes"] == "00d8"
    assert cases[13]["text_conversion_error_domain"] == "WIN32"
    assert cases[13]["text_conversion_error_code"] == "1113"
    assert cases[14]["raw_text"]["bytes"] == "616263"
    assert cases[15]["validation_error"] == cases[16]["validation_error"] == "text_copy_bound"

    modern = values[3]["data"]["modern_query_cases"]
    assert [field["reported_mode"] for field in modern[:3]] == [
        "Normal", "Passive", "EDR Block Mode"
    ]
    assert modern[3]["reported_mode"] is None and modern[3]["value"] == "FutureMode"
    assert modern[4]["value"] is False and modern[4]["reported_tamper_state"] == "disabled"
    assert modern[4]["state"] == "healthy"
    assert modern[5]["reported_tamper_state"] == "enabled"
    assert modern[6]["reported_tamper_state"] is None
    assert modern[7]["policy_authority_verified"] is False
    assert modern[8]["hresult_code"] == "2147749890"
    assert modern[8]["property_availability"] == "not_exposed_by_object"
    assert modern[9]["property_availability"] == "query_refused"
    assert modern[9]["reported_tamper_state"] is None
    assert modern[10]["hresult_code"] == "2" and modern[10]["reported_mode"] is None
    assert modern[11]["validation_error"] == "cim_type_mismatch"
    quality = values[3]["data"]["modern_property_quality"]
    assert quality["AMRunningMode"]["state"] == "degraded"
    assert quality["TamperProtectionSource"]["missing_field_captured_rows"] == "1"
