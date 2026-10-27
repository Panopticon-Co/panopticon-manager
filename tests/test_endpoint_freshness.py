"""Capture age is bounded, replay-safe and distinct from source event freshness."""

import json

from manager import db
from manager import endpoint_freshness as freshness
from tests.test_endpoint_records import headers, post
from tests.test_endpoint_state import health, latest


def proof_headers(client, hdr, record, *, sent="10000"):
    challenge = client.post("/api/v2/endpoint/freshness-challenge", headers=hdr)
    assert challenge.status_code == 200
    context = {
        "installation_id": record["endpoint"]["installation_id"],
        "boot_id": record["endpoint"]["boot_id"],
        "collector_generation": record["provenance"]["collector_generation"],
        "collector_epoch": record["provenance"]["collector_epoch"],
        "send_uptime_ms": sent,
    }
    return {
        **hdr,
        "X-Panopticon-Freshness-Nonce": challenge.json()["nonce"],
        "X-Panopticon-Capture-Context": json.dumps(context),
    }


def capture(generation=1, sequence=1, *, uptime="10000"):
    value = health(generation, sequence)
    value["provenance"].update(capture_clock="windows_uptime_ms", capture_uptime_ms=uptime)
    return value


def test_recent_capture_ages_without_endpoint_or_server_wall_clock(client, monkeypatch):
    clock = [1_000_000_000]
    monkeypatch.setattr(freshness, "clock_ns", lambda: clock[0])
    hdr = headers(client)
    value = capture()
    proof = proof_headers(client, hdr, value)
    clock[0] += 2_000_000_000
    assert post(client, proof, [value]).json()["accepted"] == 1
    status = latest(client, hdr)["projection_status"][0]
    assert status["capture_freshness"] == "fresh"
    assert status["capture_age_upper_bound_ms"] == "2100"
    assert status["observation_freshness"] == "unverified"
    clock[0] += 91_000_000_000
    assert latest(client, hdr)["projection_status"][0]["capture_freshness"] == "stale"


def test_old_offline_capture_is_stale_even_on_first_authenticated_receipt(client):
    hdr = headers(client)
    value = capture(uptime="1000")
    proof = proof_headers(client, hdr, value, sent="86401000")
    assert post(client, proof, [value]).json()["accepted"] == 1
    status = latest(client, hdr)["projection_status"][0]
    assert status["capture_freshness"] == "stale"
    assert int(status["capture_age_upper_bound_ms"]) >= 86_400_000


def test_consumed_nonce_cannot_bless_another_record_or_refresh_duplicate(client, monkeypatch):
    clock = [1_000_000_000]
    monkeypatch.setattr(freshness, "clock_ns", lambda: clock[0])
    hdr = headers(client)
    first = capture()
    proof = proof_headers(client, hdr, first)
    assert post(client, proof, [first]).json()["accepted"] == 1
    clock[0] += 120_000_000_000
    assert post(client, proof, [first]).json()["duplicates"] == 1
    assert latest(client, hdr)["projection_status"][0]["capture_freshness"] == "stale"
    second = capture(sequence=2)
    assert post(client, proof, [second]).json()["accepted"] == 1
    assert latest(client, hdr)["projection_status"][0]["capture_freshness"] == "unverified"


def test_expired_challenge_and_manager_restart_never_preserve_fresh_claim(client, monkeypatch):
    clock = [1_000_000_000]
    monkeypatch.setattr(freshness, "clock_ns", lambda: clock[0])
    hdr = headers(client)
    value = capture()
    proof = proof_headers(client, hdr, value)
    clock[0] += freshness.CHALLENGE_NS + 1
    assert post(client, proof, [value]).json()["accepted"] == 1
    assert latest(client, hdr)["projection_status"][0]["capture_freshness"] == "unverified"
    new = capture(sequence=2)
    proof = proof_headers(client, hdr, new)
    assert post(client, proof, [new]).json()["accepted"] == 1
    assert latest(client, hdr)["projection_status"][0]["capture_freshness"] == "fresh"
    monkeypatch.setattr(freshness, "SERVER_EPOCH", "different-manager-process")
    assert latest(client, hdr)["projection_status"][0]["capture_freshness"] == "unverified"


def test_boot_generation_scope_and_future_uptime_cannot_prove_freshness(client):
    hdr = headers(client)
    for index, mismatch in enumerate(
        ("boot_id", "collector_generation", "collector_epoch", "installation_id", "send_uptime_ms"),
        1,
    ):
        value = capture(sequence=index)
        proof = proof_headers(client, hdr, value)
        context = json.loads(proof["X-Panopticon-Capture-Context"])
        context[mismatch] = {
            "boot_id": "boot_" + "c" * 64,
            "collector_generation": "999",
            "collector_epoch": "epoch_" + "c" * 64,
            "installation_id": "c" * 64,
            "send_uptime_ms": "1",
        }[mismatch]
        proof["X-Panopticon-Capture-Context"] = json.dumps(context)
        assert post(client, proof, [value]).json()["accepted"] == 1
        assert latest(client, hdr)["projection_status"][0]["capture_freshness"] == "unverified"


def test_challenge_auth_bounds_and_bad_optional_proof_preserve_telemetry(client):
    hdr = headers(client)
    missing = {"X-Panopticon-Agent-Id": "agent-1"}
    assert client.post("/api/v2/endpoint/freshness-challenge", headers=missing).status_code == 401
    value = capture()
    proof = proof_headers(client, hdr, value)
    for _ in range(5):
        proof_headers(client, hdr, value)
    assert (
        db.connect().execute("SELECT COUNT(*) FROM endpoint_freshness_challenges").fetchone()[0]
        == 1
    )
    proof["X-Panopticon-Capture-Context"] = "{"  # malformed header must not lose evidence
    assert post(client, proof, [value]).json()["accepted"] == 1
    assert latest(client, hdr)["projection_status"][0]["capture_freshness"] == "unverified"


def test_unsupported_clock_preserves_evidence_without_claiming_freshness(client, monkeypatch):
    hdr = headers(client)
    monkeypatch.setattr(freshness, "clock_ns", lambda: None)
    assert client.post("/api/v2/endpoint/freshness-challenge", headers=hdr).status_code == 503
    value = capture()
    assert post(client, hdr, [value]).json()["accepted"] == 1
    assert latest(client, hdr)["projection_status"][0]["capture_freshness"] == "unverified"


def test_duplicate_context_keys_and_capture_clock_pairing_are_rejected(client):
    hdr = headers(client)
    value = capture()
    proof = proof_headers(client, hdr, value)
    text = proof["X-Panopticon-Capture-Context"]
    proof["X-Panopticon-Capture-Context"] = text[:-1] + ',"send_uptime_ms":"10000"}'
    assert post(client, proof, [value]).json()["capture_age_records"] == 0
    assert latest(client, hdr)["projection_status"][0]["capture_freshness"] == "unverified"
    other = capture(sequence=2)
    other["provenance"]["capture_uptime_ms"] = "18446744073709551616"
    response = post(client, hdr, [other])
    assert response.json()["accepted"] == 0
    assert response.json()["rejected"][0]["reason"] == "schema_invalid"
    del other["provenance"]["capture_uptime_ms"]
    assert post(client, hdr, [other]).json()["accepted"] == 0
