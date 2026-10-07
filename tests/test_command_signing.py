"""ADR 008: the Manager signs commands with the Linux sensor's ES256 command authorization (its ADR 025).

The conformance vectors were produced by the sensor's reference signer (``panopticon-command-signer input`` and
``sign``, built from panopticon-linux-agent), so these tests pin the Python signing input to the endpoint's bytes and
check that signatures cross between the two implementations.
"""

import base64
import json
import os
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric import ec
from fastapi.testclient import TestClient

from manager import command_signing
from tests.conftest import enroll_test_agent

VECTORS = json.loads((Path(__file__).parent / "fixtures" / "command_signing_vectors.json").read_text(encoding="utf-8"))
VECTOR_IDS = [vector["name"] for vector in VECTORS["vectors"]]


def _enroll(client: TestClient, agent_id: str, host_id: str) -> str:
    response = enroll_test_agent(client, agent_id, host_id)
    assert response.status_code == 200
    return str(response.json()["access_token"])


def _command(command_id: str, agent_id: str = "agent-1", **extra) -> dict:
    command = {
        "command_id": command_id,
        "agent_id": agent_id,
        "action": "KILL_PROCESS",
        "expires_at": (datetime.now(timezone.utc) + timedelta(minutes=5)).isoformat(),
        "target": {"pid": 4242, "start_time_ticks": 987654},
    }
    command.update(extra)
    return command


def _queue(client: TestClient, command: dict):
    return client.post("/api/v1/commands", json=command, headers={"X-Panopticon-Command-Token": "test-command-token"})


def _poll(client: TestClient, agent_id: str, token: str, **params):
    return client.get(f"/api/v1/agents/{agent_id}/commands", params=params, headers={"Authorization": f"Bearer {token}"})


@pytest.fixture()
def signing_key(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> bytes:
    """A configured signing key; returns its public point."""
    path = tmp_path / "command-signing.pem"
    line = command_signing.generate(path)
    monkeypatch.setenv(command_signing.SIGNING_KEY_ENV, str(path))
    return base64.b64decode(line.split()[0])


@pytest.mark.parametrize("vector", VECTORS["vectors"], ids=VECTOR_IDS)
def test_signing_input_matches_the_endpoint_byte_for_byte(vector: dict) -> None:
    assert command_signing.signing_input(vector["command"]) == vector["signing_input"].encode("utf-8")


@pytest.mark.parametrize("vector", VECTORS["vectors"], ids=VECTOR_IDS)
def test_endpoint_signed_commands_verify_here(vector: dict) -> None:
    point = base64.b64decode(VECTORS["public_key"])
    assert command_signing.key_id(point) == vector["signed"]["authorization"]["key_id"]
    assert command_signing.verify(vector["signed"], point)


def test_changing_any_signed_field_breaks_the_signature() -> None:
    point = base64.b64decode(VECTORS["public_key"])
    signed = next(v["signed"] for v in VECTORS["vectors"] if v["command"]["action"] == "KILL_PROCESS")
    changes = {
        "command_id": "other-command",
        "correlation_id": "other-correlation",
        "agent_id": "other-agent",
        "host_id": "other-host",
        "action": "COLLECT_PROCESS_INFO",
        "created_at": "2020-01-01T00:00:00+00:00",
        "expires_at": "2099-01-01T00:00:00+00:00",
    }
    for name, value in changes.items():
        assert not command_signing.verify({**signed, name: value}, point), name
    for name, value in (("pid", 1), ("start_time_ticks", 1)):
        assert not command_signing.verify({**signed, "target": {**signed["target"], name: value}}, point), name
    other = ec.generate_private_key(ec.SECP256R1())
    assert not command_signing.verify(signed, command_signing.public_point(other.public_key()))


def test_times_without_an_offset_cannot_be_signed() -> None:
    with pytest.raises(command_signing.UnsignableCommand):
        command_signing.epoch_seconds("2026-10-07T12:00:00")
    assert command_signing.epoch_seconds("2026-10-07T12:00:00.999999Z") == command_signing.epoch_seconds("2026-10-07T12:00:00+00:00")
    assert command_signing.epoch_seconds("2026-10-07T17:30:00+05:30") == command_signing.epoch_seconds("2026-10-07T12:00:00Z")


def test_enqueue_signs_and_poll_delivers_the_signature_on_request(client: TestClient, signing_key: bytes) -> None:
    token = _enroll(client, "agent-1", "host-1")
    assert _queue(client, _command("cmd-signed")).status_code == 200
    polled = _poll(client, "agent-1", token, delivery_mode="durable", command_auth="ES256")
    assert polled.status_code == 200
    (delivered,) = polled.json()["commands"]
    assert delivered["authorization"]["algorithm"] == "ES256"
    assert delivered["authorization"]["key_id"] == command_signing.key_id(signing_key)
    assert command_signing.verify(delivered, signing_key)
    assert delivered["host_id"] == "host-1" and "created_at" in delivered


def test_poll_without_command_auth_leaves_the_signature_out(client: TestClient, signing_key: bytes) -> None:
    """The Windows agent refuses unknown members, so it gets the command as before."""
    token = _enroll(client, "agent-1", "host-1")
    assert _queue(client, _command("cmd-windows")).status_code == 200
    (delivered,) = _poll(client, "agent-1", token).json()["commands"]
    assert "authorization" not in delivered


def test_unsupported_command_auth_is_refused(client: TestClient) -> None:
    token = _enroll(client, "agent-1", "host-1")
    assert _poll(client, "agent-1", token, command_auth="none").status_code == 422


def test_without_a_key_commands_stay_unsigned(client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(command_signing.SIGNING_KEY_ENV, raising=False)
    token = _enroll(client, "agent-1", "host-1")
    assert _queue(client, _command("cmd-unsigned")).status_code == 200
    (delivered,) = _poll(client, "agent-1", token, command_auth="ES256").json()["commands"]
    assert "authorization" not in delivered


def test_a_configured_key_that_cannot_be_used_stops_the_command(client: TestClient, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    token = _enroll(client, "agent-1", "host-1")
    monkeypatch.setenv(command_signing.SIGNING_KEY_ENV, str(tmp_path / "missing.pem"))
    assert _queue(client, _command("cmd-no-key")).status_code == 503
    broken = tmp_path / "broken.pem"
    broken.write_text("not a key")
    if os.name == "posix":
        broken.chmod(0o600)
    monkeypatch.setenv(command_signing.SIGNING_KEY_ENV, str(broken))
    assert _queue(client, _command("cmd-broken-key")).status_code == 503
    monkeypatch.delenv(command_signing.SIGNING_KEY_ENV)
    assert _poll(client, "agent-1", token, command_auth="ES256").json()["commands"] == [], "nothing was queued unsigned"


@pytest.mark.skipif(os.name != "posix", reason="file modes")
def test_a_key_other_users_can_read_is_refused(client: TestClient, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _enroll(client, "agent-1", "host-1")
    path = tmp_path / "shared.pem"
    command_signing.generate(path)
    path.chmod(0o644)
    monkeypatch.setenv(command_signing.SIGNING_KEY_ENV, str(path))
    assert _queue(client, _command("cmd-shared-key")).status_code == 503


def test_a_naive_expiry_cannot_be_signed(client: TestClient, signing_key: bytes) -> None:
    _enroll(client, "agent-1", "host-1")
    naive = (datetime.now(timezone.utc) + timedelta(minutes=5)).replace(tzinfo=None).isoformat()
    assert _queue(client, _command("cmd-naive", expires_at=naive)).status_code == 422


def test_the_audit_names_the_signing_key(client: TestClient, signing_key: bytes) -> None:
    _enroll(client, "agent-1", "host-1")
    assert _queue(client, _command("cmd-audited")).status_code == 200
    conn = sqlite3.connect(os.environ["PANOPTICON_DB_PATH"])
    (detail,) = conn.execute("SELECT detail FROM command_audit WHERE command_id='cmd-audited' AND event='created'").fetchone()
    conn.close()
    assert detail == f"signed ES256 key_id={command_signing.key_id(signing_key)}"


def test_a_database_rewrite_of_a_signed_command_is_detectable(client: TestClient, signing_key: bytes) -> None:
    """The signature was made at authorization: someone who can write the commands table cannot retarget it."""
    token = _enroll(client, "agent-1", "host-1")
    assert _queue(client, _command("cmd-rewritten")).status_code == 200
    conn = sqlite3.connect(os.environ["PANOPTICON_DB_PATH"])
    (stored,) = conn.execute("SELECT command_json FROM commands WHERE command_id='cmd-rewritten'").fetchone()
    rewritten = json.loads(stored)
    rewritten["target"]["pid"] = 1
    conn.execute("UPDATE commands SET command_json=? WHERE command_id='cmd-rewritten'", (json.dumps(rewritten),))
    conn.commit()
    conn.close()
    (delivered,) = _poll(client, "agent-1", token, command_auth="ES256").json()["commands"]
    assert delivered["target"]["pid"] == 1
    assert not command_signing.verify(delivered, signing_key)
