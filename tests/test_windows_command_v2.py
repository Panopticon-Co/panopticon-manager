import json
import subprocess
from datetime import datetime, timedelta, timezone
from pathlib import Path

import jsonschema
import pytest

from tests.conftest import enroll_test_agent


def request():
    return {
        "command_id": "windows-command-v2",
        "agent_id": "agent-v2",
        "schema_version": "2",
        "action": "COLLECT_PROCESS_INFO",
        "expires_at": (
            datetime.now(timezone(timedelta(hours=5, minutes=30))) + timedelta(minutes=5)
        ).isoformat(),
        "target": {
            "pid": 42,
            "start_time_ticks": "18446744073709551615",
            "boot_id": "boot_" + "a" * 64,
        },
    }


def test_authorized_dispatch_preserves_boot_scope_and_full_native_token(client):
    enrollment = enroll_test_agent(client, "agent-v2", "host-v2")
    assert enrollment.status_code == 200
    command = request()
    response = client.post(
        "/api/v1/commands",
        json=command,
        headers={"X-Panopticon-Command-Token": "test-command-token"},
    )
    assert response.status_code == 200
    polled = client.get(
        "/api/v1/agents/agent-v2/commands",
        headers={"Authorization": f"Bearer {enrollment.json()['access_token']}"},
    )
    assert polled.status_code == 200
    wire = polled.json()["commands"][0]
    assert wire["target"] == command["target"]
    assert wire["schema_version"] == "2"
    assert wire["expires_at"].endswith("+00:00")
    assert wire["host_id"] == "host-v2"
    root = Path(__file__).resolve().parents[2]
    schema = json.loads(
        (root / "panopticon-contracts/schema/windows-process-command-v2.schema.json").read_text()
    )
    jsonschema.validate(wire, schema)


def test_real_windows_decoder_accepts_manager_dispatched_command(client):
    root = Path(__file__).resolve().parents[2]
    decoder = root / "panopticon-agent/build-verify-x64/officer-response-tests.exe"
    if not decoder.is_file():
        pytest.skip("native Windows response decoder artifact not built on this platform")
    enrollment = enroll_test_agent(client, "agent-v2", "host-v2")
    assert enrollment.status_code == 200
    assert (
        client.post(
            "/api/v1/commands",
            json=request(),
            headers={"X-Panopticon-Command-Token": "test-command-token"},
        ).status_code
        == 200
    )
    wire = client.get(
        "/api/v1/agents/agent-v2/commands",
        headers={"Authorization": f"Bearer {enrollment.json()['access_token']}"},
    ).json()["commands"][0]
    decoded = subprocess.run(
        [str(decoder), "--decode-command-stdin"],
        input=json.dumps(wire),
        text=True,
        capture_output=True,
        timeout=10,
        check=True,
    )
    result = json.loads(decoded.stdout)
    assert result == {"schema_version": "2", **wire["target"]}


@pytest.mark.parametrize("ticks", [123, "0", "01", "18446744073709551616"])
def test_manager_refuses_noncanonical_version_two_token(client, ticks):
    enrollment = enroll_test_agent(client, "agent-v2", "host-v2")
    assert enrollment.status_code == 200
    command = request()
    command["target"]["start_time_ticks"] = ticks
    assert (
        client.post(
            "/api/v1/commands",
            json=command,
            headers={"X-Panopticon-Command-Token": "test-command-token"},
        ).status_code
        == 422
    )
