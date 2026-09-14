import importlib
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

# A one-rule directory so the per-test detection worker builds fast. Tests that
# need the full pinned rule set point PANOPTICON_RULES_DIR at vendor/eyedetect/rules
# themselves (see test_detection_factory.py).
FIXTURE_RULES_DIR = Path(__file__).resolve().parent / "fixtures" / "rules"


@pytest.fixture()
def client(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> TestClient:
    monkeypatch.setenv("PANOPTICON_DB_PATH", str(tmp_path / "panopticon.db"))
    monkeypatch.setenv("PANOPTICON_ALERTS_PATH", str(tmp_path / "alerts.ndjson"))
    monkeypatch.setenv("PANOPTICON_RULES_DIR", str(FIXTURE_RULES_DIR))
    monkeypatch.setenv("PANOPTICON_ENROLLMENT_TOKEN", "test-bootstrap-token")
    monkeypatch.setenv("PANOPTICON_COMMAND_TOKEN", "test-command-token")
    monkeypatch.setenv("PANOPTICON_ANALYST_ENROLLMENT_TOKEN", "test-analyst-bootstrap-token")
    # Reimport fresh so module-level state (db._db_path, thread-local conn) doesn't
    # leak between tests.
    import manager.app as app_module
    import manager.auth as auth_module
    import manager.db as db_module
    import manager.detection.factory as factory_module
    import manager.detection.response as response_module
    import manager.migrations as migrations_module
    import manager.routers.alerts as alerts_module
    import manager.routers.commands as commands_module
    import manager.routers.enrollment as enrollment_module
    import manager.routers.health as health_module
    import manager.routers.ingest as ingest_module
    import manager.routers.response_actions as response_actions_module

    for mod in (
        health_module,
        ingest_module,
        enrollment_module,
        commands_module,
        response_module,
        response_actions_module,
        alerts_module,
        factory_module,
        auth_module,
        migrations_module,
        db_module,
        app_module,
    ):
        importlib.reload(mod)

    # TestClient's context manager runs the lifespan: migrations + detection worker
    # start on enter, worker stop on exit.
    with TestClient(app_module.app) as c:
        yield c


def enroll_test_agent(
    client: TestClient, agent_id: str, host_id: str, *, token: str = "test-bootstrap-token"
):
    """Performs a full, real Phase 13 enrollment round trip (challenge ->
    locally-generated ECDSA P-256 keypair -> signed proof of possession ->
    enroll) and returns the raw response, so callers can assert either
    success (then read .json()["access_token"]) or a specific failure mode.
    Every test that used to POST {"agent_id", "host_id"} directly needs this
    now that the enrollment contract requires public_key/nonce/signature."""
    import base64

    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec

    challenge = client.post("/api/v1/agents/enrollment-challenge")
    assert challenge.status_code == 200, challenge.text
    nonce_b64 = challenge.json()["nonce"]
    nonce_raw = base64.b64decode(nonce_b64)

    private_key = ec.generate_private_key(ec.SECP256R1())
    numbers = private_key.public_key().public_numbers()
    public_key_raw = b"\x04" + numbers.x.to_bytes(32, "big") + numbers.y.to_bytes(32, "big")

    signature_raw = private_key.sign(nonce_raw, ec.ECDSA(hashes.SHA256()))

    return client.post(
        "/api/v1/agents/enroll",
        json={
            "agent_id": agent_id,
            "host_id": host_id,
            "public_key": base64.b64encode(public_key_raw).decode("ascii"),
            "nonce": nonce_b64,
            "signature": base64.b64encode(signature_raw).decode("ascii"),
        },
        headers={"X-Panopticon-Enrollment-Token": token},
    )
