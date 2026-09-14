"""Phase 13: adversarial coverage for cryptographic enrollment identity
(docs/adr/004-agent-enrollment-identity.md). Each test reproduces one
specific attack the enrollment protocol must defend against, not just a
happy-path source read."""

from __future__ import annotations

import base64

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, utils
from fastapi.testclient import TestClient

from tests.conftest import enroll_test_agent


def _keypair():
    private_key = ec.generate_private_key(ec.SECP256R1())
    numbers = private_key.public_key().public_numbers()
    public_key_raw = b"\x04" + numbers.x.to_bytes(32, "big") + numbers.y.to_bytes(32, "big")
    return private_key, base64.b64encode(public_key_raw).decode("ascii")


def _sign_raw(private_key, data: bytes) -> bytes:
    """cryptography's sign() returns DER; the wire contract uses raw r||s."""
    r, s = utils.decode_dss_signature(private_key.sign(data, ec.ECDSA(hashes.SHA256())))
    return r.to_bytes(32, "big") + s.to_bytes(32, "big")


def _challenge(client: TestClient) -> tuple[str, bytes]:
    resp = client.post("/api/v1/agents/enrollment-challenge")
    assert resp.status_code == 200
    nonce_b64 = resp.json()["nonce"]
    return nonce_b64, base64.b64decode(nonce_b64)


def _enroll_raw(client: TestClient, **fields):
    body = {"agent_id": "agent-x", "host_id": "host-x", **fields}
    return client.post(
        "/api/v1/agents/enroll",
        json=body,
        headers={"X-Panopticon-Enrollment-Token": "test-bootstrap-token"},
    )


def test_valid_enrollment_succeeds_and_persists_the_public_key(client: TestClient) -> None:
    response = enroll_test_agent(client, "agent-valid", "host-valid")
    assert response.status_code == 200
    assert response.json()["token_type"] == "Bearer"

    import manager.db as db_module

    row = db_module.connect().execute(
        "SELECT public_key FROM enrolled_agents WHERE agent_id = ?", ("agent-valid",)
    ).fetchone()
    assert row["public_key"] is not None and len(row["public_key"]) > 0


def test_invalid_signature_is_rejected(client: TestClient) -> None:
    nonce_b64, nonce_raw = _challenge(client)
    private_key, public_key_b64 = _keypair()
    # Sign the WRONG bytes -- simulates a forged/corrupted signature.
    bad_signature = _sign_raw(private_key, b"not-the-real-nonce")
    resp = _enroll_raw(
        client,
        public_key=public_key_b64,
        nonce=nonce_b64,
        signature=base64.b64encode(bad_signature).decode("ascii"),
    )
    assert resp.status_code == 401


def test_signature_from_a_different_keypair_than_the_declared_public_key_is_rejected(
    client: TestClient,
) -> None:
    """Key substitution: an attacker who does not hold the declared
    public_key's private key cannot enroll by signing with a DIFFERENT key
    they do hold."""
    nonce_b64, nonce_raw = _challenge(client)
    _, declared_public_key_b64 = _keypair()  # attacker doesn't have this private key
    attacker_private_key, _ = _keypair()
    forged_signature = _sign_raw(attacker_private_key, nonce_raw)
    resp = _enroll_raw(
        client,
        public_key=declared_public_key_b64,
        nonce=nonce_b64,
        signature=base64.b64encode(forged_signature).decode("ascii"),
    )
    assert resp.status_code == 401


def test_expired_or_never_issued_nonce_is_rejected(client: TestClient) -> None:
    private_key, public_key_b64 = _keypair()
    fake_nonce_raw = b"\x00" * 32
    fake_nonce_b64 = base64.b64encode(fake_nonce_raw).decode("ascii")
    signature = _sign_raw(private_key, fake_nonce_raw)
    resp = _enroll_raw(
        client,
        public_key=public_key_b64,
        nonce=fake_nonce_b64,
        signature=base64.b64encode(signature).decode("ascii"),
    )
    assert resp.status_code == 401


def test_reused_nonce_is_rejected_the_second_time(client: TestClient) -> None:
    """Replay: a captured, previously-successful enrollment request must not
    be replayable to enroll a second (or the same) identity."""
    nonce_b64, nonce_raw = _challenge(client)
    private_key, public_key_b64 = _keypair()
    signature_raw = _sign_raw(private_key, nonce_raw)
    signature_b64 = base64.b64encode(signature_raw).decode("ascii")

    first = client.post(
        "/api/v1/agents/enroll",
        json={
            "agent_id": "agent-replay-1",
            "host_id": "host-replay-1",
            "public_key": public_key_b64,
            "nonce": nonce_b64,
            "signature": signature_b64,
        },
        headers={"X-Panopticon-Enrollment-Token": "test-bootstrap-token"},
    )
    assert first.status_code == 200

    replay = client.post(
        "/api/v1/agents/enroll",
        json={
            "agent_id": "agent-replay-2",
            "host_id": "host-replay-2",
            "public_key": public_key_b64,
            "nonce": nonce_b64,
            "signature": signature_b64,
        },
        headers={"X-Panopticon-Enrollment-Token": "test-bootstrap-token"},
    )
    assert replay.status_code == 401


def test_malformed_public_key_length_is_rejected_by_schema_validation(client: TestClient) -> None:
    nonce_b64, _ = _challenge(client)
    resp = _enroll_raw(client, public_key="QQ==", nonce=nonce_b64, signature="QQ==" * 5)
    assert resp.status_code == 422


def test_missing_public_key_is_rejected(client: TestClient) -> None:
    nonce_b64, _ = _challenge(client)
    body = {
        "agent_id": "agent-x",
        "host_id": "host-x",
        "nonce": nonce_b64,
        "signature": base64.b64encode(b"x" * 70).decode("ascii"),
    }
    resp = client.post(
        "/api/v1/agents/enroll",
        json=body,
        headers={"X-Panopticon-Enrollment-Token": "test-bootstrap-token"},
    )
    assert resp.status_code == 422


def test_unauthorized_enrollment_without_bootstrap_token_is_rejected(client: TestClient) -> None:
    nonce_b64, nonce_raw = _challenge(client)
    private_key, public_key_b64 = _keypair()
    signature_raw = _sign_raw(private_key, nonce_raw)
    signature_b64 = base64.b64encode(signature_raw).decode("ascii")
    resp = client.post(
        "/api/v1/agents/enroll",
        json={
            "agent_id": "agent-unauth",
            "host_id": "host-unauth",
            "public_key": public_key_b64,
            "nonce": nonce_b64,
            "signature": signature_b64,
        },
        headers={"X-Panopticon-Enrollment-Token": "wrong-token"},
    )
    assert resp.status_code == 401


def test_host_id_takeover_by_a_new_agent_id_is_rejected(client: TestClient) -> None:
    """A new, unrelated agent_id must not be able to claim an already
    actively-enrolled endpoint's host_id merely by declaring it."""
    first = enroll_test_agent(client, "agent-original", "host-shared")
    assert first.status_code == 200

    takeover = enroll_test_agent(client, "agent-attacker", "host-shared")
    assert takeover.status_code == 409


def test_revoked_endpoints_host_id_can_be_legitimately_re_enrolled(client: TestClient) -> None:
    """A revoked endpoint's host_id is not permanently poisoned -- a fresh,
    legitimately-authorized re-image/re-enrollment under a new agent_id must
    still work."""
    import manager.db as db_module
    from manager.timeutil import iso_now

    first = enroll_test_agent(client, "agent-old", "host-reimaged")
    assert first.status_code == 200

    conn = db_module.connect()
    conn.execute(
        "UPDATE enrolled_agents SET revoked_at = ? WHERE agent_id = ?", (iso_now(), "agent-old")
    )
    conn.commit()

    second = enroll_test_agent(client, "agent-new", "host-reimaged")
    assert second.status_code == 200


def test_duplicate_agent_id_enrollment_is_still_rejected(client: TestClient) -> None:
    first = enroll_test_agent(client, "agent-dup", "host-dup-1")
    assert first.status_code == 200
    second = enroll_test_agent(client, "agent-dup", "host-dup-2")
    assert second.status_code == 409


def test_revoked_endpoint_cannot_authenticate_normal_operations(client: TestClient) -> None:
    import manager.db as db_module
    from manager.timeutil import iso_now

    enrollment = enroll_test_agent(client, "agent-to-revoke", "host-to-revoke")
    assert enrollment.status_code == 200
    token = enrollment.json()["access_token"]

    conn = db_module.connect()
    conn.execute(
        "UPDATE enrolled_agents SET revoked_at = ? WHERE agent_id = ?",
        (iso_now(), "agent-to-revoke"),
    )
    conn.commit()

    resp = client.get(
        "/api/v1/agents/agent-to-revoke/commands",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 401
