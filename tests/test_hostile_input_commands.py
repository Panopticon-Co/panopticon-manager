"""Priority 3 (fuzz/robustness): bounded, deterministic hostile-input
coverage for the /api/v1/commands and /api/v1/agents/{id}/command-results
request bodies -- these are pydantic-validated by response_engine.contract's
Command/CommandResult, but that validation has never been proven against
genuinely malformed transport-level input (not-JSON-at-all, truncated JSON,
oversized bodies, null-for-required, wrong JSON types, duplicate keys). Per
the operating directive, a bounded deterministic suite is used instead of a
fuzzing harness/dependency (no hypothesis or similar is installed in this
project, and none is warranted for a handful of pydantic-validated endpoints
already covered structurally by tests/test_adversarial_security.py and
vendor/response_engine's own tests/test_contract.py)."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from fastapi.testclient import TestClient

from tests.test_command_route import _enroll

_COMMAND_HEADERS = {
    "X-Panopticon-Command-Token": "test-command-token",
    "Content-Type": "application/json",
}


def _future_iso() -> str:
    return (datetime.now(timezone.utc) + timedelta(minutes=5)).isoformat()


def test_completely_non_json_body_is_rejected(client: TestClient) -> None:
    _enroll(client, "agent-1", "host-1")
    response = client.post(
        "/api/v1/commands", content=b"not json at all {{{", headers=_COMMAND_HEADERS
    )
    assert response.status_code == 422


def test_truncated_json_body_is_rejected(client: TestClient) -> None:
    _enroll(client, "agent-1", "host-1")
    truncated = b'{"command_id": "cmd-1", "agent_id": "agent-1", "action": "ISOLATE_HOST"'
    response = client.post("/api/v1/commands", content=truncated, headers=_COMMAND_HEADERS)
    assert response.status_code == 422


def test_json_array_instead_of_object_is_rejected(client: TestClient) -> None:
    _enroll(client, "agent-1", "host-1")
    response = client.post("/api/v1/commands", content=b"[1, 2, 3]", headers=_COMMAND_HEADERS)
    assert response.status_code == 422


def test_json_scalar_instead_of_object_is_rejected(client: TestClient) -> None:
    _enroll(client, "agent-1", "host-1")
    response = client.post(
        "/api/v1/commands", content=b'"just a string"', headers=_COMMAND_HEADERS
    )
    assert response.status_code == 422


def test_empty_body_is_rejected(client: TestClient) -> None:
    _enroll(client, "agent-1", "host-1")
    response = client.post("/api/v1/commands", content=b"", headers=_COMMAND_HEADERS)
    assert response.status_code == 422


def test_null_for_every_required_field_is_rejected(client: TestClient) -> None:
    _enroll(client, "agent-1", "host-1")
    response = client.post(
        "/api/v1/commands",
        json={"command_id": None, "agent_id": None, "action": None, "expires_at": None},
        headers={"X-Panopticon-Command-Token": "test-command-token"},
    )
    assert response.status_code == 422


def test_wrong_json_types_for_every_field_are_rejected(client: TestClient) -> None:
    _enroll(client, "agent-1", "host-1")
    response = client.post(
        "/api/v1/commands",
        json={
            "command_id": 12345,
            "agent_id": ["agent-1"],
            "action": {"nested": "object"},
            "expires_at": True,
            "target": "not-a-dict",
        },
        headers={"X-Panopticon-Command-Token": "test-command-token"},
    )
    assert response.status_code == 422


def test_invalid_utf8_body_is_rejected_not_crashed(client: TestClient) -> None:
    """Starlette rejects an invalid-UTF-8/unparseable body at the ASGI layer
    with 400 before FastAPI's own pydantic validation (422) ever runs --
    either is an acceptable fail-closed outcome; a 5xx or a hang would not
    be."""
    _enroll(client, "agent-1", "host-1")
    response = client.post(
        "/api/v1/commands", content=b"\xff\xfe\x00invalid-utf8", headers=_COMMAND_HEADERS
    )
    assert response.status_code in (400, 422)


def test_deeply_nested_json_does_not_crash_the_parser(client: TestClient) -> None:
    """A pathologically nested (but not otherwise huge) JSON body must fail
    validation cleanly rather than exhausting the stack or hanging."""
    _enroll(client, "agent-1", "host-1")
    nested: dict = {"a": 1}
    for _ in range(500):
        nested = {"a": nested}
    response = client.post(
        "/api/v1/commands",
        json={
            "command_id": "cmd-nested",
            "agent_id": "agent-1",
            "action": "ISOLATE_HOST",
            "expires_at": _future_iso(),
            "target": nested,
        },
        headers={"X-Panopticon-Command-Token": "test-command-token"},
    )
    assert response.status_code == 422


def test_duplicate_json_keys_resolve_deterministically_to_the_last_value(
    client: TestClient,
) -> None:
    """Standard JSON parsers (Python's json module included) silently keep
    the last occurrence of a duplicate key. This must resolve deterministically
    (last value wins) rather than validating against one value and later code
    reading a different one -- a classic request-smuggling-adjacent class of
    bug. Here: the first `action` is a bogus/eighth action, the second (the
    one that must win) is a real one."""
    _enroll(client, "agent-1", "host-1")
    body = (
        b'{"command_id": "cmd-dup-key", "agent_id": "agent-1", '
        b'"action": "EXECUTE_COMMAND", "action": "ISOLATE_HOST", '
        b'"expires_at": "' + _future_iso().encode() + b'"}'
    )
    response = client.post("/api/v1/commands", content=body, headers=_COMMAND_HEADERS)
    assert response.status_code == 200
    assert response.json()["command_id"] == "cmd-dup-key"


def test_result_body_non_json_and_wrong_types_are_rejected(client: TestClient) -> None:
    token = _enroll(client, "agent-1", "host-1")
    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
    non_json = client.post(
        "/api/v1/agents/agent-1/command-results", content=b"{{{not json", headers=headers
    )
    assert non_json.status_code == 422
    wrong_types = client.post(
        "/api/v1/agents/agent-1/command-results",
        json={"result_id": 1, "command_id": None, "outcome": "not-a-real-outcome"},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert wrong_types.status_code == 422


def test_huge_integer_in_target_does_not_crash_validation(client: TestClient) -> None:
    """Python ints are arbitrary-precision, so this must be rejected by the
    contract's own semantics (or accepted and handled safely), never crash
    the process or hang."""
    _enroll(client, "agent-1", "host-1")
    response = client.post(
        "/api/v1/commands",
        json={
            "command_id": "cmd-huge-int",
            "agent_id": "agent-1",
            "action": "KILL_PROCESS",
            "expires_at": _future_iso(),
            "target": {"pid": 42, "start_time_ticks": 10**300},
        },
        headers={"X-Panopticon-Command-Token": "test-command-token"},
    )
    assert response.status_code in (200, 422)
