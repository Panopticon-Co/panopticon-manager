"""Authenticated runtime-policy API and contract regressions; no native E2E."""

import base64
import copy
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import jsonschema
import pytest
from fastapi import HTTPException

from manager import db
from manager.response_profile import RuntimeProfile, current_profile, parse_header, policy_block
from tests.test_analyst_operations import create, setup

POLL = "/api/v1/agents/agent-1/commands?delivery_mode=durable"
ACTIONS = [
    "KILL_PROCESS",
    "COLLECT_PROCESS_INFO",
    "COLLECT_NETWORK_CONNECTIONS",
    "COLLECT_FILE",
    "QUARANTINE_FILE",
    "ISOLATE_HOST",
    "RELEASE_HOST_ISOLATION",
]


def profile(**changes):
    result = {
        "schema_version": "1",
        "platform": "linux",
        "host_id": "host-1",
        "boot_id": "boot_" + "a" * 64,
        "mode": "enforce",
        "implemented_actions": ACTIONS[:],
        "allowed_actions": ACTIONS[:],
        "require_boot_binding": False,
        "require_signature": False,
    }
    result.update(changes)
    return result


def encoded(value):
    return base64.b64encode(json.dumps(value).encode()).decode()


def poll(client, agent, report, path=POLL):
    return client.get(path, headers={**agent, "X-Panopticon-Response-Profile": encoded(report)})


def readiness(client, analyst):
    return client.get("/api/v1/agents/agent-1/response-readiness", headers=analyst).json()


def test_current_profile_is_authenticated_host_bound_and_reported_for_both_platforms(client):
    analyst, agent = setup(client)
    assert poll(client, analyst, profile()).status_code == 401
    assert poll(client, agent, profile(host_id="another-host")).status_code == 403
    assert readiness(client, analyst)["runtime_profile"]["state"] == "unknown"
    for platform in ("linux", "windows"):
        assert poll(client, agent, profile(platform=platform)).status_code == 200
        state = readiness(client, analyst)
        assert state["runtime_profile"]["state"] == "recent"
        assert state["runtime_profile"]["report"]["platform"] == platform
        assert state["native_capabilities"] == "current_report"
        assert state["execution_mode"] == "enforce"


@pytest.mark.parametrize(
    "changes",
    [
        {"mode": "automatic"},
        {"allowed_actions": ["EXECUTE_COMMAND"]},
        {"allowed_actions": ["KILL_PROCESS", "KILL_PROCESS"]},
        {"implemented_actions": [], "allowed_actions": ["KILL_PROCESS"]},
        {"require_signature": 1},
        {"require_boot_binding": "true"},
        {"schema_version": 1},
        {"boot_id": "kernel-uuid"},
        {"extra": "unexpected"},
        {"host_id": ""},
    ],
)
def test_closed_profile_refuses_ambiguous_or_unsupported_shapes(client, changes):
    analyst, agent = setup(client)
    assert poll(client, agent, profile(**changes)).status_code == 422
    assert readiness(client, analyst)["runtime_profile"]["state"] == "unknown"


@pytest.mark.parametrize(
    "value",
    [
        "not Base64",
        "a" * 4097,
        base64.b64encode(b'{"schema_version":"1","schema_version":"1"}').decode(),
        base64.b64encode(b'{"require_signature":NaN}').decode(),
        base64.b64encode(b"\xff").decode(),
    ],
)
def test_header_encoding_and_size_are_bounded(value):
    with pytest.raises(HTTPException) as error:
        parse_header(value)
    assert error.value.status_code == 422


def test_omitted_report_and_rebound_enrollment_invalidate_freshness(client):
    analyst, agent = setup(client)
    poll(client, agent, profile())
    conn = db.connect()
    conn.execute("UPDATE enrolled_agents SET host_id='rebound'")
    conn.commit()
    assert readiness(client, analyst)["runtime_profile"]["state"] == "invalidated"
    conn.execute("UPDATE enrolled_agents SET host_id='host-1'")
    conn.commit()
    client.get(POLL, headers=agent)
    assert readiness(client, analyst)["runtime_profile"]["state"] == "unknown"
    assert readiness(client, analyst)["execution_mode"] == "unknown"


def test_stale_snapshot_is_explicit_and_never_claims_current_mode(client):
    analyst, agent = setup(client)
    poll(client, agent, profile(mode="dry_run"))
    conn = db.connect()
    conn.execute(
        "UPDATE agent_response_channels SET profile_observed_at=?",
        ((datetime.now(timezone.utc) - timedelta(seconds=301)).isoformat(),),
    )
    conn.commit()
    state = readiness(client, analyst)
    assert state["runtime_profile"]["state"] == "stale"
    assert state["execution_mode"] == "unknown"
    assert current_profile(conn, "agent-1", "host-1")["report"]["mode"] == "dry_run"


@pytest.mark.parametrize(
    "changes",
    [
        {"mode": "off"},
        {"mode": "dry_run"},
        {"allowed_actions": ["COLLECT_NETWORK_CONNECTIONS"]},
        {"allowed_actions": [], "implemented_actions": []},
    ],
)
def test_fresh_runtime_policy_blocks_preflight_and_actual_authorization(client, changes):
    analyst, agent = setup(client)
    rid = create(client, analyst, "ISOLATE_HOST").json()["response_id"]
    assert poll(client, agent, profile(**changes)).status_code == 200
    preview = client.get(f"/api/v1/response-actions/{rid}/preflight", headers=analyst).json()
    assert not preview["allowed_to_authorize"]
    assert any(c["check"] == "runtime_policy" and c["state"] == "block" for c in preview["checks"])
    assert (
        client.post(f"/api/v1/response-actions/{rid}/authorize", headers=analyst).status_code == 409
    )
    assert db.connect().execute("SELECT COUNT(*) FROM commands").fetchone()[0] == 0


def test_read_only_collection_remains_available_in_dry_run(client):
    analyst, agent = setup(client)
    poll(client, agent, profile(mode="dry_run"))
    rid = create(client, analyst).json()["response_id"]
    assert (
        client.post(f"/api/v1/response-actions/{rid}/authorize", headers=analyst).status_code == 200
    )
    response = poll(client, agent, profile(mode="dry_run")).json()
    assert len(response["commands"]) == 1
    assert response["commands"][0]["action"] == "COLLECT_NETWORK_CONNECTIONS"


def test_signature_requirement_is_recorded_and_cannot_silently_downgrade(client):
    analyst, agent = setup(client)
    assert poll(client, agent, profile(require_signature=True)).status_code == 409
    assert readiness(client, analyst)["command_auth"] == "ES256"
    client.get(POLL, headers=agent)
    assert readiness(client, analyst)["command_auth"] == "ES256"
    rid = create(client, analyst).json()["response_id"]
    assert (
        client.post(f"/api/v1/response-actions/{rid}/authorize", headers=analyst).status_code == 503
    )


def test_policy_change_withholds_queued_work_without_false_dispatch(client):
    analyst, agent = setup(client)
    rid = create(client, analyst, "ISOLATE_HOST").json()["response_id"]
    client.post(f"/api/v1/response-actions/{rid}/authorize", headers=analyst)
    assert poll(client, agent, profile(mode="off")).json()["commands"] == []
    row = db.connect().execute("SELECT lifecycle_state,delivered_at FROM commands").fetchone()
    assert tuple(row) == ("AUTHORIZED", None)
    assert len(poll(client, agent, profile()).json()["commands"]) == 1


def test_boot_and_policy_checks_are_exact():
    recent = {"state": "recent", "report": profile(require_boot_binding=True)}
    assert policy_block(recent, "KILL_PROCESS", {"pid": 42})
    target = {"pid": 42, "boot_id": "boot_" + "b" * 64}
    assert policy_block(recent, "KILL_PROCESS", target)
    target["boot_id"] = recent["report"]["boot_id"]
    assert policy_block(recent, "KILL_PROCESS", target) is None
    for state in ("stale", "unknown", "invalidated"):
        assert policy_block({"state": state}, "KILL_PROCESS", {}) is None


def test_schema_and_runtime_validation_agree_on_closed_fields():
    central = Path(__file__).resolve().parents[2] / "panopticon-contracts"
    schema = json.loads((central / "schema/response-profile-v1.schema.json").read_text())
    for platform in ("linux", "windows"):
        valid = profile(platform=platform)
        jsonschema.validate(valid, schema)
        assert RuntimeProfile.model_validate(valid).model_dump() == valid
    bad = copy.deepcopy(profile())
    bad["allowed_actions"] = ["RUN_SCRIPT"]
    assert not jsonschema.Draft202012Validator(schema).is_valid(bad)


@pytest.mark.parametrize("platform", ["windows", "linux"])
def test_signed_artifact_capability_v2_is_current_explicit_and_preserves_legacy_shape(
    client, platform
):
    analyst, agent = setup(client)
    old = profile(platform=platform)
    assert parse_header(encoded(old)) == old
    assert "artifact_protocol" not in RuntimeProfile.model_validate(old).model_dump()
    value = profile(
        platform=platform,
        schema_version="2",
        artifact_protocol="signed-json-v2-resume-v1",
        require_collection_acceptance=True,
    )
    assert poll(client, agent, value).status_code == 200
    state = readiness(client, analyst)["runtime_profile"]
    assert (
        state["state"] == "recent"
        and state["report"]["artifact_protocol"] == value["artifact_protocol"]
    )
    central = Path(__file__).resolve().parents[2] / "panopticon-contracts"
    schema = json.loads((central / "schema/response-profile-v2.schema.json").read_text())
    jsonschema.validate(state["report"], schema)
    assert RuntimeProfile.model_validate(value).model_dump() == value
    unsupported = {**value, "artifact_protocol": None}
    assert parse_header(encoded(unsupported))["artifact_protocol"] is None
    assert poll(client, agent, old).status_code == 200
    assert "artifact_protocol" not in readiness(client, analyst)["runtime_profile"]["report"]


@pytest.mark.parametrize(
    "changes",
    [
        {"schema_version": "1", "artifact_protocol": None},
        {"schema_version": "1", "artifact_protocol": "signed-json-v2-resume-v1"},
        {"schema_version": "2"},
        {"schema_version": "2", "artifact_protocol": "unsigned-files"},
        {"schema_version": "2", "artifact_protocol": True},
        {"schema_version": "1", "require_collection_acceptance": True},
        {"schema_version": "2", "artifact_protocol": "signed-json-v2-resume-v1"},
        {"schema_version": "2", "artifact_protocol": None, "require_collection_acceptance": None},
        {"schema_version": "2", "artifact_protocol": None, "require_collection_acceptance": 1},
    ],
)
def test_profile_version_cannot_invent_or_ambiguously_claim_artifact_delivery(changes):
    with pytest.raises(HTTPException) as error:
        parse_header(encoded(profile(**changes)))
    assert error.value.status_code == 422


def test_blocked_queue_prefix_cannot_starve_permitted_collection(client):
    from manager.routers.commands import Command, authorize_and_enqueue

    _, agent = setup(client)
    for i in range(40):
        authorize_and_enqueue(
            db.connect(),
            Command(
                command_id=f"blocked-{i}",
                agent_id="agent-1",
                action="ISOLATE_HOST",
                target={},
                expires_at=datetime.now(timezone.utc) + timedelta(minutes=10),
            ),
            "system:test",
        )
    authorize_and_enqueue(
        db.connect(),
        Command(
            command_id="permitted",
            agent_id="agent-1",
            action="COLLECT_NETWORK_CONNECTIONS",
            target={},
            expires_at=datetime.now(timezone.utc) + timedelta(minutes=10),
        ),
        "system:test",
    )
    response = poll(client, agent, profile(mode="dry_run"))
    assert response.status_code == 200, response.text
    assert [c["command_id"] for c in response.json()["commands"]] == ["permitted"]
    assert (
        db.connect()
        .execute("SELECT COUNT(*) FROM commands WHERE lifecycle_state='AUTHORIZED'")
        .fetchone()[0]
        == 40
    )


def test_delivery_filter_agrees_with_authorization_policy_for_each_action():
    import sqlite3

    from manager.response_profile import delivery_predicate

    conn = sqlite3.connect(":memory:")
    for mode in ("off", "dry_run", "enforce"):
        for required in (False, True):
            state = {"state": "recent", "report": profile(mode=mode, require_boot_binding=required)}
            sql, args = delivery_predicate(state)
            for action in ACTIONS:
                targets = [{}, {"boot_id": "boot_" + "a" * 64}, {"boot_id": "boot_" + "b" * 64}]
                for target in targets:
                    actual = conn.execute(
                        "SELECT " + sql + " FROM (SELECT ? AS command_json)",
                        (*args, json.dumps({"action": action, "target": target})),
                    ).fetchone()[0]
                    assert bool(actual) == (policy_block(state, action, target) is None)
    conn.close()
