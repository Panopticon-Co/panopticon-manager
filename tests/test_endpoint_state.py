"""Clock rollback, offline replay and installation forks cannot bless stale state."""

import copy
import hashlib

from manager import db
from tests.test_endpoint_records import headers, post, records


def health(generation, sequence=1, *, epoch_tag=None, installation=None, timestamp=None):
    record = copy.deepcopy(records()[4])
    epoch = "epoch_" + hashlib.sha256((epoch_tag or str(generation)).encode()).hexdigest()
    record["provenance"].update(
        collector_generation=str(generation), collector_epoch=epoch, sequence=str(sequence)
    )
    if installation:
        record["endpoint"]["installation_id"] = installation
    if timestamp:
        record["observed_at"] = timestamp
    material = record["endpoint"]["installation_id"] + ":" + epoch + ":" + str(sequence)
    record["record_id"] = "rec_" + hashlib.sha256(material.encode()).hexdigest()
    return record


def latest(client, hdr):
    response = client.get(
        "/api/v2/endpoint/agent-1/latest", headers={"Authorization": hdr["Authorization"]}
    )
    assert response.status_code == 200
    return response.json()


def test_clock_rollback_and_late_offline_replay_never_select_old_health(client):
    hdr = headers(client)
    old = health(1, timestamp="2035-01-01T00:00:00.000Z")
    new = health(2, timestamp="2020-01-01T00:00:00.000Z")
    assert post(client, hdr, [old, new]).json()["accepted"] == 2
    replay = health(1, 9, timestamp="2040-01-01T00:00:00.000Z")
    assert post(client, hdr, [replay]).json()["accepted"] == 1
    result = latest(client, hdr)
    assert result["records"] == [new]
    assert result["projection_status"][0]["ordering"] == "current"
    assert result["projection_status"][0]["observation_freshness"] == "unverified"
    assert db.connect().execute("SELECT COUNT(*) FROM endpoint_records").fetchone()[0] == 3


def test_sequence_orders_state_within_generation_independent_of_arrival(client):
    hdr = headers(client)
    values = [health(1, 12), health(1, 9), health(1, 15), health(1, 3)]
    assert post(client, hdr, values).json()["accepted"] == 4
    assert latest(client, hdr)["records"] == [values[2]]


def test_new_generation_invalidates_old_domain_projections(client):
    hdr = headers(client)
    old = health(1)
    assert post(client, hdr, [old]).json()["accepted"] == 1
    other = health(2)
    other.update(kind="state", category="security_posture", data={"complete": False})
    assert post(client, hdr, [other]).json()["accepted"] == 1
    status = {row["record_id"]: row["ordering"] for row in latest(client, hdr)["projection_status"]}
    assert status[old["record_id"]] == "superseded"
    assert status[other["record_id"]] == "current"


def test_generation_fork_rolls_back_entire_batch_and_retains_prior_evidence(client):
    hdr = headers(client)
    original = health(1)
    assert post(client, hdr, [original]).json()["accepted"] == 1
    newer = health(2)
    fork = health(1, epoch_tag="cloned-counter")
    assert post(client, hdr, [newer, fork]).status_code == 409
    assert db.connect().execute("SELECT COUNT(*) FROM endpoint_records").fetchone()[0] == 1
    assert latest(client, hdr)["records"] == [original]


def test_installation_replacement_is_history_without_implicit_reactivation(client):
    hdr = headers(client)
    active = health(8)
    replacement = health(99, installation="c" * 64)
    assert post(client, hdr, [active, replacement]).json()["accepted"] == 2
    assert latest(client, hdr)["records"] == [active]
    assert db.connect().execute("SELECT COUNT(*) FROM endpoint_records").fetchone()[0] == 2


def test_unordered_records_cannot_displace_ordered_projection(client):
    hdr = headers(client)
    unverified = health(1)
    del unverified["provenance"]["collector_generation"]
    assert post(client, hdr, [unverified]).json()["accepted"] == 1
    assert latest(client, hdr)["projection_status"][0]["ordering"] == "unverified"
    ordered = health(2)
    assert post(client, hdr, [ordered]).json()["accepted"] == 1
    later_unverified = health(3)
    del later_unverified["provenance"]["collector_generation"]
    assert post(client, hdr, [later_unverified]).json()["accepted"] == 1
    assert latest(client, hdr)["records"] == [ordered]
