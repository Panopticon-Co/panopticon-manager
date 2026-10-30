"""Analyst API for alerts, incidents, response actions and status
(CONTRACT.md §7). Rows are seeded through manager/detection/store.py and
response.on_alert_created -- the same functions the detection worker calls --
so these tests cover the HTTP surface independently of the engine;
tests/test_capstone_e2e.py drives the whole pipeline."""

from __future__ import annotations

from fastapi.testclient import TestClient

import manager.db as db_module
from tests.test_command_route import _enroll
from tests.test_incident_store import _INC, _S1, _S2, _S3, _incident_alert, _stage_alert
from tests.test_response_actions_route import _enroll_analyst


def _seed(*, with_kill: bool = False) -> None:
    from manager.detection import response
    from manager.detection.store import insert_alert, upsert_incident

    conn = db_module.connect()
    conn.execute("BEGIN IMMEDIATE")
    for alert_id, rule, ts in (_S1, _S2, _S3):
        alert = _stage_alert(alert_id, rule, ts)
        if with_kill and alert_id == "ALT-1":
            alert["active_response"] = {
                "action": "TERMINATE_PROCESS",
                "host_id": "WS-1",
                "target_pid": 4100,
                "target_start_time_ticks": 133_400_000_000_000_000,
            }
        insert_alert(conn, alert, agent_id="agent-1")
        response.on_alert_created(conn, alert)
    beacon = _stage_alert("ALT-BCN", "DET-NET-004", _S3[2], source="behavioral")
    beacon["severity"] = "critical"
    insert_alert(conn, beacon, agent_id="agent-1")
    for alert in (
        _incident_alert(1, [_S1, _S2], ["Execution", "Command and Control"]),
        _incident_alert(2, [_S1, _S2, _S3], ["Execution", "Command and Control", "Persistence"]),
    ):
        insert_alert(conn, alert, agent_id="agent-1")
        upsert_incident(conn, alert, agent_id="agent-1")
    conn.commit()


def _h(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


def test_new_routes_require_analyst_token(client: TestClient) -> None:
    for path in (
        "/api/v1/alerts/ALT-1",
        "/api/v1/incidents",
        f"/api/v1/incidents/{_INC}",
        "/api/v1/status",
    ):
        assert client.get(path).status_code == 401, path
    agent_token = _enroll(client, "agent-x", "host-x")
    assert client.get("/api/v1/incidents", headers=_h(agent_token)).status_code == 401
    resp = client.post(f"/api/v1/incidents/{_INC}/status", json={"status": "resolved"})
    assert resp.status_code == 401


def test_alert_filters_and_cursor(client: TestClient) -> None:
    token = _enroll_analyst(client, "alice")
    _seed()
    h = _h(token)

    rows = client.get("/api/v1/alerts", headers=h).json()
    assert rows["next_before"] is None
    assert {r["alert_id"] for r in rows["alerts"]} == {
        "ALT-1", "ALT-2", "ALT-3", "ALT-BCN", f"{_INC}-R1", f"{_INC}-R2",
    }
    by_id = {r["alert_id"]: r for r in rows["alerts"]}
    assert by_id[f"{_INC}-R2"]["incident_id"] == _INC
    assert by_id[f"{_INC}-R2"]["detection_source"] == "correlation"
    assert by_id["ALT-1"]["detection_source"] == "rule"

    def ids(query: str) -> set[str]:
        resp = client.get(f"/api/v1/alerts?{query}", headers=h)
        assert resp.status_code == 200, resp.text
        return {r["alert_id"] for r in resp.json()["alerts"]}

    assert ids("source=behavioral") == {"ALT-BCN"}
    assert ids(f"incident_id={_INC}") == {f"{_INC}-R1", f"{_INC}-R2"}
    assert ids("rule_id=DET-NET-007") == {"ALT-2"}
    assert ids("severity=critical") == {"ALT-BCN", f"{_INC}-R2"}
    assert ids("host_id=nope") == set()

    # Keyset paging walks every row exactly once, newest first.
    seen: list[str] = []
    before = None
    while True:
        query = "limit=2" + (f"&before={before}" if before else "")
        page = client.get(f"/api/v1/alerts?{query}", headers=h).json()
        seen += [r["alert_id"] for r in page["alerts"]]
        before = page["next_before"]
        if before is None:
            break
    assert sorted(seen) == sorted(by_id) and len(seen) == len(set(seen))
    assert seen == [r["alert_id"] for r in rows["alerts"]]


def test_alert_inputs_are_validated(client: TestClient) -> None:
    h = _h(_enroll_analyst(client, "alice"))
    for query in ("severity=extreme", "source=bogus", "limit=0", "limit=201", "before=garbage"):
        assert client.get(f"/api/v1/alerts?{query}", headers=h).status_code == 422, query
    assert client.get("/api/v1/alerts/ALT-NOPE", headers=h).status_code == 404


def test_alert_detail_includes_response_actions(client: TestClient) -> None:
    h = _h(_enroll_analyst(client, "alice"))
    _seed(with_kill=True)
    body = client.get("/api/v1/alerts/ALT-1", headers=h).json()
    assert body["alert"]["alert_id"] == "ALT-1"
    assert body["alert"]["alert"]["rule_id"] == "DET-PROC-001"
    (action,) = body["response_actions"]
    assert action["action"] == "KILL_PROCESS"
    assert action["lifecycle_state"] == "PENDING"
    assert action["audit"] == [] and action["command_lifecycle_state"] is None


def test_incident_list_and_detail(client: TestClient) -> None:
    h = _h(_enroll_analyst(client, "alice"))
    _seed(with_kill=True)

    listed = client.get("/api/v1/incidents", headers=h).json()["incidents"]
    (summary,) = listed
    assert summary["incident_id"] == _INC
    assert summary["status"] == "open"
    assert summary["revision"] == 2
    assert summary["stage_count"] == 3
    assert summary["tactics"] == ["Execution", "Command and Control", "Persistence"]
    assert summary["root_process"] == "winword.exe"
    assert summary["alert_count"] == 5  # R1, R2 and three stage alerts

    assert client.get("/api/v1/incidents?status=resolved", headers=h).json()["incidents"] == []
    assert client.get("/api/v1/incidents?host_id=WS-1", headers=h).json()["incidents"]
    assert client.get("/api/v1/incidents?status=closed", headers=h).status_code == 422
    assert client.get("/api/v1/incidents?limit=0", headers=h).status_code == 422
    assert client.get("/api/v1/incidents/INC-NOPE", headers=h).status_code == 404

    detail = client.get(f"/api/v1/incidents/{_INC}", headers=h).json()
    incident = detail["incident"]
    assert incident["latest_alert_id"] == f"{_INC}-R2"
    for key in ("stages", "causal_path", "process_lineage", "score_breakdown", "why"):
        assert key in incident["evidence"], key
    assert len(incident["evidence"]["stages"]) == 3
    roles = {(a["alert_id"], a["role"]) for a in detail["alerts"]}
    assert (f"{_INC}-R1", "revision") in roles and ("ALT-3", "stage") in roles
    assert [a["action"] for a in detail["response_actions"]] == ["KILL_PROCESS"]
    assert [a["event"] for a in detail["audit"]] == ["opened", "revised"]
    assert detail["audit"][1]["detail"]["from_revision"] == 1


def test_incident_status_change_is_audited_and_validated(client: TestClient) -> None:
    h = _h(_enroll_analyst(client, "alice"))
    _seed()
    url = f"/api/v1/incidents/{_INC}/status"
    assert client.post(url, json={"status": "closed"}, headers=h).status_code == 422
    assert client.post(url, json={"status": "resolved", "x": 1}, headers=h).status_code == 422
    missing = client.post(
        "/api/v1/incidents/INC-NOPE/status", json={"status": "resolved"}, headers=h
    )
    assert missing.status_code == 404

    resp = client.post(url, json={"status": "investigating", "note": "triage"}, headers=h)
    assert resp.status_code == 200
    assert resp.json()["incident"]["status"] == "investigating"

    audit = client.get(f"/api/v1/incidents/{_INC}", headers=h).json()["audit"]
    assert audit[-1]["event"] == "status_changed"
    assert audit[-1]["actor"] == "analyst:alice"
    assert audit[-1]["detail"] == {"from": "open", "to": "investigating", "note": "triage"}
    assert [i["incident_id"] for i in client.get(
        "/api/v1/incidents?status=investigating", headers=h
    ).json()["incidents"]] == [_INC]


def test_response_actions_list_carries_command_audit(client: TestClient) -> None:
    h = _h(_enroll_analyst(client, "alice"))
    _enroll(client, "agent-1", "WS-1")
    _seed(with_kill=True)
    (pending,) = client.get("/api/v1/response-actions?state=PENDING", headers=h).json()[
        "response_actions"
    ]
    assert pending["audit"] == []
    ok = client.post(f"/api/v1/response-actions/{pending['response_id']}/authorize", headers=h)
    assert ok.status_code == 200
    (authorized,) = client.get("/api/v1/response-actions?state=AUTHORIZED", headers=h).json()[
        "response_actions"
    ]
    assert authorized["command_lifecycle_state"] == "AUTHORIZED"
    assert [(a["event"], a["actor"]) for a in authorized["audit"]] == [
        ("created", "analyst:alice")
    ]
    assert client.get("/api/v1/response-actions?state=BOGUS", headers=h).status_code == 422


def test_status_endpoint(client: TestClient) -> None:
    h = _h(_enroll_analyst(client, "alice"))
    _enroll(client, "agent-1", "WS-1")
    _seed(with_kill=True)
    body = client.get("/api/v1/status", headers=h).json()
    assert body["events"] == {"pending": 0, "claimed": 0, "done": 0, "failed": 0}
    assert body["alerts"] == 6
    assert body["incidents_open"] == 1
    assert body["response_actions"] == {"PENDING": 1}
    assert body["agents_enrolled"] == 1
    assert body["last_event_at"] is None
