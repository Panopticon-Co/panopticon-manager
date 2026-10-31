import json

from fastapi.testclient import TestClient

from manager.timeutil import iso_now
from tests.conftest import enroll_test_agent
from tests.test_response_actions_route import _enroll_analyst


def _insert_event(
    event_id: str,
    agent_id: str,
    host_id: str,
    category: str = "process",
    pid: int = 100,
    ppid: int = 4,
) -> None:
    import manager.db as db_module

    raw = {
        "schema_version": "0.3",
        "event": {"id": event_id, "category": category, "type": "start", "timestamp": iso_now()},
        "host": {
            "id": host_id,
            "hostname": host_id.lower(),
            "os": {"name": "Windows 11 Pro", "build": "26200"},
        },
        "process": {
            "pid": pid,
            "name": "cmd.exe",
            "command_line": "cmd /c whoami",
            "parent": {"pid": ppid, "name": "explorer.exe"},
        },
    }
    conn = db_module.connect()
    conn.execute(
        "INSERT INTO events (event_id, agent_id, host_id, category, event_timestamp, ingested_at, "
        "schema_version, raw_json) VALUES (?, ?, ?, ?, ?, ?, '0.3', ?)",
        (event_id, agent_id, host_id, category, iso_now(), iso_now(), json.dumps(raw)),
    )
    conn.commit()


def _auth(client: TestClient) -> dict:
    return {"Authorization": "Bearer " + _enroll_analyst(client, "alice")}


def test_inventory_requires_analyst_token(client: TestClient) -> None:
    assert client.get("/api/v1/agents").status_code == 401
    assert client.get("/api/v1/events").status_code == 401


def test_agents_reports_enrolled_and_unenrolled_activity(client: TestClient) -> None:
    h = _auth(client)
    assert enroll_test_agent(client, "agent-a", "HOST-A").status_code == 200
    assert enroll_test_agent(client, "agent-idle", "HOST-B").status_code == 200
    _insert_event("evt_1", "agent-a", "HOST-A")
    _insert_event("evt_2", "replay-agent", "HOST-R")

    body = client.get("/api/v1/agents", headers=h).json()
    by_id = {a["agent_id"]: a for a in body["agents"]}
    assert by_id["agent-a"]["status"] == "online"
    assert by_id["agent-a"]["event_count"] == 1
    assert by_id["agent-a"]["os"] == "Windows 11 Pro 26200"
    assert by_id["agent-a"]["hostname"] == "host-a"
    assert by_id["agent-idle"]["status"] == "never_seen"
    assert by_id["agent-idle"]["last_seen"] is None
    assert [s["agent_id"] for s in body["unenrolled_sources"]] == ["replay-agent"]


def test_events_tail_by_cursor_and_link_alerts(client: TestClient) -> None:
    import manager.db as db_module

    h = _auth(client)
    _insert_event("evt_a", "agent-1", "HOST-1", pid=200, ppid=100)
    first = client.get("/api/v1/events", headers=h).json()
    assert [e["event_id"] for e in first["events"]] == ["evt_a"]
    assert first["events"][0]["process"]["parent_pid"] == 100
    assert first["events"][0]["severity"] == "info"
    cursor = first["cursor"]

    empty = client.get("/api/v1/events", headers=h, params=cursor).json()
    assert empty["events"] == [] and empty["cursor"] == cursor

    _insert_event("evt_b", "agent-1", "HOST-1", category="network")
    conn = db_module.connect()
    conn.execute(
        "INSERT INTO alerts (alert_id, rule_id, level, severity, host_id, agent_id, event_id, "
        "created_at, alert_json) "
        "VALUES ('ALT-1', 'DET-1', 10, 'high', 'HOST-1', 'agent-1', 'evt_b', ?, '{}')",
        (iso_now(),),
    )
    conn.commit()
    tail = client.get("/api/v1/events", headers=h, params=cursor).json()
    assert [e["event_id"] for e in tail["events"]] == ["evt_b"]
    assert tail["events"][0]["severity"] == "high"
    assert tail["events"][0]["alerts"][0]["alert_id"] == "ALT-1"
    assert tail["cursor"]["after_event"] > cursor["after_event"]

    filtered = client.get("/api/v1/events", headers=h, params={"category": "network"}).json()
    assert [e["event_id"] for e in filtered["events"]] == ["evt_b"]
