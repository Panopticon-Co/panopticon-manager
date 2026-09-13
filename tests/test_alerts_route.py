from datetime import datetime, timezone

from fastapi.testclient import TestClient

from tests.test_response_actions_route import _enroll_analyst


def _insert_alert(host_id: str, alert_id: str, agent_id: str = "agent-1") -> None:
    import manager.db as db_module

    conn = db_module.connect()
    now = datetime.now(timezone.utc).isoformat()
    conn.execute(
        "INSERT INTO alerts (alert_id, rule_id, level, severity, host_id, agent_id, "
        "created_at, alert_json) VALUES (?, 'rule-1', 10, 'high', ?, ?, ?, ?)",
        (alert_id, host_id, agent_id, now, '{"alert_id": "%s", "rule_id": "rule-1"}' % alert_id),
    )
    conn.commit()


def test_alerts_endpoint_requires_analyst_token(client: TestClient) -> None:
    assert client.get("/api/v1/alerts").status_code == 401


def test_alerts_endpoint_lists_alerts_most_recent_first(client: TestClient) -> None:
    analyst_token = _enroll_analyst(client, "alice")
    _insert_alert("host-1", "ALT-a1")
    _insert_alert("host-1", "ALT-a2")
    resp = client.get("/api/v1/alerts", headers={"Authorization": f"Bearer {analyst_token}"})
    assert resp.status_code == 200
    alerts = resp.json()["alerts"]
    ids = [row["alert_id"] for row in alerts]
    assert "ALT-a1" in ids
    assert "ALT-a2" in ids
    matching = [row for row in alerts if row["alert_id"] == "ALT-a1"]
    assert matching[0]["alert"]["rule_id"] == "rule-1"


def test_alerts_endpoint_filters_by_host_id(client: TestClient) -> None:
    analyst_token = _enroll_analyst(client, "alice")
    _insert_alert("host-1", "ALT-h1")
    _insert_alert("host-2", "ALT-h2")
    resp = client.get(
        "/api/v1/alerts?host_id=host-1", headers={"Authorization": f"Bearer {analyst_token}"}
    )
    ids = [row["alert_id"] for row in resp.json()["alerts"]]
    assert ids == ["ALT-h1"]
