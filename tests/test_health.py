from fastapi.testclient import TestClient

from manager import migrations


def test_healthz_ok(client: TestClient) -> None:
    resp = client.get("/healthz")
    assert resp.status_code == 200
    assert resp.json()["status"] == "ok"


def test_readyz_ok_after_startup(client: TestClient) -> None:
    resp = client.get("/readyz")
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "ready"
    assert body["schema_version"] == len(migrations._MIGRATIONS)


def test_metrics_is_prometheus_text(client: TestClient) -> None:
    resp = client.get("/metrics")
    assert resp.status_code == 200
    assert "panopticon_uptime_seconds" in resp.text


def test_metrics_reports_pending_queue_depth(client: TestClient) -> None:
    resp = client.get("/metrics")
    assert resp.status_code == 200

    line = next(ln for ln in resp.text.splitlines() if ln.startswith("panopticon_events_pending "))
    assert int(line.split()[1]) >= 0


def _gauge_value(text: str, name: str) -> int:
    line = next(ln for ln in text.splitlines() if ln.startswith(f"{name} "))
    return int(line.split()[1])


def test_metrics_reports_permanently_failed_events(client: TestClient) -> None:
    # Regression: a poisoned event (ADR 003 -- one rule raising marks that
    # single event detect_state='failed' and it is never retried) used to be
    # invisible in /metrics, so an accumulating backlog of silently-dead
    # events had no operational signal. Insert one directly, exactly as the
    # detection worker would leave it after _mark_failed.
    from manager import db

    baseline = _gauge_value(client.get("/metrics").text, "panopticon_events_failed")

    conn = db.connect()
    conn.execute(
        "INSERT INTO events (event_id, agent_id, host_id, category, event_timestamp, "
        "ingested_at, schema_version, raw_json, detect_state, detect_attempts) "
        "VALUES ('evt-poisoned-1', 'agent-1', 'host-1', 'process', "
        "'2026-01-01T00:00:00.000Z', '2026-01-01T00:00:00.000Z', '0.3', '{}', 'failed', 1)"
    )
    conn.commit()

    resp = client.get("/metrics")
    assert resp.status_code == 200
    assert _gauge_value(resp.text, "panopticon_events_failed") == baseline + 1
