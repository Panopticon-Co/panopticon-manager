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


def test_readyz_fails_when_the_detection_worker_is_dead(client: TestClient) -> None:
    # Ingest can stay green while nothing is detected; readiness must not.
    worker = client.app.state.detection_worker
    assert client.get("/readyz").status_code == 200
    assert _gauge_value(client.get("/metrics").text, "panopticon_detection_worker_up") == 1

    worker.fatal_error = "RuleValidationError: simulated"
    resp = client.get("/readyz")
    assert resp.status_code == 503
    body = resp.json()
    assert body["status"] == "not_ready"
    assert body["reason"] == "detection worker not alive"
    assert body["fatal_error"] == "RuleValidationError: simulated"
    assert _gauge_value(client.get("/metrics").text, "panopticon_detection_worker_up") == 0


def test_status_reports_canonical_queue_and_worker(client: TestClient) -> None:
    from manager import db
    from tests.test_response_actions_route import _enroll_analyst

    h = {"Authorization": "Bearer " + _enroll_analyst(client, "alice")}
    conn = db.connect()
    for record_id, state in (("rec_" + "1" * 64, "done"), ("rec_" + "2" * 64, "pending")):
        conn.execute(
            "INSERT INTO endpoint_records (agent_id, host_id, record_id, kind, category, "
            "observed_at, ingested_at, payload_digest, raw_json, detect_state) "
            "VALUES ('agent-1','host-1',?,'observation','process',"
            "'2026-10-30T10:00:00.000Z','2026-10-30T10:00:01.000Z','d','{}',?)",
            (record_id, state),
        )
    conn.commit()

    body = client.get("/api/v1/status", headers=h).json()
    assert body["endpoint_records"] == {"pending": 1, "claimed": 0, "done": 1, "failed": 0}
    assert body["last_record_at"] == "2026-10-30T10:00:01.000Z"
    assert body["detection_worker"]["alive"] is True
    assert body["detection_worker"]["fatal_error"] is None
    assert body["detection_worker"]["loop_errors"] == 0
