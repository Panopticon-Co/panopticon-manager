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

    line = next(
        ln for ln in resp.text.splitlines() if ln.startswith("panopticon_events_pending ")
    )
    assert int(line.split()[1]) >= 0
