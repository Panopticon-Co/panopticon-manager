from pathlib import Path

import pytest
from fastapi.testclient import TestClient


@pytest.fixture()
def client(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> TestClient:
    monkeypatch.setenv("PANOPTICON_DB_PATH", str(tmp_path / "panopticon.db"))
    # Reimport fresh so module-level state (db._db_path, thread-local conn) doesn't
    # leak between tests.
    import importlib

    import manager.app as app_module
    import manager.db as db_module
    import manager.migrations as migrations_module
    import manager.routers.health as health_module

    for mod in (health_module, migrations_module, db_module, app_module):
        importlib.reload(mod)

    with TestClient(app_module.app) as c:
        yield c


def test_healthz_ok(client: TestClient) -> None:
    resp = client.get("/healthz")
    assert resp.status_code == 200
    assert resp.json()["status"] == "ok"


def test_readyz_ok_after_startup(client: TestClient) -> None:
    resp = client.get("/readyz")
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "ready"
    assert body["schema_version"] == 1


def test_metrics_is_prometheus_text(client: TestClient) -> None:
    resp = client.get("/metrics")
    assert resp.status_code == 200
    assert "panopticon_uptime_seconds" in resp.text
