import importlib
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

# A one-rule directory so the per-test detection worker builds fast. Tests that
# need the full pinned rule set point PANOPTICON_RULES_DIR at vendor/eyedetect/rules
# themselves (see test_detection_factory.py).
FIXTURE_RULES_DIR = Path(__file__).resolve().parent / "fixtures" / "rules"


@pytest.fixture()
def client(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> TestClient:
    monkeypatch.setenv("PANOPTICON_DB_PATH", str(tmp_path / "panopticon.db"))
    monkeypatch.setenv("PANOPTICON_ALERTS_PATH", str(tmp_path / "alerts.ndjson"))
    monkeypatch.setenv("PANOPTICON_RULES_DIR", str(FIXTURE_RULES_DIR))
    monkeypatch.setenv("PANOPTICON_ENROLLMENT_TOKEN", "test-bootstrap-token")
    # Reimport fresh so module-level state (db._db_path, thread-local conn) doesn't
    # leak between tests.
    import manager.app as app_module
    import manager.db as db_module
    import manager.auth as auth_module
    import manager.routers.enrollment as enrollment_module
    import manager.migrations as migrations_module
    import manager.routers.health as health_module
    import manager.routers.ingest as ingest_module

    for mod in (health_module, ingest_module, enrollment_module, auth_module, migrations_module, db_module, app_module):
        importlib.reload(mod)

    # TestClient's context manager runs the lifespan: migrations + detection worker
    # start on enter, worker stop on exit.
    with TestClient(app_module.app) as c:
        yield c
