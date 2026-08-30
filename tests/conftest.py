import importlib
from pathlib import Path

import pytest
from fastapi.testclient import TestClient


@pytest.fixture()
def client(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> TestClient:
    monkeypatch.setenv("PANOPTICON_DB_PATH", str(tmp_path / "panopticon.db"))
    # Reimport fresh so module-level state (db._db_path, thread-local conn) doesn't
    # leak between tests.
    import manager.app as app_module
    import manager.db as db_module
    import manager.migrations as migrations_module
    import manager.routers.health as health_module
    import manager.routers.ingest as ingest_module

    for mod in (health_module, ingest_module, migrations_module, db_module, app_module):
        importlib.reload(mod)

    with TestClient(app_module.app) as c:
        yield c
