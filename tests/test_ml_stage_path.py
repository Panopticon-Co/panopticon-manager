"""The engine's optional ML stage through the manager: canonical records ->
worker -> alerts, with a model configured by environment (engine docs/adr/001-003).

Uses the engine's hand-built fixture bundle (every start with a command line
scores at the ``high`` band), so this pins plumbing and policy, not model
quality: ML findings are stored and queryable as ``source=ml``, carry no
recommendation and stage no response action, rule alerts are unchanged apart
from the ``ml`` annotation, and a broken model leaves rule detection running.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

from manager import db
from tests.test_endpoint_records import headers, post, records
from tests.test_real_ingest_detection_reachability import real_rules_client  # noqa: F401
from tests.test_live_demo_path import TRIGGERS, _process_start, _wait_until_detected
from tests.test_response_actions_route import _enroll_analyst

_FIXTURE = Path(__file__).resolve().parent.parent / "vendor/eyedetect/tests/ml/bundle_fixture.py"


def _make_bundle(root: Path) -> Path:
    spec = importlib.util.spec_from_file_location("eyedetect_bundle_fixture", _FIXTURE)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.make_bundle(root, 5.0)  # fixture thresholds: alert 1.0, high 2.0


def _client(request, monkeypatch, model_path: str):
    monkeypatch.setenv("PANOPTICON_MODEL_PATH", model_path)
    monkeypatch.setenv("PANOPTICON_ML_MODE", "active")
    return request.getfixturevalue("real_rules_client")


def _run_triggers(client):
    base = records()[0]
    triggers = {
        name: _process_start(base, f"ml-{name}", 7000 + i, name, cmd)
        for i, (name, (cmd, _rule)) in enumerate(TRIGGERS.items())
    }
    body = post(client, headers(client), list(triggers.values())).json()
    assert body["accepted"] == len(triggers), body
    _wait_until_detected(len(triggers))
    analyst = {"Authorization": "Bearer " + _enroll_analyst(client, "ml-analyst")}
    return triggers, analyst


@pytest.mark.skipif(not _FIXTURE.is_file(), reason="vendored engine has no ML stage")
def test_ml_findings_are_stored_queryable_and_never_staged(request, monkeypatch, tmp_path):
    client = _client(request, monkeypatch, str(_make_bundle(tmp_path / "bundle")))
    triggers, analyst = _run_triggers(client)

    rows = client.get("/api/v1/alerts", headers=analyst, params={"source": "ml"})
    assert rows.status_code == 200
    ml = rows.json()["alerts"]
    assert {r["event_id"] for r in ml} == {t["record_id"] for t in triggers.values()}
    for row in ml:
        alert = row["alert"]
        assert row["detection_source"] == "ml" and row["rule_id"] == "ML-PROC-002"
        assert alert["active_response"] is None and row["mitre_tactic"] is None
        assert alert["ml"]["band"] == "high" and alert["ml"]["artifact_sha256"]

    every = client.get("/api/v1/alerts", headers=analyst).json()["alerts"]
    for name, (_cmd, rule_id) in TRIGGERS.items():
        rule = [r for r in every if r["event_id"] == triggers[name]["record_id"] and r["rule_id"] == rule_id]
        assert rule and rule[0]["alert"]["ml"]["raw_score"] == 5.0   # annotated, still the rule's level
        assert rule[0]["level"] == rule[0]["alert"]["level"]

    ml_ids = [r["alert_id"] for r in ml]
    staged = db.connect().execute(
        f"SELECT COUNT(*) FROM response_actions WHERE alert_id IN ({','.join('?' * len(ml_ids))})", ml_ids
    ).fetchone()[0]
    assert staged == 0

    status = client.get("/api/v1/status", headers=analyst).json()["detection_worker"]
    assert status["ml"]["ml_state"] == "enabled" and status["ml"]["ml_scored"] >= len(triggers)
    metrics = client.get("/metrics").text
    assert 'panopticon_ml_enabled{mode="active"' in metrics and "panopticon_ml_scored" in metrics


@pytest.mark.skipif(not _FIXTURE.is_file(), reason="vendored engine has no ML stage")
def test_a_broken_model_leaves_rule_detection_running(request, monkeypatch, tmp_path):
    client = _client(request, monkeypatch, str(tmp_path / "no-such-bundle"))
    triggers, analyst = _run_triggers(client)
    every = client.get("/api/v1/alerts", headers=analyst).json()["alerts"]
    for name, (_cmd, rule_id) in TRIGGERS.items():
        assert any(r["event_id"] == triggers[name]["record_id"] and r["rule_id"] == rule_id for r in every)
    assert not any(r["detection_source"] == "ml" for r in every)
    status = client.get("/api/v1/status", headers=analyst).json()["detection_worker"]
    assert status["alive"] is True and status["ml"]["ml_state"] == "disabled"
    assert "panopticon_ml_enabled 0" in client.get("/metrics").text
