"""tools/fake_agent.py — the offline replay tool / viva fallback.

The replay test routes fake_agent's urllib POSTs through an in-process
TestClient (full rule set, tmp paths) so the whole pipeline runs: ingest ->
events table -> detection worker -> alerts.ndjson.
"""

from __future__ import annotations

import importlib
import importlib.util
import io
import json
import os
import time
import urllib.request
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

_TOOLS = Path(__file__).resolve().parent.parent / "tools"
_RULES = Path(__file__).resolve().parent.parent / "vendor" / "eyedetect" / "rules"

_spec = importlib.util.spec_from_file_location("fake_agent", _TOOLS / "fake_agent.py")
fake_agent = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(fake_agent)


def test_demo_events_file_covers_gate_a_and_b() -> None:
    lines = [
        ln
        for ln in (_TOOLS / "demo_events.ndjson").read_text().splitlines()
        if ln.strip() and not ln.startswith("#")
    ]
    events = [json.loads(ln) for ln in lines]
    assert {"whoami.exe", "certutil.exe"} <= {e["process"]["name"] for e in events}
    certutil = [e for e in events if e["process"]["name"] == "certutil.exe"]
    assert len({e["process"]["pid"] for e in certutil}) == 1  # one process, two families
    assert {e["event"]["category"] for e in certutil} == {"process", "network"}


class _Resp(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()


def test_replay_produces_gate_a_and_b_alerts(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("PANOPTICON_DB_PATH", str(tmp_path / "p.db"))
    monkeypatch.setenv("PANOPTICON_ALERTS_PATH", str(tmp_path / "alerts.ndjson"))
    monkeypatch.setenv("PANOPTICON_RULES_DIR", str(_RULES))

    import manager.app as app_module
    import manager.db as db_module
    import manager.migrations as migrations_module
    import manager.routers.health as health_module
    import manager.routers.ingest as ingest_module

    for mod in (health_module, ingest_module, migrations_module, db_module, app_module):
        importlib.reload(mod)

    with TestClient(app_module.app) as client:

        def fake_urlopen(req, *a, **kw):
            resp = client.post(
                "/api/v1/ingest",
                content=req.data,
                headers={k: v for k, v in req.header_items()},
            )
            resp.raise_for_status()
            return _Resp(resp.content)

        monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)

        assert fake_agent.main(["--file", str(_TOOLS / "demo_events.ndjson")]) == 0

        alerts_path = Path(os.environ["PANOPTICON_ALERTS_PATH"])
        got: set[str] = set()
        for _ in range(100):
            if alerts_path.exists():
                got = {
                    json.loads(ln)["rule_id"]
                    for ln in alerts_path.read_text().splitlines()
                    if ln.strip()
                }
            if {"DET-PROC-008", "DET-PROC-003", "DET-NET-006", "PROV-CAMPAIGN"} <= got:
                break
            time.sleep(0.1)

    assert {"DET-PROC-008", "DET-PROC-003", "DET-NET-006", "PROV-CAMPAIGN"} <= got


def test_rebase_time_moves_newest_event_to_now_and_keeps_gaps() -> None:
    from datetime import datetime, timezone

    lines = [
        ln
        for ln in (_TOOLS / "demo_events.ndjson").read_text().splitlines()
        if ln.strip() and not ln.startswith("#")
    ]
    now = datetime(2026, 10, 25, 9, 30, 0, 123456, tzinfo=timezone.utc)
    prepared = fake_agent.prepare(lines, rebase=True, twins=False, now=now)
    rebased = [json.loads(ln) for ln in prepared]
    original = [json.loads(ln) for ln in lines]
    stamps = [fake_agent._parse_ts(e["event"]["timestamp"]) for e in rebased]
    assert max(stamps) == now.replace(microsecond=123000)
    before = [fake_agent._parse_ts(e["event"]["timestamp"]) for e in original]
    assert [b - before[0] for b in before] == [s - stamps[0] for s in stamps]
    # Nothing but the timestamp changes.
    for old, new in zip(original, rebased):
        old["event"].pop("timestamp")
        new["event"].pop("timestamp")
        assert old == new


def test_etw_twins_carry_filetime_ticks_and_are_wire_valid() -> None:
    from manager.wire.telemetry import TelemetryEvent

    corpus = _TOOLS.parent / "vendor" / "eyedetect" / "tests" / "corpus"
    text = (corpus / "download_execute_lsass_dump" / "events.ndjson").read_text()
    lines = [ln for ln in text.splitlines() if ln.strip() and not ln.startswith("#")]
    out = [json.loads(ln) for ln in fake_agent.prepare(lines, rebase=True, twins=True)]
    starts = [e for e in out if e["event"]["category"] == "process"]
    twins = [e for e in starts if e["source"]["kind"] == "etw"]
    assert len(twins) * 2 == len(starts)  # one twin per Sysmon start
    for twin in twins:
        TelemetryEvent.model_validate(twin)
        assert twin["process"]["command_line"] is None
        assert twin["process"]["start_time_ticks"] == fake_agent.filetime(
            twin["event"]["timestamp"]
        )
        sysmon = out[out.index(twin) + 1]  # the twin comes first, as the agent sends it
        assert sysmon["process"]["pid"] == twin["process"]["pid"]
        assert sysmon["event"]["timestamp"] == twin["event"]["timestamp"]
        assert sysmon["event"]["id"] != twin["event"]["id"]
    # 1601-01-01 is tick zero; one second is 10^7 ticks.
    assert fake_agent.filetime("1601-01-01T00:00:01.000Z") == 10_000_000
