"""Capstone end to end: engine corpus scenarios through the real manager.

Real app (TestClient: enrollment, ingest, analyst API, command queue) plus the
real detection worker's own steps (``DetectionWorker.run_once`` with the
production rule set), driven synchronously so the test is deterministic. The
app's background worker thread is not started -- the test *is* that thread --
which keeps ADR 003's single detection thread intact.

Scenarios come from the engine's replay corpus
(vendor/eyedetect/tests/corpus): schema-0.3 agent telemetry, accepted by the
wire schema unchanged.

None of the corpus events carries ``process.start_time_ticks`` (it is null),
so every TERMINATE_PROCESS recommendation must fail closed. The KILL_PROCESS
approval path is then exercised by replaying the same scenarios the way the
live agent reports a process creation: an ETW Kernel-Process twin (no command
line, ``start_time_ticks`` = the creation time as a FILETIME, its own
event id) just before each Sysmon process start. ``_with_etw_twins`` copies
the engine's ``scripts/eval_demo_suite.py`` ``wire_lines(..., etw_twins=True)``;
the manager and engine only pass the ticks through.
"""

from __future__ import annotations

import copy
import hashlib
import importlib
import json
from datetime import datetime, timezone
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from manager.config import _DEFAULT_RULES_DIR
from tests.conftest import enroll_test_agent

_CORPUS = Path(__file__).resolve().parents[1] / "vendor" / "eyedetect" / "tests" / "corpus"
_OFFICE = "office_macro_to_c2_and_persistence"
_DOWNLOAD = "download_execute_lsass_dump"
_BENIGN = "benign_workstation"

_TABLES = (
    "events",
    "alerts",
    "incidents",
    "incident_alerts",
    "incident_audit",
    "response_actions",
    "commands",
    "command_audit",
)


def _lines(scenario: str) -> list[str]:
    text = (_CORPUS / scenario / "events.ndjson").read_text(encoding="utf-8")
    return [ln for ln in text.splitlines() if ln.strip() and not ln.lstrip().startswith("#")]


def _host_of(scenario: str) -> str:
    return json.loads(_lines(scenario)[0])["host"]["id"]


_FILETIME_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)


def _filetime(timestamp: str) -> int:
    when = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
    return int((when - _FILETIME_EPOCH).total_seconds() * 10_000_000)


def _with_etw_twins(lines: list[str]) -> list[str]:
    """Each Sysmon process start preceded by its ETW twin, as the agent sends it."""
    out = []
    for line in lines:
        raw = json.loads(line)
        event, process = raw["event"], raw["process"]
        if (
            event["category"] == "process"
            and event["type"] == "start"
            and not process.get("start_time_ticks")
        ):
            twin = copy.deepcopy(raw)
            twin["event"]["id"] = "evt_" + hashlib.sha256(
                ("etw|" + event["id"]).encode()
            ).hexdigest()
            twin["source"] = {
                "kind": "etw",
                "provider": "Microsoft-Windows-Kernel-Process",
                "channel": None,
                "record_id": None,
            }
            twin["process"]["command_line"] = None
            twin["process"]["start_time_ticks"] = _filetime(event["timestamp"])
            out.append(json.dumps(twin))
        out.append(line)
    return out


def _start_ticks(scenario: str, pid: int) -> int:
    for line in _lines(scenario):
        raw = json.loads(line)
        if raw["event"]["category"] == "process" and raw["process"]["pid"] == pid:
            return _filetime(raw["event"]["timestamp"])
    raise AssertionError(f"no process start for pid {pid}")


class _Harness:
    def __init__(self, client: TestClient, tmp_path: Path) -> None:
        from manager.detection.factory import build_detection_run
        from manager.detection.worker import DetectionWorker

        self.client = client
        self.tmp_path = tmp_path
        self.worker = DetectionWorker(
            db_path=tmp_path / "panopticon.db",
            alerts_path=tmp_path / "alerts.ndjson",
            rules_dir=_DEFAULT_RULES_DIR,
        )
        self.conn = self.worker.open_connection()
        self._build = build_detection_run
        self.new_engine()
        self.agent_tokens: dict[str, str] = {}
        analyst = client.post(
            "/api/v1/analysts/enroll",
            json={"analyst_id": "alice"},
            headers={"X-Panopticon-Analyst-Enrollment-Token": "test-analyst-bootstrap-token"},
        )
        assert analyst.status_code == 200
        self.analyst = {"Authorization": f"Bearer {analyst.json()['access_token']}"}

    def new_engine(self) -> None:
        """A fresh DetectionRun, as after a manager restart."""
        if getattr(self, "writer", None) is not None:
            self.writer.close()
        self.run, self.sink, self.writer, self.context = self._build(
            self.conn, alerts_path=self.tmp_path / "alerts.ndjson", rules_dir=_DEFAULT_RULES_DIR
        )

    def close(self) -> None:
        self.writer.close()
        self.conn.close()

    def enroll(self, agent_id: str, host_id: str) -> dict:
        resp = enroll_test_agent(self.client, agent_id, host_id)
        assert resp.status_code == 200, resp.text
        self.agent_tokens[agent_id] = resp.json()["access_token"]
        return self.agent_headers(agent_id)

    def agent_headers(self, agent_id: str) -> dict:
        return {"Authorization": f"Bearer {self.agent_tokens[agent_id]}"}

    def ingest(self, agent_id: str, lines: list[str], batch_id: str) -> dict:
        resp = self.client.post(
            "/api/v1/ingest",
            content=("\n".join(lines) + "\n").encode("utf-8"),
            headers={
                "Content-Type": "application/x-ndjson",
                "X-Panopticon-Batch-Id": batch_id,
                "X-Panopticon-Agent-Id": agent_id,
                "X-Panopticon-Protocol": "1",
                **self.agent_headers(agent_id),
            },
        )
        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert body["rejected"] == [], body["rejected"]
        return body

    def drain(self) -> int:
        total = 0
        while claimed := self.worker.run_once(self.conn, self.run, self.sink):
            total += claimed
        return total

    def counts(self) -> dict[str, int]:
        return {
            t: self.conn.execute(f"SELECT COUNT(*) AS c FROM {t}").fetchone()["c"]
            for t in _TABLES
        }

    def get(self, path: str) -> dict:
        resp = self.client.get(path, headers=self.analyst)
        assert resp.status_code == 200, resp.text
        return resp.json()


@pytest.fixture()
def harness(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("PANOPTICON_DB_PATH", str(tmp_path / "panopticon.db"))
    monkeypatch.setenv("PANOPTICON_ALERTS_PATH", str(tmp_path / "alerts.ndjson"))
    monkeypatch.setenv("PANOPTICON_RULES_DIR", str(_DEFAULT_RULES_DIR))
    monkeypatch.setenv("PANOPTICON_ENROLLMENT_TOKEN", "test-bootstrap-token")
    monkeypatch.setenv("PANOPTICON_COMMAND_TOKEN", "test-command-token")
    monkeypatch.setenv("PANOPTICON_ANALYST_ENROLLMENT_TOKEN", "test-analyst-bootstrap-token")

    import manager.app as app_module
    import manager.db as db_module
    import manager.migrations as migrations_module
    from manager.detection.worker import DetectionWorker

    for mod in (migrations_module, db_module, app_module):
        importlib.reload(mod)
    # The test drives the worker's steps itself; the lifespan thread stays off.
    monkeypatch.setattr(DetectionWorker, "start", lambda self: None)

    with TestClient(app_module.app) as client:
        h = _Harness(client, tmp_path)
        try:
            yield h
        finally:
            h.close()


def _response_rows(h: _Harness, host_id: str) -> list[dict]:
    return [
        dict(r)
        for r in h.conn.execute(
            "SELECT ra.*, a.rule_id, a.host_id FROM response_actions ra "
            "JOIN alerts a ON a.alert_id = ra.alert_id WHERE a.host_id = ? "
            "ORDER BY ra.created_at, ra.rowid",
            (host_id,),
        ).fetchall()
    ]


def _complete(h: _Harness, agent_id: str, command_id: str, result_id: str) -> None:
    headers = h.agent_headers(agent_id)
    polled = h.client.get(f"/api/v1/agents/{agent_id}/commands", headers=headers).json()
    command = next(c for c in polled["commands"] if c["command_id"] == command_id)
    accepted = h.client.post(
        f"/api/v1/agents/{agent_id}/commands/{command_id}/accept", headers=headers
    )
    assert accepted.status_code == 200
    result = h.client.post(
        f"/api/v1/agents/{agent_id}/command-results",
        json={
            "result_id": result_id,
            "command_id": command_id,
            "outcome": "succeeded",
            "detail": "simulated agent result",
            "correlation_id": command["correlation_id"],
        },
        headers=headers,
    )
    assert result.status_code == 200


def test_corpus_attacks_become_incidents_and_replay_adds_nothing(harness: _Harness) -> None:
    h = harness
    office_host, download_host = _host_of(_OFFICE), _host_of(_DOWNLOAD)
    h.enroll("agent-alice", office_host)
    h.enroll("agent-carol", download_host)

    office, download = _lines(_OFFICE), _lines(_DOWNLOAD)
    assert h.ingest("agent-alice", office, "b-office")["accepted"] == len(office)
    assert h.ingest("agent-carol", download, "b-download")["accepted"] == len(download)
    assert h.drain() == len(office) + len(download)

    # -- incidents --------------------------------------------------------
    listed = h.get("/api/v1/incidents")["incidents"]
    by_host = {i["host_id"]: i for i in listed}
    assert set(by_host) == {office_host, download_host}

    office_inc = by_host[office_host]
    assert office_inc["root_process"] == "winword.exe"
    assert office_inc["status"] == "open"
    assert office_inc["revision"] >= 2  # gained Persistence after opening
    assert {"Execution", "Command and Control", "Persistence"} <= set(office_inc["tactics"])

    detail = h.get(f"/api/v1/incidents/{office_inc['incident_id']}")
    evidence = detail["incident"]["evidence"]
    for key in ("stages", "causal_path", "process_lineage", "score_breakdown", "why"):
        assert evidence.get(key), key
    stage_rules = {s["rule_id"] for s in evidence["stages"]}
    assert {"DET-PROC-001", "DET-NET-007", "DET-PERS-001"} <= stage_rules
    members = {a["alert_id"]: a["role"] for a in detail["alerts"]}
    stage_alert_ids = {s["alert_id"] for s in evidence["stages"] if s.get("alert_id")}
    assert stage_alert_ids and all(members[a] == "stage" for a in stage_alert_ids)
    revisions = [a for a, role in members.items() if role == "revision"]
    assert len(revisions) == office_inc["revision"]
    assert all(a.startswith(office_inc["incident_id"] + "-R") for a in revisions)
    assert [a["event"] for a in detail["audit"]][0] == "opened"
    assert "revised" in [a["event"] for a in detail["audit"]]
    assert detail["response_actions"], "member alerts carry the recommendations"

    download_detail = h.get(f"/api/v1/incidents/{by_host[download_host]['incident_id']}")
    assert download_detail["incident"]["root_process"] == "invoice_2026.exe"
    assert download_detail["incident"]["evidence"]["provenance_origin"]

    # The alert API sees the same incident.
    inc_alerts = h.get(f"/api/v1/alerts?incident_id={office_inc['incident_id']}")["alerts"]
    assert {a["alert_id"] for a in inc_alerts} == set(revisions)
    assert all(a["detection_source"] == "correlation" for a in inc_alerts)

    # -- response policy ------------------------------------------------
    for host in (office_host, download_host):
        rows = _response_rows(h, host)
        kills = [r for r in rows if r["action"] == "TERMINATE_PROCESS"]
        assert kills, host
        for row in kills:  # corpus has no start_time_ticks: fail closed
            assert row["lifecycle_state"] == "REJECTED"
            assert row["command_id"] is None
            assert row["decided_reason"].startswith("fail closed")
            assert "target_start_time_ticks" in row["decided_reason"]

    # AUTO_SAFE collection was authorized by the engine and dispatches.
    collect = [
        r for r in _response_rows(h, office_host) if r["action"] == "COLLECT_NETWORK_CONNECTIONS"
    ]
    assert len(collect) == 1
    assert collect[0]["lifecycle_state"] == "AUTHORIZED"
    assert collect[0]["authorized_by"] == "system:response-engine"
    _complete(h, "agent-alice", collect[0]["command_id"], "res-collect-1")
    listed_actions = h.get("/api/v1/response-actions?state=AUTHORIZED")["response_actions"]
    (collect_view,) = [a for a in listed_actions if a["response_id"] == collect[0]["response_id"]]
    assert collect_view["command_lifecycle_state"] == "SUCCEEDED"
    assert [(a["event"], a["actor"]) for a in collect_view["audit"]] == [
        ("created", "system:response-engine"),
        ("dispatched", "agent:agent-alice"),
        ("accepted", "agent:agent-alice"),
        ("result_received", "agent:agent-alice"),
    ]

    status = h.get("/api/v1/status")
    assert status["events"]["done"] == len(office) + len(download)
    assert status["events"]["pending"] == status["events"]["failed"] == 0
    assert status["incidents_open"] == 2
    assert status["agents_enrolled"] == 2

    # -- replay -----------------------------------------------------------
    before = h.counts()
    again = h.ingest("agent-alice", office, "b-office-retry")
    assert (again["accepted"], again["duplicates"]) == (0, len(office))
    h.ingest("agent-carol", download, "b-download-retry")
    assert h.drain() == 0
    assert h.counts() == before

    # Crash-recovery replay: every event re-offered to a freshly built engine.
    h.conn.execute("UPDATE events SET detect_state = 'pending'")
    h.conn.commit()
    h.new_engine()
    assert h.drain() == len(office) + len(download)
    assert h.counts() == before


def test_kill_process_approval_path_without_stacking(harness: _Harness) -> None:
    h = harness
    office_host, download_host = _host_of(_OFFICE), _host_of(_DOWNLOAD)
    h.enroll("agent-alice", office_host)
    carol = h.enroll("agent-carol", download_host)
    h.ingest("agent-alice", _with_etw_twins(_lines(_OFFICE)), "b-office-etw")
    h.ingest("agent-carol", _with_etw_twins(_lines(_DOWNLOAD)), "b-download-etw")
    h.drain()

    # Office chain: several rules and two incident revisions land on the same
    # two processes; each process gets exactly one open KILL_PROCESS.
    office_kills = [r for r in _response_rows(h, office_host) if r["action"] == "KILL_PROCESS"]
    pending = [r for r in office_kills if r["lifecycle_state"] == "PENDING"]
    duplicates = [r for r in office_kills if r["lifecycle_state"] == "REJECTED"]
    targets = [json.loads(r["target_json"]) for r in pending]
    assert len(targets) == len({(t["pid"], t["start_time_ticks"]) for t in targets})
    assert duplicates, "repeat recommendations on one process are recorded as duplicates"
    pending_ids = {r["response_id"] for r in pending}
    for row in duplicates:
        assert row["decided_reason"].removeprefix("duplicate of ") in pending_ids
        assert row["command_id"] is None

    # The incident alert itself recommends killing the incident root once the
    # root's start_time_ticks are known. Its later revision collapses onto the
    # first revision's open action instead of stacking a second request.
    incident_kills = [r for r in office_kills if r["rule_id"] == "PROV-CAMPAIGN"]
    assert len(incident_kills) >= 2
    assert incident_kills[0]["lifecycle_state"] == "PENDING"
    for row in incident_kills[1:]:
        assert row["lifecycle_state"] == "REJECTED"
        assert row["decided_reason"].startswith("duplicate of ")

    # Download chain: the LSASS dump's KILL_PROCESS awaits an analyst, next to
    # the incident's own KILL_PROCESS for the root payload.
    kills_pending = {
        r["rule_id"]: r
        for r in _response_rows(h, download_host)
        if r["action"] == "KILL_PROCESS" and r["lifecycle_state"] == "PENDING"
    }
    assert set(kills_pending) == {"DET-PROC-005", "PROV-CAMPAIGN"}
    root_target = json.loads(kills_pending["PROV-CAMPAIGN"]["target_json"])
    assert root_target["pid"] == 5500  # invoice_2026.exe, the incident root
    kill = kills_pending["DET-PROC-005"]
    assert kill["tier"] == "ANALYST_APPROVAL"
    target = json.loads(kill["target_json"])
    assert target == {"pid": 5600, "start_time_ticks": _start_ticks(_DOWNLOAD, 5600)}

    incident_id = h.get(f"/api/v1/incidents?host_id={download_host}")["incidents"][0][
        "incident_id"
    ]
    in_incident = h.get(f"/api/v1/incidents/{incident_id}")["response_actions"]
    assert kill["response_id"] in {a["response_id"] for a in in_incident}

    ok = h.client.post(
        f"/api/v1/response-actions/{kill['response_id']}/authorize", headers=h.analyst
    )
    assert ok.status_code == 200
    command_id = f"resp-{kill['response_id']}"
    polled = h.client.get("/api/v1/agents/agent-carol/commands", headers=carol).json()["commands"]
    queued = [c for c in polled if c["command_id"] == command_id]
    assert queued and queued[0]["action"] == "KILL_PROCESS"
    assert queued[0]["target"] == target
    # The poll already dispatched it; finish the exchange.
    accepted = h.client.post(
        f"/api/v1/agents/agent-carol/commands/{command_id}/accept", headers=carol
    )
    assert accepted.status_code == 200
    result = h.client.post(
        "/api/v1/agents/agent-carol/command-results",
        json={
            "result_id": "res-kill-1",
            "command_id": command_id,
            "outcome": "succeeded",
            "detail": "simulated agent result",
            "correlation_id": queued[0]["correlation_id"],
        },
        headers=carol,
    )
    assert result.status_code == 200

    alert_view = h.get(f"/api/v1/alerts/{kill['alert_id']}")
    (action,) = [a for a in alert_view["response_actions"] if a["action"] == "KILL_PROCESS"]
    assert action["lifecycle_state"] == "AUTHORIZED"
    assert action["authorized_by"] == "analyst:alice"
    assert action["command_lifecycle_state"] == "SUCCEEDED"
    assert [(a["event"], a["actor"]) for a in action["audit"]] == [
        ("created", "analyst:alice"),
        ("dispatched", "agent:agent-carol"),
        ("accepted", "agent:agent-carol"),
        ("result_received", "agent:agent-carol"),
    ]

    # Re-running the same telemetry stacks nothing.
    before = h.counts()
    h.conn.execute("UPDATE events SET detect_state = 'pending'")
    h.conn.commit()
    h.new_engine()
    h.drain()
    assert h.counts() == before

    # Analyst closes the incident; the status sticks.
    closed = h.client.post(
        f"/api/v1/incidents/{incident_id}/status",
        json={"status": "resolved", "note": "payload killed"},
        headers=h.analyst,
    )
    assert closed.status_code == 200
    assert h.get(f"/api/v1/incidents/{incident_id}")["incident"]["status"] == "resolved"
    assert h.get("/api/v1/status")["incidents_open"] == 1


def test_benign_workstation_produces_no_incident(harness: _Harness) -> None:
    h = harness
    h.enroll("agent-bob", _host_of(_BENIGN))
    lines = _lines(_BENIGN)
    h.ingest("agent-bob", lines, "b-benign")
    assert h.drain() == len(lines)
    assert h.get("/api/v1/incidents")["incidents"] == []
    assert h.get("/api/v1/alerts")["alerts"] == []
    counts = h.counts()
    assert counts["events"] == len(lines)
    assert counts["alerts"] == counts["incidents"] == counts["response_actions"] == 0
