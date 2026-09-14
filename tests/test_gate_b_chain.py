"""Gate B — the certutil correlated-incident chain, through the wired-up engine.

Two hand-built normalized events (certutil process-create, then that same
process's outbound connection) must produce three alert rows: DET-PROC-003,
DET-NET-006, and the PROV-CAMPAIGN incident joining them through the
provenance graph.
"""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import manager.vendor_path  # noqa: F401
from manager import migrations
from manager.config import _DEFAULT_RULES_DIR
from manager.detection.factory import build_detection_run

_CMD = "certutil -urlcache -split -f http://www.msftconnecttest.com/connecttest.txt out.txt"

_CERTUTIL_PROC = {
    "event_type": "process_create",
    "event_id": "evt_" + "c" * 61 + "001",
    "host_id": "HOST-B",
    "timestamp": "2026-08-31T12:00:00.000Z",
    "process": {
        "name": "certutil.exe",
        "pid": 7777,
        "command_line": _CMD,
        "entity_id": "proc_" + "a" * 64,
        "process_guid": "proc_" + "a" * 64,  # start-event entity id
    },
    "parent": {"name": "cmd.exe", "pid": 1000},
}

_CERTUTIL_NET = {
    "event_type": "network_connect",
    "event_id": "evt_" + "c" * 61 + "002",
    "host_id": "HOST-B",
    "timestamp": "2026-08-31T12:00:03.000Z",
    "process": {
        "name": "certutil.exe",
        "pid": 7777,
        "command_line": _CMD,
        "entity_id": "proc_" + "b" * 64,  # DIFFERENT context entity id, same pid
        "process_guid": "proc_" + "b" * 64,
    },
    "parent": {"name": "cmd.exe", "pid": 1000},
    "network": {
        "direction": "outbound",
        "protocol": "tcp",
        "destination_ip": "93.184.216.34",
        "destination_port": 80,
    },
}


def _db(path: Path) -> sqlite3.Connection:
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    migrations.migrate(conn)
    return conn


def test_certutil_chain_produces_three_alerts(tmp_path: Path) -> None:
    conn = _db(tmp_path / "p.db")
    run, sink, writer, _context = build_detection_run(
        conn, alerts_path=tmp_path / "alerts.ndjson", rules_dir=_DEFAULT_RULES_DIR
    )
    try:
        sink.agent_id = "officer-agent-b"
        run.process_event(dict(_CERTUTIL_PROC))
        run.process_event(dict(_CERTUTIL_NET))
        conn.commit()
    finally:
        writer.close()

    rule_ids = {r["rule_id"] for r in conn.execute("SELECT rule_id FROM alerts")}
    assert {"DET-PROC-003", "DET-NET-006", "PROV-CAMPAIGN"} <= rule_ids

    corr = conn.execute("SELECT * FROM alerts WHERE rule_id = 'PROV-CAMPAIGN'").fetchone()
    assert corr["host_id"] == "HOST-B"

    # CORR-003 hardcoded mitre_technique T1105 on the correlation rule itself.
    # A campaign is no longer a named rule with its own fixed mapping -- it is
    # a traversal result, so it reports the technique of the detection that
    # anchored the search (DET-NET-006, T1071). The full set of techniques the
    # chain covers is in the evidence rather than flattened into one field.
    assert corr["mitre_technique"] == "T1071"
    evidence = json.loads(corr["alert_json"])["evidence"]
    assert evidence["tactics_covered"] == ["Command and Control"]
    assert "DET-PROC-003" in evidence["attack_chain"]
    assert "DET-NET-006" in evidence["attack_chain"]
