import json
import subprocess
from pathlib import Path

import pytest
from panopticon_detection.ingestion.endpoint_adapter import EndpointIngestionAdapter

from manager import db
from manager.config import _DEFAULT_RULES_DIR
from manager.detection.factory import build_detection_run
from manager.detection.response import authorize_response_action
from tests.conftest import enroll_test_agent
from tests.test_endpoint_records import records


@pytest.mark.parametrize("host_rebound", [False, True])
def test_real_canonical_detection_stages_boot_bound_analyst_response(
    client, tmp_path, host_rebound
):
    assert enroll_test_agent(client, "agent-1", "host-1").status_code == 200
    raw = records()[0]
    raw["data"]["process"].update(
        name="reg.exe", command_line=r"reg.exe save hklm\sam C:\temp\sam.hiv"
    )
    conn = db.connect()
    run, sink, writer, _ = build_detection_run(
        conn, alerts_path=tmp_path / "canonical-response.ndjson", rules_dir=_DEFAULT_RULES_DIR
    )
    try:
        sink.agent_id = "agent-1"
        run.process_event(EndpointIngestionAdapter.transform(raw))
        conn.commit()
    finally:
        writer.close()
    row = conn.execute(
        "SELECT r.* FROM response_actions r JOIN alerts a ON a.alert_id=r.alert_id "
        "WHERE a.rule_id='DET-CRED-001'"
    ).fetchone()
    assert row is not None
    assert row["lifecycle_state"] == "PENDING"
    assert row["tier"] == "ANALYST_APPROVAL"
    target = json.loads(row["target_json"])
    assert target == {
        "pid": raw["subject"]["observed_pid"],
        "start_time_ticks": raw["subject"]["native_creation_ticks"],
        "boot_id": raw["subject"]["boot_id"],
    }
    assert conn.execute("SELECT COUNT(*) FROM commands").fetchone()[0] == 0
    if host_rebound:
        conn.execute(
            "UPDATE enrolled_agents SET host_id='replacement-host' WHERE agent_id='agent-1'"
        )
    authorize_response_action(conn, row["response_id"], "test:analyst")
    conn.commit()
    if host_rebound:
        assert conn.execute("SELECT COUNT(*) FROM commands").fetchone()[0] == 0
        assert (
            conn.execute(
                "SELECT lifecycle_state FROM response_actions WHERE response_id=?",
                (row["response_id"],),
            ).fetchone()[0]
            == "REJECTED"
        )
        return
    wire = json.loads(conn.execute("SELECT command_json FROM commands").fetchone()[0])
    assert wire["schema_version"] == "2" and wire["target"] == target
    decoder = (
        Path(__file__).resolve().parents[2]
        / "panopticon-agent/build-verify-x64/officer-response-tests.exe"
    )
    if decoder.is_file():
        result = subprocess.run(
            [str(decoder), "--decode-command-stdin"],
            input=json.dumps(wire),
            text=True,
            capture_output=True,
            timeout=10,
            check=True,
        )
        assert json.loads(result.stdout) == {"schema_version": "2", **target}
