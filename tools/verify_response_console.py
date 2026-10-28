"""Real local HTTP Console -> Manager response qualification, with simulated endpoint receipts.

Run with Manager's dependencies and a sibling Console checkout. --serve keeps the
isolated lab open for visual inspection. No real endpoint command is executed.
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import os
import secrets
import socket
import sys
import tempfile
import threading
import time
from pathlib import Path

import httpx
import uvicorn

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--console-dir", type=Path, default=ROOT.parent / "panopticon-console")
    parser.add_argument("--serve", action="store_true")
    args = parser.parse_args()
    lab = Path(tempfile.mkdtemp(prefix="panopticon-response-lab-"))
    bootstrap, analyst_bootstrap = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
    os.environ.update(
        PANOPTICON_DB_PATH=str(lab / "lab.db"),
        PANOPTICON_ALERTS_PATH=str(lab / "alerts.ndjson"),
        PANOPTICON_RULES_DIR=str(ROOT / "tests/fixtures/rules"),
        PANOPTICON_ENROLLMENT_TOKEN=bootstrap,
        PANOPTICON_ANALYST_ENROLLMENT_TOKEN=analyst_bootstrap,
    )
    # Bind Manager tests before vendor_path prepends eyedetect (which also has tests/).
    from tests.conftest import enroll_test_agent  # isort: skip
    from manager import db
    from manager.app import app
    from tests.test_endpoint_records import records
    from tests.test_response_actions_route import _stage_response_action

    spec = importlib.util.spec_from_file_location(
        "response_console_lab", args.console_dir / "app.py"
    )
    console_module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(console_module)
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    manager_url = f"http://127.0.0.1:{sock.getsockname()[1]}"
    server = uvicorn.Server(uvicorn.Config(app, log_level="error", access_log=False))
    manager_thread = threading.Thread(target=server.run, kwargs={"sockets": [sock]}, daemon=True)
    manager_thread.start()
    console = None
    try:
        deadline = time.monotonic() + 20
        while not server.started:
            if not manager_thread.is_alive() or time.monotonic() > deadline:
                raise RuntimeError("Manager did not start")
            time.sleep(0.05)
        with httpx.Client(base_url=manager_url, timeout=10) as manager:
            enrolled = enroll_test_agent(manager, "agent-1", "host-1", token=bootstrap)
            assert enrolled.status_code == 200, enrolled.text
            agent_headers = {"Authorization": "Bearer " + enrolled.json()["access_token"]}
            enrolled = manager.post(
                "/api/v1/analysts/enroll",
                json={"analyst_id": "lab-analyst"},
                headers={"X-Panopticon-Analyst-Enrollment-Token": analyst_bootstrap},
            )
            assert enrolled.status_code == 200, enrolled.text
            analyst_token = enrolled.json()["access_token"]
            _stage_response_action("agent-1", "LAB-RESPONSE-1")
            raw = records()[0]
            context = {"endpoint": raw["endpoint"], "subject": raw["subject"]}
            alert = {
                "alert_id": "LAB-RESPONSE-1",
                "rule_id": "LAB-RESPONSE",
                "title": "Response workflow lab — synthetic evidence",
                "severity": "high",
                "endpoint_context": context,
                "host_id": "host-1",
                "agent_id": "agent-1",
            }
            conn = db.connect()
            conn.execute("UPDATE alerts SET host_id='host-1',alert_json=?", (json.dumps(alert),))
            conn.execute("UPDATE response_actions SET lifecycle_state='REJECTED'")
            conn.commit()
            console = console_module.build_server(None, "127.0.0.1", 0, manager_url, analyst_token)
            threading.Thread(target=console.serve_forever, daemon=True).start()
            console_url = f"http://127.0.0.1:{console.server_address[1]}"
            with httpx.Client(base_url=console_url, timeout=10) as browser:
                catalog = browser.get("/api/response-actions/catalog")
                assert len(catalog.json()["actions"]) == 7
                for action in ("ISOLATE_HOST", "KILL_PROCESS"):
                    created = browser.post(
                        "/api/response-actions",
                        json={
                            "alert_id": "LAB-RESPONSE-1",
                            "action": action,
                            "reason": "Synthetic lab qualification; no OS execution",
                            "target": {},
                        },
                    )
                    assert created.status_code == 201, created.text
                    rid = created.json()["response_id"]
                    assert browser.post(f"/api/response-actions/{rid}/authorize").json()[
                        "authorized"
                    ]
                    if action == "ISOLATE_HOST":
                        cancelled = browser.post(
                            f"/api/response-actions/{rid}/cancel",
                            json={"reason": "Cancel before endpoint delivery"},
                        )
                        assert cancelled.status_code == 200
                        assert (
                            manager.get(
                                "/api/v1/agents/agent-1/commands", headers=agent_headers
                            ).json()["commands"]
                            == []
                        )
                        continue
                    command = manager.get(
                        "/api/v1/agents/agent-1/commands", headers=agent_headers
                    ).json()["commands"][0]
                    receipt = {
                        "schema_version": "2",
                        "result_id": "lab-receipt",
                        "command_id": command["command_id"],
                        "correlation_id": command["correlation_id"],
                        "outcome": "indeterminate",
                        "detail": "Simulated receipt for UI qualification; no OS execution",
                        "execution": {
                            "representation": "windows_process_termination_v1",
                            "stage": "completion",
                            "action_initiated": True,
                            "completion_observed": False,
                            "native_error": 5,
                        },
                    }
                    assert (
                        manager.post(
                            "/api/v1/agents/agent-1/command-results",
                            json=receipt,
                            headers=agent_headers,
                        ).status_code
                        == 200
                    )
                response = browser.get("/api/response-actions?state=AUTHORIZED")
                rows = response.json()["response_actions"]
                assert {r["command_lifecycle_state"] for r in rows} == {
                    "CANCELLED",
                    "INDETERMINATE",
                }
                assert any(r["receipts"] for r in rows)
                assert analyst_token not in response.text
                assert browser.get("/").status_code == 200
            print(
                "PASS: real HTTP Console -> Manager "
                "catalog/create/approve/cancel/poll/result/evidence",
                flush=True,
            )
            print("Endpoint receipt is simulated; no native action was executed.", flush=True)
            if args.serve:
                print("CONSOLE_URL=" + console_url, flush=True)
                threading.Event().wait()
    finally:
        if console:
            console.shutdown()
            console.server_close()
        server.should_exit = True
        manager_thread.join(timeout=10)
        sock.close()


if __name__ == "__main__":
    main()
