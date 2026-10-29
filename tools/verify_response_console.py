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


def load_console(console_dir):
    """Load the sibling application with the same module path as its CLI entrypoint."""
    spec = importlib.util.spec_from_file_location("response_console_lab", console_dir / "app.py")
    console_module = importlib.util.module_from_spec(spec)
    original_path = sys.path[:]
    sys.path.insert(0, str(console_dir.resolve()))
    try:
        spec.loader.exec_module(console_module)
    finally:
        sys.path[:] = original_path
    return console_module


def verify_governance(manager, browser, console_module, manager_url, bootstrap, case_id):
    """Exercise policy and evidence through real HTTP without native execution."""
    assert browser.get("/api/analysts/me").json()["role"] == "analyst"
    request = {
        "alert_id": "LAB-RESPONSE-1",
        "action": "COLLECT_NETWORK_CONNECTIONS",
        "reason": "Retry-safe governance qualification",
        "request_id": "lab-retry-1",
    }
    first = browser.post("/api/response-actions", json=request)
    assert first.status_code == 201, first.text
    rid = first.json()["response_id"]
    replay = browser.post("/api/response-actions", json=request)
    assert replay.json()["response_id"] == rid and replay.json()["replayed"]
    assert (
        browser.post(
            "/api/response-actions", json={**request, "reason": "Different intent"}
        ).status_code
        == 409
    )
    os.environ["PANOPTICON_REQUIRE_SEPARATE_APPROVER"] = "true"
    try:
        assert browser.post(f"/api/response-actions/{rid}/authorize").status_code == 403
        approver = manager.post(
            "/api/v1/analysts/enroll",
            json={"analyst_id": "lab-approver", "role": "approver"},
            headers={"X-Panopticon-Analyst-Enrollment-Token": bootstrap},
        )
        assert approver.status_code == 200
        assert manager.post(
            f"/api/v1/response-actions/{rid}/authorize",
            headers={"Authorization": "Bearer " + approver.json()["access_token"]},
        ).json()["authorized"]
    finally:
        os.environ["PANOPTICON_REQUIRE_SEPARATE_APPROVER"] = "false"
    response = browser.get("/api/response-actions?command_state=INDETERMINATE")
    assert len(response.json()["response_actions"]) == 1
    exported = browser.get(f"/api/response-actions/{case_id}/export")
    assert exported.status_code == 200
    assert "attachment" in exported.headers["content-disposition"]
    assert exported.json()["originating_alert"]["alert_id"] == "LAB-RESPONSE-1"
    assert exported.json()["response_action"]["decision_audit"]
    viewer = manager.post(
        "/api/v1/analysts/enroll",
        json={"analyst_id": "lab-viewer", "role": "viewer"},
        headers={"X-Panopticon-Analyst-Enrollment-Token": bootstrap},
    )
    assert viewer.status_code == 200
    token = viewer.json()["access_token"]
    viewer_console = console_module.build_server(None, "127.0.0.1", 0, manager_url, token)
    thread = threading.Thread(target=viewer_console.serve_forever, daemon=True)
    thread.start()
    try:
        with httpx.Client(
            base_url=f"http://127.0.0.1:{viewer_console.server_address[1]}"
        ) as reader:
            assert (
                reader.get("/api/response-actions/catalog").json()["analyst"]["permissions"] == []
            )
            assert reader.post("/api/response-actions", json=request).status_code == 403
            result = reader.get(f"/api/response-actions/{case_id}/export")
            assert result.status_code == 200 and token not in result.text
    finally:
        viewer_console.shutdown()
        viewer_console.server_close()
        thread.join(timeout=5)
    print(
        "PASS: HTTP roles/separate-approval/retry-conflicts/outcome-filter/decision-export",
        flush=True,
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--console-dir", type=Path, default=ROOT.parent / "panopticon-console")
    parser.add_argument("--serve", action="store_true")
    parser.add_argument("--governance", action="store_true")
    parser.add_argument("--console-port", type=int, default=0)
    parser.add_argument(
        "--preview-only",
        action="store_true",
        help="Serve synthetic Console data without workflow qualification",
    )
    args = parser.parse_args()
    lab = Path(tempfile.mkdtemp(prefix="panopticon-response-lab-"))
    bootstrap, analyst_bootstrap = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
    os.environ.update(
        PANOPTICON_DB_PATH=str(lab / "lab.db"),
        PANOPTICON_ALERTS_PATH=str(lab / "alerts.ndjson"),
        PANOPTICON_RULES_DIR=str(ROOT / "tests/fixtures/rules"),
        PANOPTICON_ENROLLMENT_TOKEN=bootstrap,
        PANOPTICON_ANALYST_ENROLLMENT_TOKEN=analyst_bootstrap,
        PANOPTICON_REQUIRE_SEPARATE_APPROVER="false",
    )
    # Bind Manager tests before vendor_path prepends eyedetect (which also has tests/).
    from tests.conftest import enroll_test_agent  # isort: skip
    from manager import db
    from manager.app import app
    from tests.test_endpoint_records import records
    from tests.test_response_actions_route import _stage_response_action

    console_module = load_console(args.console_dir)
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
            console = console_module.build_server(
                None, "127.0.0.1", args.console_port, manager_url, analyst_token
            )
            threading.Thread(target=console.serve_forever, daemon=True).start()
            console_url = f"http://127.0.0.1:{console.server_address[1]}"
            if args.preview_only:
                print("PREVIEW ONLY: synthetic data; no response workflow/E2E run.", flush=True)
                print("CONSOLE_URL=" + console_url, flush=True)
                threading.Event().wait()
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
                if args.governance:
                    verify_governance(
                        manager, browser, console_module, manager_url, analyst_bootstrap, rid
                    )
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
