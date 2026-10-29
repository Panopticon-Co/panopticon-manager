"""Focused Console HTTP -> real Manager ASGI artifact authorization qualification.

No native execution or full-system E2E: the retained signed fixture exercises
actual Manager routes behind the Console's bounded upstream transport seam.
"""

import base64
import http.client
import importlib.util
import json
import sys
import threading
from pathlib import Path

from manager import audit_chain, db
from tests.artifact_access_support import grant_reader
from tests.test_response_governance import identity
from tests.test_signed_artifacts import prepared


def load(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_individual_browser_scope_signed_frames_and_view_reach_real_manager(client, monkeypatch):
    operator, agent, _, upload, url = prepared(client, with_scope=False)
    assert client.post(url, headers=agent, json=upload).status_code == 200
    root = Path(__file__).resolve().parents[2] / "panopticon-console"
    sessions = load(root / "evidence_sessions.py", "console_evidence_session_test")
    monkeypatch.setitem(sys.modules, "evidence_sessions", sessions)
    console = load(root / "app.py", "console_artifact_http_test")
    upstream_calls = []

    def upstream(manager_url, token, path, payload=None, **_):
        upstream_calls.append((token, path))
        headers = {"Authorization": "Bearer " + token, "Content-Type": "application/json"}
        result = (
            client.get(path, headers=headers)
            if payload is None
            else client.post(path, headers=headers, content=payload)
        )
        return result.status_code, result.content

    monkeypatch.setattr(sessions, "exchange", upstream)
    monkeypatch.delenv("PANOPTICON_CONSOLE_PUBLIC_ORIGIN", raising=False)
    shared_headers = identity(client, "shared-console", "analyst")
    grant_reader(client, shared_headers, request_id="shared-explicit-scope")
    shared = shared_headers["Authorization"].removeprefix("Bearer ")
    monkeypatch.setattr(console, "manager_get", upstream)
    server = console.build_server(None, "127.0.0.1", 0, "http://127.0.0.1:1", shared)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    origin = "http://127.0.0.1:" + str(server.server_address[1])

    def request(path, *, body=None, cookie=None, version=None):
        headers = {"Origin": origin, "Content-Type": "application/json"}
        if cookie:
            headers["Cookie"] = cookie
        if version:
            headers["X-Panopticon-Evidence-Identity"] = version
        connection = http.client.HTTPConnection("127.0.0.1", server.server_address[1], timeout=5)
        try:
            connection.request(
                "GET" if body is None else "POST",
                path,
                json.dumps(body).encode() if body is not None else None,
                headers,
            )
            response = connection.getresponse()
            return response.status, dict(response.getheaders()), json.loads(response.read())
        finally:
            connection.close()

    try:
        status, _, shared_queue = request("/api/response-actions")
        assert status == 200
        assert all(not row["artifacts"] for row in shared_queue["response_actions"])
        upstream_calls.clear()
        token = operator["Authorization"].removeprefix("Bearer ")
        status, headers, signed_in = request("/api/evidence/session", body={"access_token": token})
        assert status == 200 and signed_in["analyst_id"] == "operator"
        assert token not in json.dumps(signed_in)
        browser = {
            "cookie": headers["Set-Cookie"].split(";")[0],
            "version": signed_in["identity_version"],
        }
        artifact = "/api/evidence/artifacts/" + upload["manifest"]["artifact_id"]
        assert request(artifact + "/context", **browser)[0] == 403
        grant_reader(client, operator)
        status, _, context = request(artifact + "/context", **browser)
        assert status == 200
        rid = context["trusted"]["response_id"]
        status, _, case = request("/api/evidence/cases/" + rid, **browser)
        assert status == 200 and len(case["response_action"]["artifacts"]) == 1
        status, _, chunk = request(
            artifact + "/chunks?offset=0&manifest_sha256=" + context["manifest_sha256"], **browser
        )
        assert status == 200
        assert base64.b64decode(chunk["content_base64"]) == base64.b64decode(
            upload["content_base64"]
        )
        status, _, receipt = request(
            artifact + "/view",
            body={
                "schema_version": "1",
                "request_id": "browser-view-1",
                "manifest_sha256": context["manifest_sha256"],
                "operation": "view",
            },
            **browser,
        )
        assert status == 200 and receipt["recorded"]
        assert request("/api/evidence/session/logout", body={}, **browser)[0] == 200
        assert request(artifact + "/context", **browser)[0] == 401
        assert all(caller == token for caller, _ in upstream_calls)
        assert audit_chain.verify(db.connect())["complete_history_verified"]
    finally:
        server.shutdown()
        thread.join(5)
        server.server_close()
