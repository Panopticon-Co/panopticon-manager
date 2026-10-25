"""Seed a running manager with the capstone demo. Starts nothing itself.

Prerequisite: a manager is already running (see docs/DEMO.md, "Capstone demo
(current)"), started with the same bootstrap secrets this script reads:

    PANOPTICON_ENROLLMENT_TOKEN=demo-enroll \\
    PANOPTICON_ANALYST_ENROLLMENT_TOKEN=demo-analyst \\
    PANOPTICON_DB_PATH=demo.db uvicorn manager.app:app --port 8000

then:

    PANOPTICON_ENROLLMENT_TOKEN=demo-enroll \\
    PANOPTICON_ANALYST_ENROLLMENT_TOKEN=demo-analyst \\
    python tools/demo_seed.py --url http://127.0.0.1:8000

What it does, in order -- every step is a plain HTTP call a console or agent
would make:

1. Enrolls analyst ``demo-analyst`` (POST /api/v1/analysts/enroll).
2. For each scenario, enrolls one agent for the scenario's host with a fresh
   ECDSA P-256 key (enrollment-challenge -> signed nonce -> enroll).
3. Replays the engine corpus scenario through tools/fake_agent.py with
   ``--rebase-time --etw-twins`` (timestamps moved to now; each Sysmon process
   start preceded by the ETW twin carrying start_time_ticks, as the live agent
   sends it).
4. Waits for the worker to drain, then prints incidents and pending response
   actions, plus ready-to-paste curl commands and the analyst token.

Re-running against the same database is safe, but ``--rebase-time`` gives the
events new timestamps, not new ids, so a second run ingests nothing new
(duplicates) -- use a fresh PANOPTICON_DB_PATH for a fresh demo. Agent ids
must be unused, so a re-run on the same DB needs ``--suffix``.
"""

from __future__ import annotations

import argparse
import base64
import importlib.util
import json
import os
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
_CORPUS = _ROOT / "vendor" / "eyedetect" / "tests" / "corpus"
DEFAULT_SCENARIOS = (
    "office_macro_to_c2_and_persistence",
    "download_execute_lsass_dump",
    "benign_workstation",
)

_FAKE_AGENT = Path(__file__).with_name("fake_agent.py")
_spec = importlib.util.spec_from_file_location("fake_agent", _FAKE_AGENT)
fake_agent = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(fake_agent)


def _call(url: str, method: str = "GET", body: dict | None = None, headers: dict | None = None):
    data = None if body is None else json.dumps(body).encode("utf-8")
    req = urllib.request.Request(url, data=data, method=method, headers=dict(headers or {}))
    if body is not None:
        req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req) as resp:
            return json.load(resp)
    except urllib.error.HTTPError as exc:
        raise SystemExit(f"{method} {url} -> {exc.code}: {exc.read().decode()}") from exc


def enroll_agent(base: str, agent_id: str, host_id: str, bootstrap: str) -> str:
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec, utils

    nonce_b64 = _call(f"{base}/api/v1/agents/enrollment-challenge", "POST", {})["nonce"]
    key = ec.generate_private_key(ec.SECP256R1())
    numbers = key.public_key().public_numbers()
    public_raw = b"\x04" + numbers.x.to_bytes(32, "big") + numbers.y.to_bytes(32, "big")
    r, s = utils.decode_dss_signature(
        key.sign(base64.b64decode(nonce_b64), ec.ECDSA(hashes.SHA256()))
    )
    signature = r.to_bytes(32, "big") + s.to_bytes(32, "big")
    body = {
        "agent_id": agent_id,
        "host_id": host_id,
        "public_key": base64.b64encode(public_raw).decode("ascii"),
        "nonce": nonce_b64,
        "signature": base64.b64encode(signature).decode("ascii"),
    }
    resp = _call(
        f"{base}/api/v1/agents/enroll",
        "POST",
        body,
        {"X-Panopticon-Enrollment-Token": bootstrap},
    )
    return resp["access_token"]


def _host_of(scenario: str) -> str:
    for line in (_CORPUS / scenario / "events.ndjson").read_text(encoding="utf-8").splitlines():
        if line.strip() and not line.lstrip().startswith("#"):
            return json.loads(line)["host"]["id"]
    raise SystemExit(f"scenario {scenario} has no events")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    ap.add_argument("--url", default="http://127.0.0.1:8000")
    ap.add_argument("--scenario", action="append", help="corpus scenario (repeatable)")
    ap.add_argument("--analyst-id", default="demo-analyst")
    ap.add_argument("--suffix", default="", help="appended to agent ids, for a re-run")
    ap.add_argument("--wait", type=float, default=30.0, help="seconds to wait for detection")
    args = ap.parse_args(argv)
    base = args.url.rstrip("/")
    enroll_secret = os.environ.get("PANOPTICON_ENROLLMENT_TOKEN")
    analyst_secret = os.environ.get("PANOPTICON_ANALYST_ENROLLMENT_TOKEN")
    if not enroll_secret or not analyst_secret:
        print(
            "set PANOPTICON_ENROLLMENT_TOKEN and PANOPTICON_ANALYST_ENROLLMENT_TOKEN to the "
            "values the manager was started with",
            file=sys.stderr,
        )
        return 2

    analyst = _call(
        f"{base}/api/v1/analysts/enroll",
        "POST",
        {"analyst_id": args.analyst_id},
        {"X-Panopticon-Analyst-Enrollment-Token": analyst_secret},
    )["access_token"]
    auth = {"Authorization": f"Bearer {analyst}"}

    for scenario in args.scenario or DEFAULT_SCENARIOS:
        host = _host_of(scenario)
        agent_id = f"demo-{host.lower()}{args.suffix}"
        token = enroll_agent(base, agent_id, host, enroll_secret)
        print(f"[*] {scenario}: agent {agent_id} on {host}")
        code = fake_agent.main(
            [
                "--file", str(_CORPUS / scenario / "events.ndjson"),
                "--url", base,
                "--agent-id", agent_id,
                "--token", token,
                "--rebase-time",
                "--etw-twins",
            ]
        )
        if code != 0:
            return code

    deadline = time.time() + args.wait
    while time.time() < deadline:
        events = _call(f"{base}/api/v1/status", headers=auth)["events"]
        if events["pending"] == 0 and events["claimed"] == 0:
            break
        time.sleep(0.5)
    status = _call(f"{base}/api/v1/status", headers=auth)
    print(f"[+] status: {json.dumps(status)}")
    for inc in _call(f"{base}/api/v1/incidents", headers=auth)["incidents"]:
        print(
            f"    incident {inc['incident_id']} host={inc['host_id']} root={inc['root_process']} "
            f"rev={inc['revision']} tactics={inc['tactics']} status={inc['status']}"
        )
    pending = _call(f"{base}/api/v1/response-actions?state=PENDING", headers=auth)
    for action in pending["response_actions"]:
        print(f"    PENDING {action['response_id']} {action['action']} {action['target']}")

    print("\nAnalyst token (for the console / curl):")
    print(f"  export ANALYST={analyst}")
    print(f'  curl -s -H "Authorization: Bearer $ANALYST" {base}/api/v1/incidents')
    print(f'  curl -s -H "Authorization: Bearer $ANALYST" {base}/api/v1/incidents/<incident_id>')
    print(
        f'  curl -s -X POST -H "Authorization: Bearer $ANALYST" '
        f"{base}/api/v1/response-actions/<response_id>/authorize"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
