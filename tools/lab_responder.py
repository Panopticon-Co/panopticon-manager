"""Lab endpoint emulator for the automated-response demo (Linux).

A real, enrolled Panopticon endpoint whose response scope is exactly the
processes it launched itself. It is the safe containment adapter for the
demo, not a replacement for officer-agent.exe or panopticon-linux-agent:

1. ``launch`` starts a harmless, dedicated payload process it owns::

       bash -c ': panopticon-lab-payload; echo /dev/tcp/198.51.100.7/4444 >/dev/null; ...'

   The command line really contains ``/dev/tcp/`` (production rule
   DET-LNX-001, reverse shell via /dev/tcp) but only *prints* it: no socket is
   opened, and 198.51.100.0/24 is a documentation range (TEST-NET-2).
2. It reports the payload's process start as observed from ``/proc``
   (``source.kind = linux_procfs``): real pid, comm, executable, command line
   and the kernel's start time (``/proc/<pid>/stat`` field 22) as
   ``start_time_ticks``. Nothing about the event is invented.
3. Manager's detection worker raises DET-LNX-001 -> the response policy
   (``contain-reverse-shell``) previews the KILL_PROCESS (simulation adapter)
   and stages it for analyst approval.
4. ``serve`` polls for commands (durable delivery), accepts, executes and
   reports a schema-2 result. KILL_PROCESS is executed only for a pid in this
   process's own launch registry whose start ticks still match (PID-reuse
   guard): SIGTERM, bounded wait, SIGKILL fallback, then *verification* that
   the process is gone. Only then is the result ``succeeded`` with a
   ``verified:`` detail. Every other target or action is refused.

    python tools/lab_responder.py demo --url http://127.0.0.1:8000
    python tools/lab_responder.py demo --url ... --enroll-analyst lab-analyst

Requires PANOPTICON_ENROLLMENT_TOKEN (and PANOPTICON_ANALYST_ENROLLMENT_TOKEN
for ``--enroll-analyst``). Ctrl-C / exit always terminates the payload.
"""

from __future__ import annotations

import argparse
import atexit
import getpass
import hashlib
import json
import os
import platform
import signal
import subprocess
import sys
import time
import urllib.error
import urllib.request
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone

PAYLOAD_MARKER = "panopticon-lab-payload"
# Documentation-only address (RFC 5737); the payload never connects to it.
PAYLOAD_COMMAND = (
    f": {PAYLOAD_MARKER}; echo /dev/tcp/198.51.100.7/4444 >/dev/null; "
    "while :; do sleep 1; done"
)
KILL_TIMEOUT_SECONDS = 5.0
RESULT_RETRIES = 3


def proc_start_ticks(pid: int) -> int | None:
    """``/proc/<pid>/stat`` starttime (clock ticks since boot), or None when no
    such process exists. Together with the pid it names one process instance."""
    try:
        with open(f"/proc/{pid}/stat", encoding="utf-8") as fh:
            stat = fh.read()
    except OSError:
        return None
    fields = stat[stat.rindex(")") + 2 :].split()
    return int(fields[19])


def _read(path: str) -> str | None:
    try:
        with open(path, "rb") as fh:
            return fh.read().decode("utf-8", "replace")
    except OSError:
        return None


@dataclass
class Payload:
    pid: int
    start_ticks: int
    popen: subprocess.Popen


@dataclass
class LabEndpoint:
    agent_id: str
    host_id: str
    payloads: dict[int, Payload] = field(default_factory=dict)
    handled: dict[str, dict] = field(default_factory=dict)

    # --- payload and telemetry -------------------------------------------------

    def launch_payload(self) -> Payload:
        popen = subprocess.Popen(
            ["bash", "-c", PAYLOAD_COMMAND],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        ticks = None
        for _ in range(50):
            ticks = proc_start_ticks(popen.pid)
            cmdline = _read(f"/proc/{popen.pid}/cmdline") or ""
            if ticks and PAYLOAD_MARKER in cmdline:
                break
            time.sleep(0.02)
        if not ticks:
            popen.kill()
            raise RuntimeError("payload did not start")
        payload = Payload(popen.pid, ticks, popen)
        self.payloads[popen.pid] = payload
        return payload

    def observe(self, payload: Payload) -> dict:
        """A schema-0.3 process-start event for the payload, read from /proc."""
        pid = payload.pid
        cmdline = (_read(f"/proc/{pid}/cmdline") or "").replace("\0", " ").strip()
        comm = (_read(f"/proc/{pid}/comm") or "").strip() or None
        try:
            exe = os.readlink(f"/proc/{pid}/exe")
        except OSError:
            exe = None
        ppid = os.getpid()
        identity = f"{self.host_id}|{pid}|{payload.start_ticks}"
        now = datetime.now(timezone.utc)
        return {
            "schema_version": "0.3",
            "event": {
                "id": "evt_" + hashlib.sha256(("start|" + identity).encode()).hexdigest(),
                "category": "process",
                "type": "start",
                "timestamp": now.strftime("%Y-%m-%dT%H:%M:%S.")
                + f"{now.microsecond // 1000:03d}Z",
            },
            "source": {
                "kind": "linux_procfs",
                "provider": "panopticon-lab-endpoint",
                "channel": None,
                "record_id": None,
            },
            "agent": {"id": self.agent_id, "version": "lab-0.1"},
            "host": {
                "id": self.host_id,
                "hostname": self.host_id,
                "os": {"name": "Linux", "build": platform.release() or "unknown"},
            },
            "user": {"name": getpass.getuser(), "domain": None, "sid": None},
            "process": {
                "entity_id": "proc_" + hashlib.sha256(identity.encode()).hexdigest(),
                "pid": pid,
                "name": comm,
                "executable": exe,
                "command_line": cmdline,
                "start_time_ticks": payload.start_ticks,
                "parent": {
                    "entity_id": None,
                    "pid": ppid,
                    "name": (_read(f"/proc/{ppid}/comm") or "").strip() or None,
                },
                "hash": {"sha256": None},
            },
        }

    # --- execution adapter -----------------------------------------------------

    def _owned(self, target: dict) -> tuple[Payload | None, str | None]:
        pid, ticks = target.get("pid"), target.get("start_time_ticks")
        if type(pid) is not int:
            return None, "refused: target pid is not an integer"
        payload = self.payloads.get(pid)
        if payload is None:
            return None, f"refused: pid {pid} was not launched by this lab endpoint"
        if str(ticks) != str(payload.start_ticks):
            return None, f"refused: start_time_ticks {ticks} does not match pid {pid}"
        return payload, None

    def execute(self, command: dict) -> tuple[str, str]:
        """Runs one dispatched command; returns (outcome, detail)."""
        action, target = command.get("action"), command.get("target") or {}
        if action == "KILL_PROCESS":
            payload, refusal = self._owned(target)
            if refusal:
                return "rejected", refusal
            return self._terminate(payload)
        if action == "COLLECT_PROCESS_INFO":
            payload, refusal = self._owned(target)
            if refusal:
                return "rejected", refusal
            if proc_start_ticks(payload.pid) != payload.start_ticks:
                return "failed", f"pid {payload.pid} is no longer running"
            status = (_read(f"/proc/{payload.pid}/status") or "").splitlines()
            state = next((s.split(":", 1)[1].strip() for s in status if s.startswith("State")), "")
            return "succeeded", f"collected: pid {payload.pid} state {state}"
        if action == "COLLECT_NETWORK_CONNECTIONS":
            count = sum(
                max(0, len((_read(path) or "").splitlines()) - 1)
                for path in ("/proc/net/tcp", "/proc/net/tcp6")
            )
            return "succeeded", f"collected: {count} TCP socket entries"
        return "rejected", f"refused: {action} is outside the lab endpoint's scope"

    def _terminate(self, payload: Payload) -> tuple[str, str]:
        pid, ticks = payload.pid, payload.start_ticks
        if proc_start_ticks(pid) != ticks:
            return "failed", f"pid {pid} (start ticks {ticks}) was not running"
        started = time.monotonic()
        payload.popen.send_signal(signal.SIGTERM)
        sent = "SIGTERM"
        try:
            payload.popen.wait(timeout=KILL_TIMEOUT_SECONDS)
        except subprocess.TimeoutExpired:
            payload.popen.kill()
            sent = "SIGTERM then SIGKILL"
            try:
                payload.popen.wait(timeout=2)
            except subprocess.TimeoutExpired:
                pass
        elapsed = time.monotonic() - started
        if proc_start_ticks(pid) == ticks:
            return "indeterminate", f"{sent} sent to pid {pid}; process still present"
        self.payloads.pop(pid, None)
        return (
            "succeeded",
            f"verified: pid {pid} (start ticks {ticks}) terminated by {sent}, exit status "
            f"{payload.popen.returncode}, /proc entry gone after {elapsed:.2f}s",
        )

    def handle(self, client, command: dict) -> dict:
        """Accept, execute once and report. A redelivered command reuses its
        first result (stable result_id), so retries are idempotent."""
        command_id = command["command_id"]
        if command_id not in self.handled:
            client.post(f"/api/v1/agents/{self.agent_id}/commands/{command_id}/accept", {})
            outcome, detail = self.execute(command)
            self.handled[command_id] = {
                "schema_version": "2",
                "result_id": f"lab-{command_id}",
                "command_id": command_id,
                "outcome": outcome,
                "detail": detail[:512],
                "correlation_id": command["correlation_id"],
            }
        result = self.handled[command_id]
        for attempt in range(RESULT_RETRIES):
            try:
                client.post(f"/api/v1/agents/{self.agent_id}/command-results", result)
                break
            except OSError:
                if attempt == RESULT_RETRIES - 1:
                    raise
                time.sleep(2**attempt)
        return result

    def poll_once(self, client) -> list[dict]:
        commands = client.get(
            f"/api/v1/agents/{self.agent_id}/commands?delivery_mode=durable"
        )["commands"]
        return [self.handle(client, command) for command in commands]

    def cleanup(self) -> None:
        for payload in list(self.payloads.values()):
            if payload.popen.poll() is None:
                payload.popen.kill()
                payload.popen.wait(timeout=5)
        self.payloads.clear()


class HttpClient:
    def __init__(self, base: str, token: str | None = None, agent_id: str | None = None):
        self.base, self.token, self.agent_id = base.rstrip("/"), token, agent_id

    def _send(self, path: str, data: bytes | None, method: str, headers: dict) -> dict:
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        req = urllib.request.Request(self.base + path, data=data, method=method, headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                return json.load(resp)
        except urllib.error.HTTPError as exc:
            raise SystemExit(f"{method} {path} -> {exc.code}: {exc.read().decode()}") from exc

    def get(self, path: str) -> dict:
        return self._send(path, None, "GET", {})

    def post(self, path: str, body: dict, headers: dict | None = None) -> dict:
        return self._send(
            path, json.dumps(body).encode(), "POST",
            {"Content-Type": "application/json", **(headers or {})},
        )

    def ingest(self, events: list[dict]) -> dict:
        body = "".join(json.dumps(e, separators=(",", ":")) + "\n" for e in events).encode()
        return self._send("/api/v1/ingest", body, "POST", {
            "Content-Type": "application/x-ndjson",
            "X-Panopticon-Agent-Id": self.agent_id or "",
            "X-Panopticon-Protocol": "1",
            "X-Panopticon-Batch-Id": str(uuid.uuid4()),
        })


def _enroll(base: str, agent_id: str, host_id: str) -> str:
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from demo_seed import enroll_agent  # same real ECDSA enrollment as demo_seed

    token = os.environ.get("PANOPTICON_ENROLLMENT_TOKEN")
    if not token:
        raise SystemExit("set PANOPTICON_ENROLLMENT_TOKEN")
    return enroll_agent(base, agent_id, host_id, token)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("mode", choices=["demo"], help="launch payload, report it, serve commands")
    ap.add_argument("--url", default="http://127.0.0.1:8000")
    ap.add_argument("--agent-id", default="lab-responder-01")
    ap.add_argument("--host-id", default="LAB-RESPONDER-01")
    ap.add_argument("--enroll-analyst", metavar="ANALYST_ID",
                    help="also enroll an analyst and print its token (for Console/curl)")
    ap.add_argument("--poll-interval", type=float, default=2.0)
    ap.add_argument("--duration", type=float, default=900.0,
                    help="seconds to serve before cleaning up and exiting")
    args = ap.parse_args(argv)

    suffix = uuid.uuid4().hex[:6]
    agent_id = f"{args.agent_id}-{suffix}"
    token = _enroll(args.url, agent_id, args.host_id)
    print(f"[+] enrolled lab endpoint {agent_id} for host {args.host_id}")
    if args.enroll_analyst:
        bootstrap = os.environ.get("PANOPTICON_ANALYST_ENROLLMENT_TOKEN", "")
        analyst = HttpClient(args.url).post(
            "/api/v1/analysts/enroll", {"analyst_id": f"{args.enroll_analyst}-{suffix}"},
            {"X-Panopticon-Analyst-Enrollment-Token": bootstrap},
        )
        print(f"export ANALYST={analyst['access_token']}")

    endpoint = LabEndpoint(agent_id, args.host_id)
    atexit.register(endpoint.cleanup)
    signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))
    client = HttpClient(args.url, token, agent_id)
    payload = endpoint.launch_payload()
    print(f"[+] payload pid {payload.pid} start_ticks {payload.start_ticks}: bash -c "
          f"{PAYLOAD_COMMAND!r}")
    event = endpoint.observe(payload)
    print(f"[+] reported process start: {client.ingest([event])}")
    print("[*] waiting for commands (approve the KILL_PROCESS in Console). Ctrl-C to stop.")
    deadline = time.monotonic() + args.duration
    try:
        while time.monotonic() < deadline:
            for result in endpoint.poll_once(client):
                print(f"[+] {result['command_id']}: {result['outcome']} - {result['detail']}")
            if not endpoint.payloads:
                print("[+] payload contained; exiting")
                break
            time.sleep(args.poll_interval)
    except KeyboardInterrupt:
        pass
    finally:
        endpoint.cleanup()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
