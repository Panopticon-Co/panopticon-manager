"""Replay a Panopticon-schema NDJSON file at the manager's ingest endpoint.

This is the offline pipeline test and the viva fallback: it exercises
ingest -> events table -> detection worker -> incidents/alerts -> console
without officer-agent.exe or Sysmon. It is NOT the Phase 2 load harness -- no
--agents, no --eps, no failure injection; those belong in the performance work.

    python tools/fake_agent.py                       # replay tools/demo_events.ndjson
    python tools/fake_agent.py --file some.ndjson --url http://127.0.0.1:8000
    python tools/fake_agent.py --file vendor/eyedetect/tests/corpus/<scenario>/events.ndjson \\
        --rebase-time --etw-twins --agent-id demo-agent --token <agent bearer>

``--rebase-time`` shifts every event so the newest lands at "now", keeping the
gaps between events. Corpus scenarios are dated weeks in the past, and the
worker prunes provenance older than ``GRAPH_RETENTION`` against wall-clock
time (manager/detection/factory.py ``prune_graph``); without rebasing, a
prune mid-demo could drop the chain an incident is built from.

``--etw-twins`` adds, before each Sysmon process start lacking
``start_time_ticks``, the ETW Kernel-Process report the live agent sends for
the same creation: same instant/pid/image/parent, no command line, its own
event id, and ``start_time_ticks`` = that instant as a Windows FILETIME --
as the agent's ETW collector reports it (the engine's
``scripts/eval_demo_suite.py`` builds twins the same way). With twins a kill
recommendation carries the PID-reuse guard and is proposed for approval;
without them it fails closed. Twins are built after rebasing, so their ticks
match the rebased time.

``--token`` sends ``Authorization: Bearer <token>`` (required for schema 0.4
batches; harmless otherwise).
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import urllib.request
import uuid
from datetime import datetime, timezone
from pathlib import Path

_DEFAULT_FILE = Path(__file__).with_name("demo_events.ndjson")
_FILETIME_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)
_TS_FORMAT = "%Y-%m-%dT%H:%M:%S.%fZ"


def _parse_ts(value: str) -> datetime:
    return datetime.strptime(value, _TS_FORMAT).replace(tzinfo=timezone.utc)


def _format_ts(moment: datetime) -> str:
    return moment.strftime("%Y-%m-%dT%H:%M:%S.") + f"{moment.microsecond // 1000:03d}Z"


def rebase_times(events: list[dict], now: datetime | None = None) -> list[dict]:
    """Shift every ``event.timestamp`` by one offset so the newest equals
    ``now`` (UTC, millisecond precision); relative timing is preserved."""
    if not events:
        return events
    now = now or datetime.now(timezone.utc)
    newest = max(_parse_ts(e["event"]["timestamp"]) for e in events)
    offset = now.replace(microsecond=(now.microsecond // 1000) * 1000) - newest
    out = []
    for event in events:
        shifted = copy.deepcopy(event)
        shifted["event"]["timestamp"] = _format_ts(_parse_ts(event["event"]["timestamp"]) + offset)
        out.append(shifted)
    return out


def filetime(timestamp: str) -> int:
    """A wire timestamp as a Windows FILETIME (100 ns ticks since 1601)."""
    delta = _parse_ts(timestamp) - _FILETIME_EPOCH
    return (delta.days * 86_400 + delta.seconds) * 10_000_000 + delta.microseconds * 10


def etw_twin(event: dict) -> dict | None:
    """The ETW Kernel-Process report of a Sysmon process start, or None."""
    meta, process = event["event"], event["process"]
    if meta["category"] != "process" or meta["type"] != "start":
        return None
    if process.get("start_time_ticks") or event["source"]["kind"] == "etw":
        return None
    twin = copy.deepcopy(event)
    twin["event"]["id"] = "evt_" + hashlib.sha256(("etw|" + meta["id"]).encode()).hexdigest()
    twin["source"] = {
        "kind": "etw",
        "provider": "Microsoft-Windows-Kernel-Process",
        "channel": None,
        "record_id": None,
    }
    twin["process"]["command_line"] = None
    twin["process"]["start_time_ticks"] = filetime(meta["timestamp"])
    return twin


def with_etw_twins(events: list[dict]) -> list[dict]:
    out = []
    for event in events:
        twin = etw_twin(event)
        if twin is not None:
            out.append(twin)
        out.append(event)
    return out


def prepare(
    lines: list[str], *, rebase: bool, twins: bool, now: datetime | None = None
) -> list[str]:
    """Apply the requested transforms; with neither, lines go out byte-for-byte."""
    if not rebase and not twins:
        return lines
    events = [json.loads(line) for line in lines]
    if rebase:
        events = rebase_times(events, now)
    if twins:
        events = with_etw_twins(events)
    return [json.dumps(e, separators=(",", ":")) for e in events]


def _batches(lines: list[str], size: int):
    for i in range(0, len(lines), size):
        yield lines[i : i + size]


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    ap.add_argument("--file", type=Path, default=_DEFAULT_FILE, help="NDJSON to replay")
    ap.add_argument("--url", default="http://127.0.0.1:8000", help="manager base URL")
    ap.add_argument("--agent-id", default="fake-agent", help="X-Panopticon-Agent-Id")
    ap.add_argument("--token", default=None, help="agent bearer token (Authorization header)")
    ap.add_argument("--batch-size", type=int, default=100)
    ap.add_argument(
        "--rebase-time", action="store_true", help="shift timestamps so the newest is now"
    )
    ap.add_argument(
        "--etw-twins", action="store_true", help="add the ETW twin of each Sysmon process start"
    )
    args = ap.parse_args(argv)

    lines = [
        ln
        for ln in args.file.read_text(encoding="utf-8").splitlines()
        if ln.strip() and not ln.lstrip().startswith("#")
    ]
    lines = prepare(lines, rebase=args.rebase_time, twins=args.etw_twins)
    print(f"[*] {len(lines)} event(s) from {args.file} -> {args.url}/api/v1/ingest")

    headers = {
        "Content-Type": "application/x-ndjson",
        "X-Panopticon-Agent-Id": args.agent_id,
        "X-Panopticon-Protocol": "1",
    }
    if args.token:
        headers["Authorization"] = f"Bearer {args.token}"

    accepted = duplicates = rejected = 0
    for batch in _batches(lines, args.batch_size):
        body = ("\n".join(batch) + "\n").encode("utf-8")
        req = urllib.request.Request(
            f"{args.url}/api/v1/ingest",
            data=body,
            method="POST",
            headers={**headers, "X-Panopticon-Batch-Id": str(uuid.uuid4())},
        )
        with urllib.request.urlopen(req) as resp:
            data = json.load(resp)
        accepted += data["accepted"]
        duplicates += data["duplicates"]
        rejected += len(data["rejected"])
        for r in data["rejected"]:
            print(f"    rejected line {r['line']}: {r['reason']} - {r['detail']}")

    print(f"[+] accepted={accepted} duplicates={duplicates} rejected={rejected}")
    print("[*] incidents: GET /api/v1/incidents (analyst bearer)")
    return 1 if rejected else 0


if __name__ == "__main__":
    raise SystemExit(main())
