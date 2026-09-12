"""Replay a Panopticon-schema NDJSON file at the manager's ingest endpoint.

This is the offline pipeline test and the viva fallback: it exercises
ingest -> events table -> detection worker -> alerts.ndjson -> console without
officer-agent.exe or Sysmon. It is NOT the Phase 2 load harness -- no --agents,
no --eps, no failure injection; those belong in the performance work.

    python tools/fake_agent.py                       # replay tools/demo_events.ndjson
    python tools/fake_agent.py --file some.ndjson --url http://127.0.0.1:8000
"""

from __future__ import annotations

import argparse
import json
import urllib.request
import uuid
from pathlib import Path

_DEFAULT_FILE = Path(__file__).with_name("demo_events.ndjson")


def _batches(lines: list[str], size: int):
    for i in range(0, len(lines), size):
        yield lines[i : i + size]


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--file", type=Path, default=_DEFAULT_FILE, help="NDJSON to replay")
    ap.add_argument("--url", default="http://127.0.0.1:8000", help="manager base URL")
    ap.add_argument("--agent-id", default="fake-agent", help="X-Panopticon-Agent-Id")
    ap.add_argument("--batch-size", type=int, default=100)
    args = ap.parse_args(argv)

    lines = [
        ln
        for ln in args.file.read_text(encoding="utf-8").splitlines()
        if ln.strip() and not ln.lstrip().startswith("#")
    ]
    print(f"[*] {len(lines)} event(s) from {args.file} -> {args.url}/api/v1/ingest")

    accepted = duplicates = rejected = 0
    for batch in _batches(lines, args.batch_size):
        body = ("\n".join(batch) + "\n").encode("utf-8")
        req = urllib.request.Request(
            f"{args.url}/api/v1/ingest",
            data=body,
            method="POST",
            headers={
                "Content-Type": "application/x-ndjson",
                "X-Panopticon-Batch-Id": str(uuid.uuid4()),
                "X-Panopticon-Agent-Id": args.agent_id,
                "X-Panopticon-Protocol": "1",
            },
        )
        with urllib.request.urlopen(req) as resp:
            data = json.load(resp)
        accepted += data["accepted"]
        duplicates += data["duplicates"]
        rejected += len(data["rejected"])
        for r in data["rejected"]:
            print(f"    rejected line {r['line']}: {r['reason']} - {r['detail']}")

    print(f"[+] accepted={accepted} duplicates={duplicates} rejected={rejected}")
    print("[*] watch the console (http://127.0.0.1:8787) for alerts")
    return 1 if rejected else 0


if __name__ == "__main__":
    raise SystemExit(main())
