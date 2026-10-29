"""Live readiness check for a running demo Manager (and its console).

    python tools/demo_check.py [--state-dir demo-state]

Reads the URLs and the analyst token that tools/demo_up.sh wrote into the
state directory, then reports, one line each, OK / WARN / FAIL:

  /readyz (schema + detection worker alive), canonical record queue,
  enrolled agents and the newest record, stored alerts (newest five),
  the console's view of the Manager, database size and free disk.

Exit status is 1 if anything is FAIL. Stdlib only, so it runs anywhere the
Manager does.
"""

from __future__ import annotations

import argparse
import json
import shutil
import ssl
import sys
import urllib.error
import urllib.request
from pathlib import Path

MIN_FREE_GB = 3.0
WARN_FREE_GB = 5.0


def _read(state: Path, name: str) -> str | None:
    path = state / name
    return path.read_text(encoding="utf-8").strip() if path.exists() else None


def _get(url: str, *, token: str | None = None, ca: str | None = None, timeout: float = 5.0):
    """(status, headers, parsed JSON or text); status 0 when unreachable."""
    request = urllib.request.Request(url)
    if token:
        request.add_header("Authorization", f"Bearer {token}")
    context = ssl.create_default_context(cafile=ca) if url.startswith("https") else None
    try:
        with urllib.request.urlopen(request, timeout=timeout, context=context) as response:
            body = response.read().decode("utf-8", "replace")
            status, headers = response.status, response.headers
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", "replace")
        status, headers = exc.code, exc.headers
    except (urllib.error.URLError, OSError) as exc:
        return 0, {}, str(exc)
    try:
        return status, headers, json.loads(body)
    except ValueError:
        return status, headers, body


class Report:
    def __init__(self) -> None:
        self.failed = False

    def line(self, level: str, what: str, detail: str) -> None:
        self.failed |= level == "FAIL"
        print(f"[{level:4}] {what:<18} {detail}")


def check(state: Path) -> bool:
    report = Report()
    manager = _read(state, "manager.url")
    if manager is None:
        report.line("FAIL", "state", f"{state}/manager.url missing -- run tools/demo_up.sh first")
        return False
    ca = _read(state, "ca.path")
    token = _read(state, "analyst.token")

    status, _, ready = _get(f"{manager}/readyz", ca=ca)
    if status == 200:
        report.line("OK", "manager", f"{manager} ready, schema {ready.get('schema_version')}")
    else:
        reason = ready.get("reason") if isinstance(ready, dict) else ready
        extra = ready.get("fatal_error") if isinstance(ready, dict) else None
        report.line("FAIL", "manager", f"{manager} /readyz {status}: {reason} {extra or ''}")

    if not token:
        report.line("FAIL", "analyst token", f"{state}/analyst.token missing")
        return False
    status, _, body = _get(f"{manager}/api/v1/status", token=token, ca=ca)
    if status != 200 or not isinstance(body, dict):
        report.line("FAIL", "status", f"/api/v1/status {status}: {body}")
        return False

    worker = body.get("detection_worker") or {}
    if worker.get("alive"):
        report.line(
            "OK",
            "detection worker",
            f"alive (heartbeat {worker.get('heartbeat_age_seconds')}s ago, "
            f"{worker.get('loop_errors', 0)} recovered cycle errors)",
        )
    else:
        report.line("FAIL", "detection worker", f"NOT alive: {worker.get('fatal_error')}")

    records = {k: (body.get("endpoint_records") or {}).get(k, 0) for k in
               ("pending", "claimed", "done", "failed")}
    level = "WARN" if records["failed"] or records["pending"] > 500 else "OK"
    report.line(
        level,
        "records queue",
        "pending {pending} / claimed {claimed} / done {done} / failed {failed}".format(**records),
    )
    agents = body.get("agents_enrolled", 0)
    report.line(
        "OK" if agents else "WARN",
        "agents",
        f"{agents} enrolled, newest record ingested {body.get('last_record_at') or 'never'}",
    )

    status, _, alerts = _get(f"{manager}/api/v1/alerts?limit=5", token=token, ca=ca)
    if status == 200 and isinstance(alerts, dict):
        report.line("OK", "alerts", f"{body.get('alerts', 0)} stored")
        for row in alerts.get("alerts", []):
            print(
                f"{'':25}{row.get('created_at')}  {row.get('severity', ''):<8} "
                f"{row.get('rule_id')}  host={row.get('host_id')}"
            )
    else:
        report.line("FAIL", "alerts", f"/api/v1/alerts {status}: {alerts}")

    console = _read(state, "console.url")
    if console:
        status, _, _ = _get(f"{console}/api/status")
        _, headers, _ = _get(f"{console}/api/alerts")
        source = headers.get("X-Panopticon-Alert-Source") if headers else None
        if status == 200 and source == "manager":
            report.line("OK", "console", f"{console} reading alerts from the Manager")
        else:
            report.line("FAIL", "console", f"{console} /api/status {status}, alert source {source}")

    db_path = Path(_read(state, "db.path") or state / "panopticon.db")
    size_mb = sum(
        p.stat().st_size for p in db_path.parent.glob(db_path.name + "*") if p.is_file()
    ) / 1e6
    free_gb = shutil.disk_usage(db_path.parent).free / 1e9
    level = "FAIL" if free_gb < MIN_FREE_GB else "WARN" if free_gb < WARN_FREE_GB else "OK"
    report.line(level, "disk", f"db {size_mb:.0f} MB, {free_gb:.1f} GB free on {db_path.parent}")
    return not report.failed


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--state-dir", default="demo-state", type=Path)
    args = parser.parse_args(argv)
    return 0 if check(args.state_dir) else 1


if __name__ == "__main__":
    sys.exit(main())
