"""Own an agent with unread stdout/stderr; inspect only its stopped journal."""

from __future__ import annotations

import json
import subprocess
import time
from pathlib import Path

from verify_endpoint_https import owned_scratch


def main() -> None:
    build = Path(__file__).resolve().parents[2] / "panopticon-agent/build-verify-x64"
    with owned_scratch() as scratch:
        spool = scratch / "unread-display-spool"
        process = subprocess.Popen(
            [str(build / "officer-agent.exe"), "--source", "etw", "--spool-directory",
             str(spool), "--identity-path", str(scratch / "missing-test-identity.json")],
            cwd=scratch, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
        try:
            # Never drain either pipe. No second journal owner or live DB inspection.
            deadline = time.monotonic() + 18
            while time.monotonic() < deadline:
                if process.poll() is not None:
                    raise RuntimeError("owned agent exited while display pipes were unread")
                time.sleep(0.1)
        finally:
            process.terminate()  # only the process created above
            process.wait(timeout=5)
            process.stdout.close()
            process.stderr.close()
        recovered = json.loads(subprocess.check_output(
            [str(build / "officer-host-inventory-tests.exe"), "--read-spool", str(spool)],
            text=True, encoding="utf-8",
        ))
        categories = {record.get("category") for record in recovered if record["kind"] == "state"}
        expected = {"host_inventory", "process_inventory", "service_inventory",
                    "loaded_driver_inventory", "socket_inventory", "route_inventory",
                    "ip_interface_inventory", "firewall_profile_state", "firewall_rule_inventory",
                    "security_center_state", "defender_status"}
        if not expected <= categories:
            raise RuntimeError(
                f"unread display stalled durable state: missing {expected - categories}"
            )
        health = [record["data"] for record in recovered if record["kind"] == "health"]
        if not health:
            raise RuntimeError("health was not durable with unread display")
        observed = False
        for value in health:
            for stream in ("diagnostic_stdout", "diagnostic_stderr"):
                status = value["pipeline"][stream]
                numbers = {key: int(status[key]) for key in (
                    "admitted_volatile", "completed_native_writes", "failed_native_writes",
                    "abandoned_unattempted", "owned_lines", "charged_bytes", "byte_limit",
                    "event_limit", "refused",
                )}
                if numbers["admitted_volatile"] != sum(numbers[key] for key in (
                    "completed_native_writes", "failed_native_writes",
                    "abandoned_unattempted", "owned_lines",
                )):
                    raise RuntimeError("diagnostic dispositions do not reconcile")
                if numbers["charged_bytes"] > numbers["byte_limit"] or (
                    numbers["owned_lines"] > numbers["event_limit"]
                ):
                    raise RuntimeError("diagnostic owned bounds exceeded")
                observed |= status["write_in_progress"] and numbers["owned_lines"] > 0
        if not observed:
            raise RuntimeError("test did not observe an in-flight unread display write")
        print(f"Unread stdout/stderr: {len(recovered)} durable records; all eleven state domains, "
              f"{len(health)} health records and diagnostic accounting survived owned abrupt exit")


if __name__ == "__main__":
    main()
