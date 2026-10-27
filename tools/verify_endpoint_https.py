"""Isolated real WinHTTP -> TLS -> Manager -> durable ACK integration check.

Uses ephemeral test credentials/certificate/DB/spool and an owned server process.
Never installs a certificate, alters real endpoint policy or touches a live DB.
Run with this repository's Python environment after building officer-endpoint-tests.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import os
import socket
import sqlite3
import subprocess
import tempfile
import time
from contextlib import closing, contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path

import httpx
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID


@contextmanager
def owned_scratch():
    temporary = tempfile.TemporaryDirectory(prefix="panopticon-https-check-")
    scratch = Path(temporary.name).resolve()
    if scratch.parent != Path(tempfile.gettempdir()).resolve() or not scratch.name.startswith(
        "panopticon-https-check-"
    ):
        raise RuntimeError("test scratch path escaped its owned temporary root")
    try:
        yield scratch
    finally:
        # The owned server has already exited. Windows scanners can briefly
        # retain a file handle; retry only this verified test-owned directory.
        for attempt in range(30):
            try:
                temporary.cleanup()
                break
            except PermissionError:
                if attempt == 29:
                    raise
                time.sleep(0.1)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--response-tls-refusal", action="store_true")
    options = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    native_test = (
        "officer-response-runtime-tests.exe"
        if options.response_tls_refusal
        else "officer-endpoint-tests.exe"
    )
    executable = root.parent / "panopticon-agent/build-verify-x64" / native_test
    if not executable.is_file():
        raise RuntimeError("native officer-endpoint-tests build required")
    import sys

    sys.path.insert(0, str(root))
    from tests.conftest import enroll_test_agent

    with owned_scratch() as scratch:
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "isolated endpoint test")])
        now = datetime.now(timezone.utc)
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=1))
            .not_valid_after(now + timedelta(hours=1))
            .add_extension(
                x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]),
                critical=False,
            )
            .sign(key, hashes.SHA256())
        )
        key_path, cert_path = scratch / "key.pem", scratch / "cert.pem"
        key_path.write_bytes(
            key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        )
        cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        with socket.socket() as probe:
            probe.bind(("127.0.0.1", 0))
            port = probe.getsockname()[1]
        environment = dict(os.environ)
        environment.update(
            {
                "PANOPTICON_DB_PATH": str(scratch / "manager.db"),
                "PANOPTICON_ALERTS_PATH": str(scratch / "alerts.ndjson"),
                "PANOPTICON_RULES_DIR": str(root / "tests/fixtures/rules"),
                "PANOPTICON_ENROLLMENT_TOKEN": "test-bootstrap-token",
            }
        )
        with tempfile.TemporaryFile(mode="w+b") as log:
            server = subprocess.Popen(
                [
                    sys.executable,
                    "-m",
                    "uvicorn",
                    "manager.app:app",
                    "--host",
                    "127.0.0.1",
                    "--port",
                    str(port),
                    "--ssl-keyfile",
                    str(key_path),
                    "--ssl-certfile",
                    str(cert_path),
                ],
                cwd=root,
                env=environment,
                stdout=log,
                stderr=log,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
            try:
                with httpx.Client(
                    base_url=f"https://127.0.0.1:{port}", verify=False, timeout=2
                ) as client:
                    deadline = time.monotonic() + 15
                    while True:
                        if server.poll() is not None:
                            raise RuntimeError("owned test server failed to start")
                        try:
                            if client.get("/readyz").status_code == 200:
                                break
                        except httpx.HTTPError:
                            pass
                        if time.monotonic() >= deadline:
                            raise RuntimeError("test server readiness deadline exceeded")
                        time.sleep(0.1)
                    enrolled = enroll_test_agent(client, "agent-1", "host-1")
                    enrolled.raise_for_status()
                    token_path = scratch / "test-token.txt"
                    token_path.write_text(enrolled.json()["access_token"], encoding="utf-8")
                    completed = subprocess.run(
                        [
                            str(executable),
                            "--verify-untrusted-https"
                            if options.response_tls_refusal
                            else "--send-fixtures",
                            str(client.base_url).rstrip("/"),
                            str(scratch / "spool"),
                            str(token_path),
                        ],
                        capture_output=True,
                        text=True,
                        timeout=30,
                        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
                    )
                    if completed.returncode:
                        raise RuntimeError(
                            "native integration failed: " + completed.stdout + completed.stderr
                        )
                    outcome = json.loads(completed.stdout)
                    if options.response_tls_refusal:
                        with closing(sqlite3.connect(scratch / "manager.db")) as connection:
                            receipts = connection.execute(
                                "SELECT COUNT(*) FROM command_result_receipts"
                            ).fetchone()[0]
                        if receipts != 0:
                            raise RuntimeError(
                                "untrusted native TLS unexpectedly reached result retention"
                            )
                        print(
                            json.dumps(
                                {"check": "native response TLS refusal and recovery", **outcome}
                            )
                        )
                        return
                    latest = client.get(
                        "/api/v2/endpoint/agent-1/latest",
                        headers={"Authorization": "Bearer " + enrolled.json()["access_token"]},
                    )
                    latest.raise_for_status()
                    kinds = {record["kind"] for record in latest.json()["records"]}
                    if kinds != {"health", "state"}:
                        raise RuntimeError("latest state/health not preserved")
                    if any(
                        status["ordering"] != "current"
                        for status in latest.json()["projection_status"]
                    ):
                        raise RuntimeError(
                            "native committed generation did not establish state ordering"
                        )
                    if any(
                        status["observation_freshness"] != "unverified"
                        for status in latest.json()["projection_status"]
                    ):
                        raise RuntimeError("receipt incorrectly treated as live observation proof")
                    if any(
                        status["capture_freshness"] != "fresh"
                        for status in latest.json()["projection_status"]
                    ):
                        raise RuntimeError("native one-use capture-age proof did not validate")
                with closing(sqlite3.connect(scratch / "manager.db")) as connection:
                    count = connection.execute("SELECT COUNT(*) FROM endpoint_records").fetchone()[
                        0
                    ]
                    if count != 6:
                        raise RuntimeError("unexpected durable Manager record count")
                    observation_rows = connection.execute(
                        "SELECT raw_json FROM endpoint_records "
                        "WHERE kind='observation' ORDER BY rowid"
                    ).fetchall()
                    observations = [json.loads(row[0]) for row in observation_rows]
                    if len(observations) != 4 or any(
                        record["data"].get("source_facts", {}).get("representation")
                        != "decoded_source_facts_v1"
                        for record in observations
                    ):
                        raise RuntimeError("native decoded source facts were not retained")
                    if (
                        observations[0]["data"]["source_facts"]["process"]["start_time_ticks"]
                        != "133700000000000001"
                    ):
                        raise RuntimeError("decoded native creation token changed in transport")
                    deadline = time.monotonic() + 10
                    while True:
                        detected = connection.execute(
                            "SELECT COUNT(*) FROM endpoint_records WHERE detect_state='done'"
                        ).fetchone()[0]
                        if detected == 6:
                            break
                        if time.monotonic() >= deadline:
                            raise RuntimeError("canonical detection queue did not drain")
                        time.sleep(0.05)
                    row = connection.execute(
                        "SELECT alert_json FROM alerts WHERE rule_id='DET-PROC-008'"
                    ).fetchone()
                    if row is None:
                        raise RuntimeError("native canonical fixture did not reach fleet rule")
                    context = json.loads(row[0])["endpoint_context"]
                    if context["subject"]["native_creation_ticks"] != "133700000000000001":
                        raise RuntimeError("native exact target context lost in alert")
                print(
                    json.dumps(
                        {
                            "check": "native WinHTTP HTTPS canonical ingestion",
                            "manager_records": count,
                            "detected_records": detected,
                            "canonical_rule_alert": True,
                            "decoded_source_facts_retained": True,
                            **outcome,
                        }
                    )
                )
            finally:
                server.terminate()
                try:
                    server.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    server.kill()
                    server.wait(timeout=5)


if __name__ == "__main__":
    main()
