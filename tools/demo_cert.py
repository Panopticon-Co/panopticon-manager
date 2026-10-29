"""Self-signed TLS certificate for a demo Manager that terminates TLS itself
(``tools/demo_up.sh --tls``), i.e. when there is no nginx in front of it.

    python tools/demo_cert.py --san 10.77.10.10 --san 127.0.0.1 --out demo-state/tls

Writes cert.pem and key.pem (0600). The Windows agent verifies TLS for
enrollment and commands, so import cert.pem into the guest's machine root
store before starting it:  certutil -addstore -f Root cert.pem
Every address the agent or console uses in its URL must be one of the SANs.
Same construction as tools/verify_endpoint_https.py, with configurable names.
"""

from __future__ import annotations

import argparse
import ipaddress
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID


def _san(value: str) -> x509.GeneralName:
    try:
        return x509.IPAddress(ipaddress.ip_address(value))
    except ValueError:
        return x509.DNSName(value)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--san", action="append", required=True, help="IP or DNS name")
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--days", type=int, default=7)
    args = parser.parse_args(argv)

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "panopticon demo manager")])
    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=args.days))
        .add_extension(x509.SubjectAlternativeName([_san(s) for s in args.san]), critical=False)
        # Self-signed and trusted directly from the Root store, so it is its own CA.
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .sign(key, hashes.SHA256())
    )
    args.out.mkdir(parents=True, exist_ok=True)
    key_path, cert_path = args.out / "key.pem", args.out / "cert.pem"
    key_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    os.chmod(key_path, 0o600)
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    print(f"{cert_path}\n{key_path}\nSANs: {', '.join(args.san)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
