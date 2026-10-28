"""Manager-owned ES256 key custody and authorization-time signatures.

Canonical signing bytes and retained native vectors live in response-engine and
contracts. A configured unusable key refuses authorization. Key files are bounded
and re-read for each authorization; persisted signatures are never changed at poll.
"""

from __future__ import annotations

import base64
import hashlib
import os
import stat
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils
from response_engine.signing import UnsignableCommand, epoch_seconds, signing_input

SIGNING_KEY_ENV = "PANOPTICON_COMMAND_SIGNING_KEY"
ALGORITHM = "ES256"


class SigningUnavailable(RuntimeError):
    """A signing key is configured but cannot be used."""


def public_point(key: ec.EllipticCurvePublicKey) -> bytes:
    return key.public_bytes(
        serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint
    )


def key_id(point: bytes) -> str:
    """Endpoint key ID: first 16 hex digits of the public point SHA-256."""
    return hashlib.sha256(point).hexdigest()[:16]


def keyring_line(key: ec.EllipticCurvePrivateKey) -> str:
    """Public point and key ID for explicit endpoint key pinning."""
    point = public_point(key.public_key())
    return f"{base64.b64encode(point).decode()} {key_id(point)}"


class CommandSigner:
    def __init__(self, private_key: ec.EllipticCurvePrivateKey):
        if not isinstance(private_key, ec.EllipticCurvePrivateKey) or not isinstance(
            private_key.curve, ec.SECP256R1
        ):
            raise SigningUnavailable("the command signing key is not a P-256 private key")
        self._key = private_key
        self.key_id = key_id(public_point(private_key.public_key()))

    def keyring_line(self) -> str:
        return keyring_line(self._key)

    def authorization(self, command: dict) -> dict:
        lifetime = epoch_seconds(command["expires_at"]) - epoch_seconds(command["created_at"])
        if not 0 < lifetime <= 900:
            raise UnsignableCommand("signed command lifetime must be within 900 seconds")
        der = self._key.sign(signing_input(command), ec.ECDSA(hashes.SHA256()))
        r, s = utils.decode_dss_signature(der)
        raw = r.to_bytes(32, "big") + s.to_bytes(32, "big")
        return {
            "algorithm": ALGORITHM,
            "key_id": self.key_id,
            "signature": base64.b64encode(raw).decode(),
        }


def verify(command: dict, point: bytes) -> bool:
    """Check the retained signature against an explicit public point."""
    authorization = command.get("authorization")
    if not isinstance(authorization, dict) or authorization.get("algorithm") != ALGORITHM:
        return False
    if authorization.get("key_id") != key_id(point):
        return False
    try:
        raw = base64.b64decode(authorization["signature"], validate=True)
        if len(raw) != 64:
            return False
        der = utils.encode_dss_signature(
            int.from_bytes(raw[:32], "big"), int.from_bytes(raw[32:], "big")
        )
        public = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), point)
        unsigned = {name: value for name, value in command.items() if name != "authorization"}
        public.verify(der, signing_input(unsigned), ec.ECDSA(hashes.SHA256()))
        return True
    except (InvalidSignature, ValueError, KeyError, TypeError):
        return False


def load_key_file(path: Path) -> CommandSigner:
    """Read a bounded, private regular key file through the same validated handle."""
    descriptor = None
    try:
        descriptor = os.open(
            path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
        )
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or info.st_size > 16384:
            raise SigningUnavailable("command key must be a bounded regular file")
        if os.name == "posix" and (info.st_mode & (stat.S_IRWXG | stat.S_IRWXO)):
            raise SigningUnavailable("command key permissions must restrict access to its owner")
        with os.fdopen(descriptor, "rb") as handle:
            descriptor = None
            raw = handle.read(16385)
        if len(raw) > 16384:
            raise SigningUnavailable("command key exceeds the size bound")
        key = serialization.load_pem_private_key(raw, password=None)
        return CommandSigner(key)
    except (OSError, ValueError, TypeError) as exc:
        raise SigningUnavailable("configured command signing key is unavailable") from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)


def signer() -> CommandSigner | None:
    """Reread on every authorization so rotation and permission changes take effect."""
    configured = os.environ.get(SIGNING_KEY_ENV, "")
    return load_key_file(Path(configured)) if configured else None


def readiness() -> dict:
    try:
        current = signer()
    except SigningUnavailable:
        return {"state": "unavailable", "algorithm": ALGORITHM, "key_id": None}
    return {
        "state": "ready" if current else "not_configured",
        "algorithm": ALGORITHM,
        "key_id": current.key_id if current else None,
    }


def generate(path: Path) -> str:
    """Create a new key without overwriting a file; return its public keyring line."""
    key = ec.generate_private_key(ec.SECP256R1())
    pem = key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    )
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "wb") as handle:
        handle.write(pem)
    return keyring_line(key)


if __name__ == "__main__":
    import sys

    if len(sys.argv) != 3 or sys.argv[1] not in ("generate", "keyring-line"):
        sys.exit("usage: python -m manager.command_signing generate|keyring-line <key.pem>")
    if sys.argv[1] == "generate":
        print(generate(Path(sys.argv[2])))
    else:
        print(load_key_file(Path(sys.argv[2])).keyring_line())
