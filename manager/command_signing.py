"""ES256 command authorization (ADR 008): the Manager signs every command it authorizes.

The signature is made once, when the command is authorized and written to the commands table, over the exact
fields the endpoint will act on. It is stored with the command, so a later write to the database cannot change
what a command does without breaking its signature. Endpoints that verify (the Linux sensor, its ADR 025) refuse
anything unsigned or signed by a key they do not pin.

The signing input is the Linux sensor's ``command_signing_input``, byte for byte. Its conformance vectors in
``tests/fixtures/command_signing_vectors.json`` are produced by the sensor's own reference signer; change this
module only together with that function and those vectors.

The key is a P-256 private key in a PEM file named by ``PANOPTICON_COMMAND_SIGNING_KEY``. With the variable unset
commands are not signed (endpoints that require signatures then refuse them, and say so in their result). With it
set, a key that cannot be loaded makes command creation fail: a command is never silently left unsigned.
"""

from __future__ import annotations

import base64
import hashlib
import os
import stat
import threading
from datetime import datetime
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils

SIGNING_KEY_ENV = "PANOPTICON_COMMAND_SIGNING_KEY"
ALGORITHM = "ES256"
_DOMAIN = b"panopticon-command-auth/1\n"


class SigningUnavailable(RuntimeError):
    """A signing key is configured but cannot be used."""


class UnsignableCommand(ValueError):
    """The command cannot be expressed in the signing input (e.g. a time without a UTC offset)."""


def epoch_seconds(text: str) -> int:
    """Whole seconds since the epoch of an RFC 3339 time with an offset, as the endpoint computes them (the fraction
    is dropped, the offset applied). A time without an offset is refused: the endpoint refuses it too."""
    if not isinstance(text, str):
        raise UnsignableCommand("time is not a string")
    value = text[:-1] + "+00:00" if text.endswith(("Z", "z")) else text
    try:
        moment = datetime.fromisoformat(value)
    except ValueError as exc:
        raise UnsignableCommand(f"not an RFC 3339 time: {text!r}") from exc
    if moment.tzinfo is None or moment.utcoffset() is None:
        raise UnsignableCommand(f"time has no UTC offset: {text!r}")
    seconds = int(moment.replace(microsecond=0).timestamp())
    if seconds < 0:
        raise UnsignableCommand(f"time is before 1970: {text!r}")
    return seconds


def _field(name: str, value: str) -> bytes:
    data = value.encode("utf-8")
    return name.encode() + b":" + str(len(data)).encode() + b":" + data + b"\n"


def _unsigned(target: dict, key: str) -> str:
    value = target.get(key, 0)
    if isinstance(value, bool) or not isinstance(value, (int, str)):
        raise UnsignableCommand(f"target {key} is not an integer")
    number = int(value)
    if number < 0:
        raise UnsignableCommand(f"target {key} is negative")
    return str(number)


def signing_input(command: dict) -> bytes:
    """The bytes an ES256 command signature covers (panopticon-linux-agent ``command_signing_input``)."""
    target = command.get("target") or {}
    if not isinstance(target, dict):
        raise UnsignableCommand("target is not an object")
    boot_id = target.get("boot_id", "")
    path = target.get("path", "")
    if not isinstance(boot_id, str) or not isinstance(path, str):
        raise UnsignableCommand("target boot_id and path must be strings")
    if "created_at" not in command:
        raise UnsignableCommand("a signed command needs created_at")
    fields = (
        ("schema_version", "2" if boot_id else "1"),
        ("command_id", command["command_id"]),
        ("correlation_id", command["correlation_id"]),
        ("agent_id", command["agent_id"]),
        ("host_id", command["host_id"]),
        ("action", command["action"]),
        ("created_at", str(epoch_seconds(command["created_at"]))),
        ("expires_at", str(epoch_seconds(command["expires_at"]))),
        ("pid", _unsigned(target, "pid")),
        ("start_time_ticks", _unsigned(target, "start_time_ticks")),
        ("boot_id", boot_id),
        ("path", path),
    )
    out = bytearray(_DOMAIN)
    for name, value in fields:
        if not isinstance(value, str):
            raise UnsignableCommand(f"{name} is not a string")
        out += _field(name, value)
    return bytes(out)


def public_point(key: ec.EllipticCurvePublicKey) -> bytes:
    return key.public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)


def key_id(point: bytes) -> str:
    """The id an endpoint's keyring knows a key by: the first 16 hex digits of SHA-256 of the 65-byte point."""
    return hashlib.sha256(point).hexdigest()[:16]


def keyring_line(key: ec.EllipticCurvePrivateKey) -> str:
    """The line to add to an endpoint's command signing key file for this key (point, then the id as a label)."""
    point = public_point(key.public_key())
    return f"{base64.b64encode(point).decode()} {key_id(point)}"


class CommandSigner:
    def __init__(self, private_key: ec.EllipticCurvePrivateKey):
        if not isinstance(private_key, ec.EllipticCurvePrivateKey) or not isinstance(private_key.curve, ec.SECP256R1):
            raise SigningUnavailable("the command signing key is not a P-256 private key")
        self._key = private_key
        self.key_id = key_id(public_point(private_key.public_key()))

    def keyring_line(self) -> str:
        return keyring_line(self._key)

    def authorization(self, command: dict) -> dict:
        der = self._key.sign(signing_input(command), ec.ECDSA(hashes.SHA256()))
        r, s = utils.decode_dss_signature(der)
        raw = r.to_bytes(32, "big") + s.to_bytes(32, "big")
        return {"algorithm": ALGORITHM, "key_id": self.key_id, "signature": base64.b64encode(raw).decode()}


def verify(command: dict, point: bytes) -> bool:
    """True when ``command["authorization"]`` is a valid signature of the command by the key ``point``."""
    authorization = command.get("authorization")
    if not isinstance(authorization, dict) or authorization.get("algorithm") != ALGORITHM:
        return False
    if authorization.get("key_id") != key_id(point):
        return False
    try:
        raw = base64.b64decode(authorization["signature"], validate=True)
        if len(raw) != 64:
            return False
        der = utils.encode_dss_signature(int.from_bytes(raw[:32], "big"), int.from_bytes(raw[32:], "big"))
        public = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), point)
        unsigned = {name: value for name, value in command.items() if name != "authorization"}
        public.verify(der, signing_input(unsigned), ec.ECDSA(hashes.SHA256()))
        return True
    except (InvalidSignature, ValueError, KeyError, TypeError):
        return False


def load_key_file(path: Path) -> CommandSigner:
    try:
        info = path.stat()
    except OSError as exc:
        raise SigningUnavailable(f"the command signing key {path} is not readable") from exc
    # The key authorizes every enforcement action on every endpoint that pins it.
    if os.name == "posix" and (info.st_mode & (stat.S_IRWXG | stat.S_IRWXO)):
        raise SigningUnavailable(f"the command signing key {path} is accessible to other users (mode {oct(info.st_mode & 0o777)})")
    try:
        key = serialization.load_pem_private_key(path.read_bytes(), password=None)
    except (OSError, ValueError, TypeError) as exc:
        raise SigningUnavailable(f"the command signing key {path} is not an unencrypted PEM private key") from exc
    return CommandSigner(key)


_lock = threading.Lock()
_cache: tuple[str, int, int, CommandSigner] | None = None


def signer() -> CommandSigner | None:
    """The configured signer, None when signing is not configured. Raises SigningUnavailable when it is configured
    and unusable. The key file is re-read when it changes, so a key can be rotated without a restart."""
    global _cache
    configured = os.environ.get(SIGNING_KEY_ENV, "")
    if not configured:
        return None
    path = Path(configured)
    try:
        info = path.stat()
    except OSError as exc:
        raise SigningUnavailable(f"the command signing key {path} is not readable") from exc
    with _lock:
        if _cache is not None and _cache[:3] == (configured, info.st_mtime_ns, info.st_size):
            return _cache[3]
        loaded = load_key_file(path)
        _cache = (configured, info.st_mtime_ns, info.st_size, loaded)
        return loaded


def generate(path: Path) -> str:
    """Writes a new P-256 key to ``path`` (owner-only, never over an existing file) and returns its keyring line."""
    key = ec.generate_private_key(ec.SECP256R1())
    pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
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
