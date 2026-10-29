"""Read-only verification against an independently retained signed checkpoint."""

import argparse
import base64
import json
import sqlite3
import sys
from pathlib import Path

from manager import audit_chain, command_signing
from manager.wire.linux_endpoint import strict_json


def bounded_read(path, maximum):
    with Path(path).open("rb") as handle:
        data = handle.read(maximum + 1)
    if len(data) > maximum:
        raise ValueError("verification input exceeds size bound")
    return data.decode("utf-8")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--database", required=True)
    parser.add_argument("--checkpoint", required=True)
    parser.add_argument(
        "--trusted-key",
        required=True,
        help="trusted public keyring; one base64 P-256 point per line",
    )
    args = parser.parse_args(argv)
    conn = None
    try:
        anchor = strict_json(bounded_read(args.checkpoint, 65536))
        key_id = anchor["authorization"]["key_id"]
        point = None
        for line in bounded_read(args.trusted_key, 16384).splitlines():
            if line.strip() and not line.lstrip().startswith("#"):
                candidate = base64.b64decode(line.split()[0], validate=True)
                if len(candidate) != 65:
                    raise ValueError("invalid trusted public point")
                if command_signing.key_id(candidate) == key_id:
                    point = candidate
        if point is None:
            raise ValueError("checkpoint key is not independently trusted")
        conn = sqlite3.connect(Path(args.database).resolve().as_uri() + "?mode=ro", uri=True)
        conn.row_factory = sqlite3.Row
        conn.execute("BEGIN")
        result = audit_chain.verify_checkpoint(conn, anchor, point)
        print(json.dumps({"verified": True, **result}, sort_keys=True))
        return 0
    except (OSError, ValueError, TypeError, KeyError, sqlite3.DatabaseError):
        print("Audit checkpoint verification failed; history must not be trusted.", file=sys.stderr)
        return 1
    finally:
        if conn is not None:
            conn.close()


if __name__ == "__main__":
    sys.exit(main())
