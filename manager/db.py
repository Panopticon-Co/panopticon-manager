"""SQLite connection factory. One connection per thread, no ORM — matches the
style already established in vendor/eyedetect/src/reliability/spool.py.

Pragmas are non-negotiable per ADR 003: WAL journaling, NORMAL sync, a 5s busy
timeout so concurrent writers block briefly instead of raising "database is
locked", and foreign keys enforced.
"""

from __future__ import annotations

import sqlite3
import threading
from pathlib import Path

_local = threading.local()
_db_path: Path | None = None


def configure(path: Path) -> None:
    """Set the database file path. Call once, at startup, before any connect()."""
    global _db_path
    _db_path = path
    _db_path.parent.mkdir(parents=True, exist_ok=True)


def connect() -> sqlite3.Connection:
    """Return this thread's connection, opening one on first use."""
    conn = getattr(_local, "conn", None)
    if conn is not None:
        return conn
    if _db_path is None:
        raise RuntimeError("manager.db.configure() must be called before connect()")
    conn = sqlite3.connect(_db_path, check_same_thread=True)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    conn.execute("PRAGMA busy_timeout=5000")
    conn.execute("PRAGMA foreign_keys=ON")
    conn.row_factory = sqlite3.Row
    _local.conn = conn
    return conn
