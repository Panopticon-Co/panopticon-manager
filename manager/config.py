"""Manager configuration: where the database lives, what host/port to bind.

Deliberately minimal for Phase 0 — no auth, no rule directories, no delivery
tuning yet. Later phases extend this dataclass rather than replacing it.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class ManagerConfig:
    db_path: Path = Path("panopticon.db")
    host: str = "0.0.0.0"
    port: int = 8000


def load() -> ManagerConfig:
    """Load config from environment, falling back to defaults.

    Env vars: PANOPTICON_DB_PATH, PANOPTICON_HOST, PANOPTICON_PORT.
    """
    return ManagerConfig(
        db_path=Path(os.environ.get("PANOPTICON_DB_PATH", "panopticon.db")),
        host=os.environ.get("PANOPTICON_HOST", "0.0.0.0"),
        port=int(os.environ.get("PANOPTICON_PORT", "8000")),
    )
