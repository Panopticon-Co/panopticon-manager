"""Manager configuration: where the database lives, what host/port to bind,
where alerts are written, and where detection rules load from.

Still deliberately minimal — no auth or delivery tuning yet. Later phases extend
this dataclass rather than replacing it.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

# vendor/eyedetect/rules — the pinned submodule's rule set. Resolved relative to
# this file so it works regardless of the process's working directory.
_DEFAULT_RULES_DIR = Path(__file__).resolve().parent.parent / "vendor" / "eyedetect" / "rules"


@dataclass(frozen=True)
class ManagerConfig:
    db_path: Path = Path("panopticon.db")
    host: str = "0.0.0.0"
    port: int = 8000
    alerts_path: Path = Path("alerts.ndjson")
    rules_dir: Path = _DEFAULT_RULES_DIR


def load() -> ManagerConfig:
    """Load config from environment, falling back to defaults.

    Env vars: PANOPTICON_DB_PATH, PANOPTICON_HOST, PANOPTICON_PORT,
    PANOPTICON_ALERTS_PATH, PANOPTICON_RULES_DIR.
    """
    return ManagerConfig(
        db_path=Path(os.environ.get("PANOPTICON_DB_PATH", "panopticon.db")),
        host=os.environ.get("PANOPTICON_HOST", "0.0.0.0"),
        port=int(os.environ.get("PANOPTICON_PORT", "8000")),
        alerts_path=Path(os.environ.get("PANOPTICON_ALERTS_PATH", "alerts.ndjson")),
        rules_dir=Path(os.environ.get("PANOPTICON_RULES_DIR", str(_DEFAULT_RULES_DIR))),
    )
