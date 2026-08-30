"""Puts vendor/eyedetect on sys.path so ``from src.X import Y`` resolves to the
vendored detection engine's own package (``src``) — the same import spelling
the engine uses internally (e.g. ``src/main.py`` does ``from
src.alerting.alert import Alert``). Imported once, before any eyedetect import.

Every module that needs engine internals should ``import manager.vendor_path``
(for its side effect) before importing anything from ``src``, rather than
reaching into ``vendor/`` with a relative path — this is the one place the
manager touches the submodule's layout, per ADR 001.
"""

from __future__ import annotations

import sys
from pathlib import Path

_VENDOR_ROOT = Path(__file__).resolve().parent.parent / "vendor" / "eyedetect"

if str(_VENDOR_ROOT) not in sys.path:
    sys.path.insert(0, str(_VENDOR_ROOT))
