"""Puts vendor/eyedetect on sys.path so ``from panopticon_detection.X import Y`` resolves to the
vendored detection engine's own package (``panopticon_detection``) — the same import spelling
the engine uses internally (e.g. ``cli.py`` does ``from
panopticon_detection.alerting.alert import Alert``). Imported once, before any eyedetect import.

Every module that needs engine internals should ``import manager.vendor_path``
(for its side effect) before importing anything from ``panopticon_detection``, rather than
reaching into ``vendor/`` with a relative path — this is the one place the
manager touches the submodule's layout, per ADR 001.
"""

from __future__ import annotations

import sys
from pathlib import Path

_VENDOR_ROOT = Path(__file__).resolve().parent.parent / "vendor" / "eyedetect"

if str(_VENDOR_ROOT) not in sys.path:
    sys.path.insert(0, str(_VENDOR_ROOT))
