"""Builds a DetectionRun from the vendored engine.

Stub for Phase 0 — filled in during Phase 3. DetectionRun's constructor takes
11 required keyword-only stateful engine args with no factory of its own in
vendor/eyedetect (main.py is the only call site there); per ADR 001 that
wiring is intentionally duplicated here rather than added upstream, to keep
the manager a pure, read-only consumer of the submodule.
"""

from __future__ import annotations

import manager.vendor_path  # noqa: F401


def build_detection_run():
    """Construct a DetectionRun with its full engine graph. Not yet implemented — Phase 3."""
    raise NotImplementedError("DetectionRun wiring lands in Phase 3")
