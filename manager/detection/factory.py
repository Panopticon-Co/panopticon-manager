"""Builds a DetectionRun from the vendored engine, wired to manager storage.

This file used to hand-assemble eleven stateful engine objects, duplicating
wiring the manager does not own -- ADR 001 accepted that as the cost of keeping
the submodule a read-only consumer, and noted it would break loudly if the
engine's constructor changed.

It did, and the fix removed the duplication rather than repeating it: the
engine now owns its own composition in
``panopticon_detection.factory.build_detection_run``. The manager supplies only
what is genuinely manager-specific -- where alerts go.

``AlertSink`` is that piece: DetectionRun calls ``emit`` for every alert, and
here ``emit`` does exactly three things -- INSERT the alert row, append it to
``alerts.ndjson`` (the file the console reads), and create at most one
``response_actions`` row. The engine's ``Alert`` carries no ``agent_id``, so the
worker binds the current event's agent id onto the sink before each
``process_event`` call.
"""

from __future__ import annotations

import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import manager.vendor_path  # noqa: F401  (sys.path side effect, must precede engine imports)
from manager.detection import response
from manager.detection.store import insert_alert
from panopticon_detection.factory import DetectionContext
from panopticon_detection.factory import build_detection_run as build_engine_run
from panopticon_detection.reliability.alert_sink import IncrementalAlertWriter

# How much provenance history the graph keeps. A campaign traversal cannot
# reach past this, so it bounds both memory and how far back a root cause can
# be attributed. Deliberately longer than the engine's own campaign horizon.
GRAPH_RETENTION = timedelta(hours=24)


class AlertSink:
    """``emit`` target for DetectionRun: persist the alert, append it to the
    console's NDJSON file, then stage any response recommendation.
    ``agent_id`` is set per-event by the worker."""

    def __init__(self, conn: sqlite3.Connection, writer: IncrementalAlertWriter) -> None:
        self._conn = conn
        self._writer = writer
        self.agent_id: str | None = None

    def emit(self, alert: Any) -> None:
        inserted = insert_alert(self._conn, alert, agent_id=self.agent_id)
        self._writer.write(alert)
        if inserted:
            # Only for a genuinely new alert row -- a replayed/crash-recovered
            # duplicate (insert_alert returns False) must never produce a
            # second response_actions row for the same alert_id.
            response.on_alert_created(self._conn, alert)


def build_detection_run(
    conn: sqlite3.Connection,
    *,
    alerts_path: Path,
    rules_dir: Path,
) -> tuple[Any, AlertSink, IncrementalAlertWriter, DetectionContext]:
    """Construct a DetectionRun and its manager-side alert sink.

    Returns ``(run, sink, writer, context)``. The caller runs events through
    ``run.process_event(event)`` after setting ``sink.agent_id``, calls
    ``context.prune()`` periodically so the provenance graph stays bounded, and
    closes ``writer`` on shutdown.
    """
    writer = IncrementalAlertWriter(Path(alerts_path))
    sink = AlertSink(conn, writer)

    run, context = build_engine_run(
        Path(rules_dir),
        emit=sink.emit,
        retention=GRAPH_RETENTION,
    )
    return run, sink, writer, context


def prune_graph(context: DetectionContext) -> dict[str, int]:
    """Drop provenance older than :data:`GRAPH_RETENTION`.

    The graph is in-memory and grows with every event, so a long-running worker
    must call this. There is no background scheduler in Manager, so the worker
    does it on its own loop -- the same pattern
    ``expire_stale_response_actions`` uses.
    """
    return context.prune(datetime.now(timezone.utc).replace(tzinfo=None) - GRAPH_RETENTION)
