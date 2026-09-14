"""The detection worker: one dedicated thread, events-table-as-queue.

Per ADR 003 this is the only code path in the process allowed to touch
``DetectionRun``. Ingest writes ``events`` rows with ``detect_state='pending'``;
this thread claims a bounded batch under ``BEGIN IMMEDIATE``, normalizes each
event and runs it through the engine, and marks it ``done`` (or ``failed``, on a
rule bug — which must poison exactly one event, never the claim loop).

The claim/lease/revert-on-crash design is new engineering, not a reuse of the
engine's ``AlertSpool`` (ADR 003 is explicit about that), so it has its own
tests: claim→done, single-event poisoning, and stale-lease recovery.
"""

from __future__ import annotations

import json
import logging
import sqlite3
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path

import manager.vendor_path  # noqa: F401  (sys.path side effect, must precede engine imports)
from manager.detection.factory import build_detection_run, prune_graph
from manager.timeutil import iso_at, iso_now
from panopticon_detection.ingestion.officer_adapter import OfficerIngestionAdapter

_log = logging.getLogger("manager.detection.worker")

CLAIM_LIMIT = 256
LEASE_SECONDS = 60
PRUNE_EVERY_IDLE_ROUNDS = 60
IDLE_SLEEP_SECONDS = 1.0


class DetectionWorker:
    """Runs the claim → detect → mark loop on its own thread and connection."""

    def __init__(
        self, *, db_path: str | Path, alerts_path: str | Path, rules_dir: str | Path
    ) -> None:
        self._db_path = str(db_path)
        self._alerts_path = Path(alerts_path)
        self._rules_dir = Path(rules_dir)
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._run, name="detection-worker", daemon=True)
        self._started = False

    # -- lifecycle -----------------------------------------------------
    def start(self) -> None:
        self._started = True
        self._thread.start()

    def stop(self, timeout: float = 10.0) -> None:
        self._stop.set()
        if self._started:
            self._thread.join(timeout)

    def _run(self) -> None:
        conn = self.open_connection()
        run, sink, writer, context = build_detection_run(
            conn, alerts_path=self._alerts_path, rules_dir=self._rules_dir
        )
        _log.info("detection worker started (rules=%s)", self._rules_dir)
        try:
            self.revert_stale_claims(conn)
            idle_rounds = 0
            while not self._stop.is_set():
                if self.run_once(conn, run, sink) == 0:
                    # The provenance graph is in-memory and grows with every
                    # event. There is no background scheduler here, so prune on
                    # the idle path -- the same place the queue is quiet and the
                    # same pattern expire_stale_response_actions uses.
                    idle_rounds += 1
                    if idle_rounds >= PRUNE_EVERY_IDLE_ROUNDS:
                        idle_rounds = 0
                        dropped = prune_graph(context)
                        if dropped["edges_removed"] or dropped["processes_removed"]:
                            _log.info("pruned provenance: %s", dropped)
                    self._stop.wait(IDLE_SLEEP_SECONDS)
                else:
                    idle_rounds = 0
        finally:
            writer.close()
            conn.close()
            _log.info("detection worker stopped")

    # -- connection --------------------------------------------------
    def open_connection(self) -> sqlite3.Connection:
        """A fresh connection with ADR-003 pragmas, for the calling thread."""
        conn = sqlite3.connect(self._db_path, check_same_thread=True)
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")
        conn.execute("PRAGMA busy_timeout=5000")
        conn.execute("PRAGMA foreign_keys=ON")
        conn.row_factory = sqlite3.Row
        return conn

    # -- steps (separately testable) --------------------------------
    def revert_stale_claims(self, conn: sqlite3.Connection) -> int:
        """On startup, any row still ``claimed`` past the lease reverts to
        ``pending`` — free crash recovery. Returns how many were reverted."""
        cutoff = iso_at(datetime.now(timezone.utc) - timedelta(seconds=LEASE_SECONDS))
        conn.execute("BEGIN IMMEDIATE")
        try:
            n = conn.execute(
                "UPDATE events SET detect_state='pending', claimed_at=NULL "
                "WHERE detect_state='claimed' AND (claimed_at IS NULL OR claimed_at < ?)",
                (cutoff,),
            ).rowcount
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        if n:
            _log.info("reverted %d stale claimed event(s) to pending", n)
        return n

    def claim_batch(self, conn: sqlite3.Connection) -> list[sqlite3.Row]:
        """Claim up to ``CLAIM_LIMIT`` pending events in one transaction."""
        conn.execute("BEGIN IMMEDIATE")
        try:
            rows = conn.execute(
                "SELECT event_id, agent_id, raw_json FROM events "
                "WHERE detect_state='pending' "
                "ORDER BY event_timestamp, event_id LIMIT ?",
                (CLAIM_LIMIT,),
            ).fetchall()
            if rows:
                claimed_at = iso_now()
                conn.executemany(
                    "UPDATE events SET detect_state='claimed', claimed_at=? WHERE event_id=?",
                    [(claimed_at, r["event_id"]) for r in rows],
                )
            conn.commit()
            return rows
        except Exception:
            conn.rollback()
            raise

    def process_claimed(self, conn, run, sink, rows: list[sqlite3.Row]) -> None:
        """Run each claimed event through the engine. A failure on one event
        marks that one ``failed`` and moves on — it never breaks the loop."""
        for row in rows:
            event_id = row["event_id"]
            try:
                event = self._normalize(row["raw_json"])
                sink.agent_id = row["agent_id"]
                conn.execute("BEGIN IMMEDIATE")
                run.process_event(event)  # emit -> insert_alert + alerts.ndjson
                conn.execute("UPDATE events SET detect_state='done' WHERE event_id=?", (event_id,))
                conn.commit()
            except Exception:
                self._mark_failed(conn, event_id)

    def run_once(self, conn: sqlite3.Connection, run, sink) -> int:
        """One claim + process cycle. Returns the number of events claimed."""
        rows = self.claim_batch(conn)
        if rows:
            self.process_claimed(conn, run, sink, rows)
        return len(rows)

    # -- helpers ---------------------------------------------------
    @staticmethod
    def _normalize(raw_json: str) -> dict:
        raw = json.loads(raw_json)
        if (
            isinstance(raw, dict)
            and isinstance(raw.get("event"), dict)
            and OfficerIngestionAdapter.is_officer_event(raw)
        ):
            return OfficerIngestionAdapter.transform_officer_event(raw)
        return raw

    def _mark_failed(self, conn: sqlite3.Connection, event_id: str) -> None:
        try:
            conn.rollback()
        except sqlite3.Error:
            pass
        _log.exception("detection failed for event_id=%s", event_id)
        conn.execute("BEGIN IMMEDIATE")
        try:
            conn.execute(
                "UPDATE events SET detect_state='failed', "
                "detect_attempts = detect_attempts + 1 WHERE event_id=?",
                (event_id,),
            )
            conn.commit()
        except Exception:
            conn.rollback()
            raise
