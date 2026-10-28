"""One dedicated detection thread over durable legacy and canonical queues.

Per ADR 003 this is the only code path in the process allowed to touch
``DetectionRun``. Ingest writes ``events`` or ``endpoint_records`` rows pending;
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
from manager.detection.linux_mapper import to_engine_event
from response_engine.linux_identity import linux_endpoint_context
from manager.timeutil import iso_at, iso_now
from panopticon_detection.ingestion.endpoint_adapter import EndpointIngestionAdapter
from panopticon_detection.ingestion.officer_adapter import OfficerIngestionAdapter

_log = logging.getLogger("manager.detection.worker")

CLAIM_LIMIT = 256
LEASE_SECONDS = 60
PRUNE_EVERY_IDLE_ROUNDS = 60
PRUNE_EVERY_EVENTS = 10_000
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
        self._idle_rounds = 0
        self._events_since_prune = 0

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
            while not self._stop.is_set():
                claimed = self.run_once(conn, run, sink)
                self.maybe_prune(context, claimed)
                if claimed == 0:
                    self._stop.wait(IDLE_SLEEP_SECONDS)
        finally:
            writer.close()
            conn.close()
            _log.info("detection worker stopped")

    # -- connection --------------------------------------------------
    def open_connection(self) -> sqlite3.Connection:
        """A fresh connection with ADR-003 pragmas, for the calling thread."""
        conn = sqlite3.connect(self._db_path, check_same_thread=True)
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=FULL")
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
            n += conn.execute(
                "UPDATE endpoint_records SET detect_state='pending', claimed_at=NULL "
                "WHERE detect_state='claimed' AND (claimed_at IS NULL OR claimed_at < ?)",
                (cutoff,),
            ).rowcount
            n += conn.execute(
                "UPDATE linux_endpoint_detection SET state='pending',claimed_at=NULL "
                "WHERE state='claimed' AND (claimed_at IS NULL OR claimed_at < ?)",
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
        """Claim a bounded batch with capacity for each protocol, atomically."""
        conn.execute("BEGIN IMMEDIATE")
        try:
            legacy = conn.execute(
                "SELECT event_id, agent_id, raw_json, 'legacy' AS queue FROM events "
                "WHERE detect_state='pending' "
                # Ties on event time keep arrival order (rowid), not event_id
                # order: the agent reports a process creation via ETW (with
                # start_time_ticks) just before Sysmon (with the command line),
                # often in the same millisecond, and the engine attaches the
                # ETW twin's ticks to the Sysmon detection only if it saw the
                # twin first. An event_id tie-break is a hash -- arbitrary.
                "ORDER BY event_timestamp, rowid LIMIT ?",
                (CLAIM_LIMIT,),
            ).fetchall()
            canonical = conn.execute(
                "SELECT record_id AS event_id, agent_id, raw_json, 'endpoint' AS queue "
                "FROM endpoint_records WHERE detect_state='pending' "
                "ORDER BY ingested_at,agent_id,record_id LIMIT ?",
                (CLAIM_LIMIT,),
            ).fetchall()
            linux = conn.execute(
                "SELECT r.record_id AS event_id,r.agent_id,r.raw_json,'linux' AS queue "
                "FROM linux_endpoint_detection d JOIN linux_endpoint_records r "
                "ON r.agent_id=d.agent_id AND r.record_id=d.record_id "
                "WHERE d.state='pending' ORDER BY r.ingested_at,r.rowid LIMIT ?",
                (CLAIM_LIMIT,),
            ).fetchall()
            # Share bounded capacity across active protocols; refill spare slots.
            queues = [legacy, canonical, linux]
            take = [0, 0, 0]
            remaining = CLAIM_LIMIT
            while remaining:
                changed = False
                for i, queue in enumerate(queues):
                    if remaining and take[i] < len(queue):
                        take[i] += 1
                        remaining -= 1
                        changed = True
                if not changed:
                    break
            rows = [row for queue, count in zip(queues, take) for row in queue[:count]]
            if rows:
                claimed_at = iso_now()
                conn.executemany(
                    "UPDATE events SET detect_state='claimed', claimed_at=? WHERE event_id=?",
                    [(claimed_at, r["event_id"]) for r in rows if r["queue"] == "legacy"],
                )
                conn.executemany(
                    "UPDATE endpoint_records SET detect_state='claimed', claimed_at=? "
                    "WHERE agent_id=? AND record_id=?",
                    [
                        (claimed_at, r["agent_id"], r["event_id"])
                        for r in rows
                        if r["queue"] == "endpoint"
                    ],
                )
                conn.executemany(
                    "UPDATE linux_endpoint_detection SET state='claimed',claimed_at=? "
                    "WHERE agent_id=? AND record_id=?",
                    [
                        (claimed_at, r["agent_id"], r["event_id"])
                        for r in rows
                        if r["queue"] == "linux"
                    ],
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
                sink.linux_context = None
                if row["queue"] == "linux":
                    raw = json.loads(row["raw_json"])
                    # Invalid native identity still carries an explicit context:
                    # response translation must never fall back to a legacy PID.
                    sink.linux_context = linux_endpoint_context(raw, row["agent_id"]) or {
                        "identity_model": "linux_endpoint_v1",
                        "record_id": raw["id"],
                        "endpoint": {"agent_id": row["agent_id"], "host_id": raw["host"]["id"]},
                        "subject": {},
                    }
                    sink.linux_context["provenance"] = raw.get("provenance", {})
                conn.execute("BEGIN IMMEDIATE")
                run.process_event(event)  # emit -> insert_alert + alerts.ndjson
                if row["queue"] == "endpoint":
                    conn.execute(
                        "UPDATE endpoint_records SET detect_state='done',claimed_at=NULL "
                        "WHERE agent_id=? AND record_id=?",
                        (row["agent_id"], event_id),
                    )
                elif row["queue"] == "linux":
                    conn.execute(
                        "UPDATE linux_endpoint_detection SET state='done',claimed_at=NULL "
                        "WHERE agent_id=? AND record_id=?",
                        (row["agent_id"], event_id),
                    )
                else:
                    conn.execute(
                        "UPDATE events SET detect_state='done' WHERE event_id=?", (event_id,)
                    )
                conn.commit()
            except Exception:
                self._mark_failed(conn, event_id, agent_id=row["agent_id"], queue=row["queue"])

    def maybe_prune(self, context, claimed: int) -> dict[str, int] | None:
        """Prune detection state after a quiet spell or a volume of events,
        whichever comes first. Returns what was dropped, or None if skipped.

        Detection state is in-memory and grows with every event, and there is
        no background scheduler. Pruning only on the idle path meant a worker
        under sustained load -- exactly when state grows fastest -- never pruned.
        """
        if claimed:
            self._idle_rounds = 0
            self._events_since_prune += claimed
        else:
            self._idle_rounds += 1

        if (
            self._events_since_prune < PRUNE_EVERY_EVENTS
            and self._idle_rounds < PRUNE_EVERY_IDLE_ROUNDS
        ):
            return None

        self._idle_rounds = 0
        self._events_since_prune = 0
        dropped = prune_graph(context)
        if any(dropped.values()):
            _log.info("pruned detection state: %s", dropped)
        return dropped

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
        if isinstance(raw, dict) and raw.get("record_type") and raw.get("schema_version") == "1.0":
            event = to_engine_event(raw)
            if event is None:
                raise ValueError("Linux record is not a detectable process event")
            return event
        if EndpointIngestionAdapter.is_endpoint_record(raw):
            return EndpointIngestionAdapter.transform(raw)
        if (
            isinstance(raw, dict)
            and isinstance(raw.get("event"), dict)
            and OfficerIngestionAdapter.is_officer_event(raw)
        ):
            return OfficerIngestionAdapter.transform_officer_event(raw)
        return raw

    def _mark_failed(
        self, conn: sqlite3.Connection, event_id: str, *, agent_id=None, queue="legacy"
    ) -> None:
        try:
            conn.rollback()
        except sqlite3.Error:
            pass
        _log.exception("detection failed for event_id=%s", event_id)
        conn.execute("BEGIN IMMEDIATE")
        try:
            if queue == "endpoint":
                conn.execute(
                    "UPDATE endpoint_records SET detect_state='failed',claimed_at=NULL, "
                    "detect_attempts=detect_attempts+1 WHERE agent_id=? AND record_id=?",
                    (agent_id, event_id),
                )
            elif queue == "linux":
                conn.execute(
                    "UPDATE linux_endpoint_detection SET state='failed',claimed_at=NULL, "
                    "attempts=attempts+1 WHERE agent_id=? AND record_id=?",
                    (agent_id, event_id),
                )
            else:
                conn.execute(
                    "UPDATE events SET detect_state='failed', "
                    "detect_attempts = detect_attempts + 1 WHERE event_id=?",
                    (event_id,),
                )
            conn.commit()
        except Exception:
            conn.rollback()
            raise
