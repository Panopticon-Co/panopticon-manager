"""Builds a DetectionRun from the vendored engine, wired to manager storage.

DetectionRun's constructor takes 11 stateful engine objects with no factory of
its own upstream (``vendor/eyedetect/src/main.py`` is the only call site). Per
ADR 001 that wiring is duplicated here rather than added to the submodule, to
keep the manager a pure read-only consumer. If the engine's constructor
signature changes upstream, this file breaks loudly — that is the intended
trade-off.

The one manager-specific piece is ``AlertSink``: DetectionRun calls ``emit`` for
every alert it produces, and here ``emit`` does exactly two things — INSERT the
alert row and append it to ``alerts.ndjson`` (the file the console reads). The
engine's ``Alert`` carries no ``agent_id``, so the worker binds the current
event's agent id onto the sink before each ``process_event`` call.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Any

import manager.vendor_path  # noqa: F401  (sys.path side effect, must precede src.* imports)
from manager.detection.store import insert_alert
from src.cloud.cloud_engine import CloudThreatEngine
from src.correlation.correlation_engine import CorrelationEngine
from src.correlation.enterprise_graph import EnterpriseAttackGraph
from src.correlation.process_tree import ProcessTree
from src.correlation.risk_scorer import EntityRiskScorer
from src.evaluator.engine import RuleEvaluator
from src.evaluator.threshold import ThresholdEngine
from src.identity.ueba import IdentityAnalyticsEngine
from src.network.beacon_detector import C2BeaconDetector
from src.network.port_scanner import PortScanDetector
from src.pipeline_core import DetectionRun
from src.reliability.alert_sink import IncrementalAlertWriter
from src.remediation.engine import EndpointRemediationEngine
from src.remediation.ransomware_shield import RansomwareShield
from src.rules.loader import RuleLoader
from src.threat_intel.ioc_lookup import ThreatIntelEngine


class AlertSink:
    """``emit`` target for DetectionRun: persist the alert, then append it to
    the console's NDJSON file. ``agent_id`` is set per-event by the worker."""

    def __init__(self, conn: sqlite3.Connection, writer: IncrementalAlertWriter) -> None:
        self._conn = conn
        self._writer = writer
        self.agent_id: str | None = None

    def emit(self, alert: Any) -> None:
        insert_alert(self._conn, alert, agent_id=self.agent_id)
        self._writer.write(alert)


def build_detection_run(
    conn: sqlite3.Connection,
    *,
    alerts_path: Path,
    rules_dir: Path,
) -> tuple[DetectionRun, AlertSink, IncrementalAlertWriter]:
    """Construct a DetectionRun and its manager-side alert sink.

    Returns ``(run, sink, writer)``. The caller runs events through
    ``run.process_event(event)``, setting ``sink.agent_id`` first, and closes
    ``writer`` on shutdown.
    """
    rules = RuleLoader().load_directory(Path(rules_dir))

    threat_intel = ThreatIntelEngine()
    process_tree = ProcessTree()
    evaluator = RuleEvaluator(rules, process_tree=process_tree, threat_intel=threat_intel)
    threshold_engine = ThresholdEngine()
    correlation_engine = CorrelationEngine()
    risk_scorer = EntityRiskScorer(breach_threshold=75)
    beacon_detector = C2BeaconDetector(min_samples=4, max_cv_threshold=0.22)
    port_scan_detector = PortScanDetector(horizontal_ip_threshold=5, vertical_port_threshold=6)
    ransomware_shield = RansomwareShield(burst_threshold=4, burst_window_seconds=5.0)
    identity_engine = IdentityAnalyticsEngine(brute_force_threshold=5, spray_account_threshold=4)
    cloud_engine = CloudThreatEngine()
    enterprise_graph = EnterpriseAttackGraph()
    # dry_run=True: EndpointRemediationEngine makes no real syscall either way
    # (no os.kill / subprocess / winreg / socket anywhere in it), but now that
    # live endpoint telemetry drives detection, "inert" needs to be legible at
    # the call site, not something a reader has to go and verify. A roadmap
    # phase flips this deliberately when real containment is in scope.
    remediation_engine = EndpointRemediationEngine(dry_run=True)

    writer = IncrementalAlertWriter(Path(alerts_path))
    sink = AlertSink(conn, writer)

    run = DetectionRun(
        evaluator=evaluator,
        threshold_engine=threshold_engine,
        correlation_engine=correlation_engine,
        risk_scorer=risk_scorer,
        beacon_detector=beacon_detector,
        port_scan_detector=port_scan_detector,
        ransomware_shield=ransomware_shield,
        identity_engine=identity_engine,
        cloud_engine=cloud_engine,
        enterprise_graph=enterprise_graph,
        remediation_engine=remediation_engine,
        auto_remediate=True,
        emit=sink.emit,
        emit_remediation=lambda _report: None,
    )
    return run, sink, writer
