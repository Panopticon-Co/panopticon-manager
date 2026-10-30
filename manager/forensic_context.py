"""Connect pure forensic planning to existing requests and retained signed evidence."""

import json
from datetime import datetime

from fastapi import HTTPException
from pydantic import ValidationError
from response_engine.forensics import (
    EvidenceExpectation,
    ForensicCollectionPolicy,
    ForensicCollectionRequest,
    plan_forensic_collection,
    validate_evidence_metadata,
)
from response_engine.triage import COLLECT_ACTIONS

from manager.artifact_keys import record
from manager.response_profile import current_profile
from manager.timeutil import iso_now
from manager.triage_store import asset_for

POLICY = ForensicCollectionPolicy(
    policy_id="forensic-context-v1", version=1, enabled=True, require_approval=[],
)


def install(conn):
    conn.execute("""CREATE TABLE response_forensic_plans (
        response_id TEXT PRIMARY KEY REFERENCES response_actions(response_id),
        plan_json TEXT NOT NULL, actor TEXT NOT NULL, created_at TEXT NOT NULL)""")
    for operation in ("UPDATE", "DELETE"):
        conn.execute(f"""CREATE TRIGGER forensic_plan_no_{operation.lower()}
            BEFORE {operation} ON response_forensic_plans
            BEGIN SELECT RAISE(ABORT,'forensic plan is immutable'); END""")


def capture_plan(conn, response_id, actor):
    """Retain an advisory snapshot without minting a second authorization path."""
    if conn.execute("SELECT 1 FROM response_forensic_plans WHERE response_id=?",
                    (response_id,)).fetchone():
        return
    row = conn.execute(
        "SELECT ra.action,ra.target_json,a.* FROM response_actions ra "
        "JOIN alerts a ON a.alert_id=ra.alert_id WHERE ra.response_id=?", (response_id,),
    ).fetchone()
    if row is None or row["action"] not in COLLECT_ACTIONS:
        return
    value = {"schema_version": "1", "state": "unavailable",
             "reason": "Retained alert lacks complete forensic provenance "
                       "or native target context."}
    try:
        alert = json.loads(row["alert_json"])
        context = alert.get("endpoint_context") or {}
        provenance = context.get("provenance") or {}
        source = (provenance.get("provider") or provenance.get("kind")
                  or alert.get("detection_source"))
        source_record = context.get("record_id") or row["event_id"]
        observed = context.get("observed_at") or row["alert_timestamp"]
        if not source or not source_record or not observed:
            raise ValueError("original source identifiers and timestamp required")
        target = json.loads(row["target_json"])
        fields = {}
        if row["action"] == "COLLECT_PROCESS_INFO":
            fields["process"] = {
                "pid": target.get("pid"),
                "start_time_ticks": int(target["start_time_ticks"])
                if isinstance(target.get("start_time_ticks"), str)
                else target.get("start_time_ticks"),
            }
            if "boot_id" in target:
                fields["process"]["boot_id"] = target["boot_id"]
        if row["action"] == "COLLECT_FILE":
            report = current_profile(conn, row["agent_id"], row["host_id"])["report"]
            if not report:
                raise ValueError("endpoint platform is not reported")
            fields["file"] = {"platform": report["platform"], "path": target.get("path")}
        request = ForensicCollectionRequest.model_validate({
            "request_id": response_id, "action": row["action"], **fields,
            "context": {"alert_id": row["alert_id"], "agent_id": row["agent_id"],
                        "host_id": row["host_id"], "rule_id": row["rule_id"],
                        "source_id": source, "source_record_id": source_record,
                        "observed_at": datetime.fromisoformat(observed.replace("Z", "+00:00"))},
        })
        asset, version = asset_for(conn, row["host_id"])
        plan = plan_forensic_collection(request, POLICY, asset_class=asset)
        value = {"schema_version": "1", "state": "planned", "plan": plan.model_dump(mode="json"),
                 "asset_classification_version": version,
                 "advisory_only": True,
                 "notice": "Forensic context is advisory. Existing response approval and explicit "
                           "versioned auto-triage policy remain the execution authority."}
    except (ValueError, TypeError, AttributeError, KeyError):
        # Never fabricate provenance for legacy alerts or lose the original response.
        # Missing context does not imply approval or endpoint execution readiness.
        pass
    conn.execute("INSERT INTO response_forensic_plans VALUES (?,?,?,?)",
                 (response_id, json.dumps(value, sort_keys=True), actor, iso_now()))
    record(conn, "forensic_collection_planned", actor, row["host_id"], response_id,
           {"state": value["state"], "policy_id": POLICY.policy_id,
            "policy_version": POLICY.version, "alert_id": row["alert_id"],
            "action": row["action"], "advisory_only": True, "context": value})


def validate_retained_manifest(conn, manifest, command_id):
    """Pure metadata check bound to the persisted command; no duplicate crypto/storage."""
    command = conn.execute("SELECT agent_id,command_json FROM commands WHERE command_id=?",
                           (command_id,)).fetchone()
    if command is None:
        raise HTTPException(422, "evidence command is not retained")
    payload = json.loads(command["command_json"])
    if payload["action"] not in COLLECT_ACTIONS:
        return None  # Preserve the existing separate execution-report semantics.
    kind = manifest.get("kind") if isinstance(manifest, dict) else manifest.kind
    if kind == "execution_report":
        # Existing signed admission verifies these reports and their command binding.
        # They are not process/network/file snapshots understood by the pure planner.
        return None
    try:
        return validate_evidence_metadata(manifest, expected=EvidenceExpectation(
            action=payload["action"], agent_id=command["agent_id"], host_id=payload["host_id"],
            command_id=command_id, correlation_id=payload["correlation_id"],
        ))
    except (ValueError, ValidationError) as exc:
        raise HTTPException(
            422, "forensic evidence metadata does not match retained command",
        ) from exc


def case_context(conn, row):
    """Caller must already enforce the live credential/case/endpoint grant."""
    saved = conn.execute("SELECT plan_json FROM response_forensic_plans WHERE response_id=?",
                         (row["response_id"],)).fetchone()
    if row["action"] not in COLLECT_ACTIONS:
        return None
    value = json.loads(saved[0]) if saved else {
        "schema_version": "1", "state": "legacy_without_plan",
        "reason": "This response predates forensic plan capture; no historical plan is invented.",
    }
    if saved:
        original = conn.execute(
            "SELECT detail FROM response_security_audit WHERE request_id=? "
            "AND event='forensic_collection_planned' ORDER BY rowid LIMIT 1",
            (row["response_id"],),
        ).fetchone()
        if not original or json.loads(original[0]).get("context") != value:
            value = {"schema_version": "1", "state": "inconsistent_plan",
                     "reason": "Stored forensic context disagrees with its immutable audit fact."}
    references = []
    if row["command_id"]:
        manifests = conn.execute(
            "SELECT a.manifest_json,a.verified_at,k.compromised_at,k.retired_at,k.key_version "
            "FROM artifact_manifest_attestations a JOIN response_artifacts e "
            "ON e.artifact_id=a.artifact_id JOIN artifact_signing_keys k "
            "ON k.agent_id=a.agent_id AND k.key_id=a.key_id WHERE e.command_id=? "
            "ORDER BY e.received_at,e.artifact_id LIMIT 32", (row["command_id"],),
        ).fetchall()
        for entry in manifests:
            original = json.loads(entry["manifest_json"])
            try:
                validated = validate_retained_manifest(conn, original, row["command_id"])
            except HTTPException:
                references.append({"artifact_id": original.get("artifact_id"),
                                   "metadata_status": "inconsistent", "content_available": False})
                continue
            if validated:
                references.append({"manifest": validated.model_dump(),
                                   "metadata_status": "consistent_with_retained_command",
                                   "verified_at": entry["verified_at"],
                                   "key_version": entry["key_version"],
                                   "trust_status": "compromised_key" if entry["compromised_at"]
                                   else "retired_key" if entry["retired_at"] else "active_key",
                                   "content_requires_verified_retrieval": True})
    process = value.get("plan", {}).get("request", {}).get("process")
    native_process_identity = None
    if process:
        native_process_identity = {**process, "start_time_ticks": str(process["start_time_ticks"])}
    return {**value, "evidence_references": references,
            "native_process_identity": native_process_identity,
            "effective_response_tier": row["tier"], "response_origin": row["origin"],
            "content_verification": "Use the existing signed-manifest/hash verification and "
                                    "custody path before viewing or downloading bytes."}
