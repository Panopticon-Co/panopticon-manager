"""One verification path for signed package, context and resumable evidence reads."""

import base64
import hashlib
import json

from fastapi import HTTPException
from response_engine.artifacts import artifact_signing_input

from manager import response_artifacts as store
from manager.artifact_keys import retained_status, verify_signature


class EvidenceRefusal(HTTPException):
    def __init__(self, status, message, event, actor, detail=None):
        super().__init__(status, message)
        self.event = event
        self.actor = actor
        self.evidence_detail = detail or {}


def verified(conn, row, analyst, *, allow_compromised=False):
    artifact_id = row["artifact_id"]
    signing = retained_status(conn, artifact_id)
    if signing["trust_status"] == "unsigned_legacy":
        raise EvidenceRefusal(
            410,
            "unsigned legacy evidence is preserved but cannot be downloaded",
            "retrieval_blocked_unsigned_legacy",
            "analyst:" + analyst,
        )
    if signing["trust_status"] == "compromised_key" and not allow_compromised:
        raise EvidenceRefusal(
            403,
            "artifact signer is compromised; evidence preserved for review",
            "retrieval_blocked_compromised_key",
            "analyst:" + analyst,
            {"key_id": signing["key_id"]},
        )
    data = bytes(row["content"])
    if len(data) != row["content_bytes"] or hashlib.sha256(data).hexdigest() != row["sha256"]:
        raise EvidenceRefusal(
            503,
            "artifact integrity check failed; original retained for investigation",
            "integrity_check_failed",
            "system:artifact-store",
        )
    attestation = conn.execute(
        "SELECT manifest_json,key_id,key_version,agent_id FROM artifact_manifest_attestations "
        "WHERE artifact_id=?",
        (artifact_id,),
    ).fetchone()
    try:
        manifest = json.loads(attestation["manifest_json"])
        digest = hashlib.sha256(store.canonical(manifest).encode()).hexdigest()
        verification = conn.execute(
            "SELECT detail FROM response_artifact_custody "
            "WHERE artifact_id=? AND event='artifact_signature_verified' ORDER BY sequence LIMIT 1",
            (artifact_id,),
        ).fetchone()
        valid = (
            verification is not None
            and json.loads(verification["detail"]).get("manifest_sha256") == digest
            and all(
                manifest[field] == row[field]
                for field in (
                    "artifact_id",
                    "agent_id",
                    "command_id",
                    "correlation_id",
                    "host_id",
                    "kind",
                    "media_type",
                    "content_bytes",
                    "sha256",
                )
            )
            and manifest["authorization"]["key_id"] == signing["key_id"] == attestation["key_id"]
            and attestation["agent_id"] == row["agent_id"]
            and attestation["key_version"] == signing["key_version"]
            and verify_signature(
                signing["public_key"],
                manifest["authorization"]["signature"],
                artifact_signing_input(manifest),
            )
        )
    except (ValueError, KeyError, TypeError, AttributeError):
        valid = False
    if not valid:
        raise EvidenceRefusal(
            503,
            "artifact manifest integrity failed; evidence preserved",
            "integrity_check_failed",
            "system:artifact-verifier",
            {"kind": "signed_manifest"},
        )
    return data, manifest, signing, digest


def package(data, manifest, signing):
    return {
        "manifest": manifest,
        "content_base64": base64.b64encode(data).decode(),
        "signing_key": signing,
    }
