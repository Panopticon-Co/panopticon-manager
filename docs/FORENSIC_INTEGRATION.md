# Forensic collection context in Manager and Console

Migration 33 captures immutable advisory forensic plans for new response requests
using the response library's `ForensicCollectionRequest`, version-1
`ForensicCollectionPolicy` and `plan_forensic_collection`. This hooks the existing
response staging writer, so manual, detection and triage collection requests share
the same context path. Plans refer to the original alert, endpoint, source record,
source provider/kind, observation time, rule and native process or exact file
target. No source identifiers, evidence hashes, wall-clock replacements or native
identity tokens are manufactured. Missing legacy provenance/platform is explicitly
labelled unavailable; earlier responses are labelled legacy_without_plan rather
than reconstructed as historical facts.

The plan is explanatory, not an authorization token. Existing manual requests
still require approval. Execution authority remains the existing server-side
response tier or an explicit versioned collection-only auto-triage policy with
its path allowlist, capability and budget checks. The forensic library's base
file-collection approval tier is not an implicit automation grant. Critical and
unclassified triage assets still cannot auto-execute. No new endpoint behavior,
action or script is added; COLLECT_FILE stays metadata/hash JSON only.

The whole planning snapshot is also recorded through the existing chained
response_security_audit writer, atomically with the response. Updates/deletes of
the snapshot are forbidden. Case serialization compares a retained snapshot with
its immutable audit fact; a disagreement exposes inconsistent_plan instead of the
untrusted plan. Replayed request identities reuse their existing snapshot/audit.

Signed artifact admission calls `validate_evidence_metadata` against the persisted
command's action, agent, host, command and correlation identifiers. It reuses the
existing signed manifest model and verifies SHA-256 representation and kind/scope
agreement. Existing Manager verification still handles enrollment/key history,
signature authenticity, exact-byte hashing, size limits, resumable transfer,
storage and custody. No duplicate evidence store or cryptographic verifier exists.
The new forensic_metadata_validated audit event is appended only on first accepted
retention; a failed audit rolls back retention, and exact retries create no extra
event. Execution reports retain their existing separate semantics.

Individual case exports include forensic_context only with the same live
credential-bound case/endpoint grant used for evidence. This also allows scoped
planning inspection before a command exists. Shared Console views remove the
entire forensic context even if their configured server token has evidence scope.
The individual evidence dialog displays original context, exact native identity,
effective response tier and linked evidence/trust status through literal text.
Native ticks have an explicit decimal-string `native_process_identity` view so
JavaScript cannot round uint64 identity tokens; consumers should use that view
rather than converting the advisory domain snapshot's integer fields to floats.

Artifact references retain original signed manifest metadata and verification
time. Current key status is read from retained history on each case read;
compromised-key evidence stays flagged and retained, while ordinary content
retrieval remains refused by the existing verifier. A consistent metadata summary
is not a fresh signature/content verification. Browser viewing and download still
require the existing signature/hash verification and mandatory custody receipt.

New audit facts are queryable through the existing response-audit request_id
(response ID), actor, asset_id and time filters. Scoped case/HTTP tests cover
planning, missing provenance, repeat requests, immutable snapshots, snapshot/audit
disagreement, cross-command metadata, precise native identities, signature/hash
custody reuse, compromised keys, failed audit rollback and shared-view redaction.

No raw file acquisition, process memory, disk imaging, packet capture, forensic
timeline or deeper agent thread/module inspection is included. These require
separate collection contracts and agent work. This release connects the existing
forensic domain capabilities; it does not claim to implement every DFIR technique.
Deployment/restart and operator credentials/grants remain required after merge.
