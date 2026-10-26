# Immutable Windows process captures

The Windows endpoint emits a durable begin record, bounded process pages and a
final manifest. `capture_id` is the begin record's immutable ID; the manifest's
ordered `page_record_ids` identifies exactly the pages accepted by the endpoint
journal. Generic endpoint ingestion retains all records without collapsing pages
into one latest-state payload. State snapshots have no inferred process actor.

Agent-token authenticated read routes:

- `GET /api/v2/endpoint/{agent_id}/process-captures/{capture_id}` discovers records
  claiming a capture even before a manifest arrives. `limit` defaults to 100 and
  accepts 1–256; `after` is the last immutable record ID returned as `next_cursor`.
- `GET /api/v2/endpoint/{agent_id}/process-captures/{capture_id}/records/{record_id}`
  returns one unchanged indexed record, including a mismatched-scope claim marked
  explicitly false. A record belonging to another capture returns 404.
- `GET /api/v2/endpoint/{agent_id}/process-snapshots/{manifest_record_id}` returns
  the unchanged manifest, verified entry count and explicit assembly issues.
- `GET /api/v2/endpoint/{agent_id}/process-snapshots/{manifest_record_id}/pages/{index}`
  returns the unchanged referenced page after scope/index verification.

Verification requires matching endpoint identity (including boot/install),
collector epoch/generation, capture ID and decimal page index. The begin must
exist in the same scope; duplicate/malformed page IDs invalidate the manifest.
Absent pages remain incomplete; mismatched page retrieval returns 409. Missing
records or out-of-range indexes return 404, malformed manifests 422, and absent
or another agent's token 401. Existing latest projections remain per category;
they do not constitute an assembled capture.

Migration 17 adds a derived capture index and backfills prior begin/page/manifest
records one body at a time. It preserves original payloads/digests and Detection
dispositions. New entries commit in the same acceptance transaction as immutable
records; duplicate delivery does not duplicate index entries, and collision
rollback removes both new evidence and its derived index entry. Orphan pages are
indexed so delayed begins can make them discoverable later. Legacy single-prefix
snapshots remain retained without being misclassified as paged captures.

Discovery returns role counts and bounded record-reference metadata, with scope
and page-index checks. `manifest_status=not_observed` means no retained indexed
manifest; it does not prove a crash, abandonment or source loss. Any manifest
claim yields `observed_unverified`; its scope and complete page assembly still
require separate verification. Pagination orders immutable record IDs, not event
time, arrival or page index. Concurrent late records may sort before a cursor;
restart pagination to reconcile such arrivals. This API does not resume native
collection or automatically close an unfinished capture.

`assembly_complete` proves retention and these structural relationships only.
`enumeration_complete` additionally requires the endpoint's complete-enumeration
report with no bound or consumer refusal. `inventory_complete` remains false:
Toolhelp descriptors can precede later PID queries, verified ancestry and event
continuity are not established, and inaccessible processes remain uncertain.

Overview parses at most 64 MiB of referenced page bodies across at most 4,096
pages. Budget refusal is explicit and leaves every retained page individually
retrievable. Reads are separate immutable-record lookups; concurrent arrival can
change missing-page status. This bounds parsed bytes, not a qualified request
latency or total server memory guarantee. Resumable/background verification,
analyst authorization/Console integration, endpoint restart reconciliation of
begins without a manifest and large-host/fleet qualification remain open. The
derived index avoids parsing historical page bodies for discovery; query latency,
aggregate counts/index storage and concurrent-arrival reconciliation budgets are
not yet qualified.

Compiled native multi-page fixtures exercise ingestion, delayed page assembly,
reordered references, scope validation, token isolation and budget refusal.
Upgrade/reopen tests preserve exact preexisting evidence and index orphan pages;
unfinished-capture tests check pagination, delayed manifests, boot mismatch,
malformed indexes, record readback, token isolation and collision rollback.
The actual runtime crash/reopen fixture checks all committed pages and their
manifest against exact recovered journal records. Neither establishes complete
process lifecycle or market-grade endpoint coverage.

Paged state version 1.4 includes held-object critical-process and raw protection
level facts. Manager preserves each exact success/null/error/classification and
the manifest's security query summary; it does not reinterpret these as full
host coverage. Unknown and documented unimplemented native levels stay degraded.
Unattempted queries after OpenProcess/GetProcessId refusal remain counted in
manifest-bound health. These additional fields do not weaken or truncate endpoint
payloads to fit the backend.

The same retained process object supplies selected primary-token SID/integrity,
elevation/type, raw session ID and token statistics. Per-field native/validation/
collection-bound refusal survives ingestion and readback, as do raw unknown
enums and full-width LUID components. Counts, primary-token attributes and raw
identifiers do not imply complete groups/privileges, effective access, thread
impersonation or globally correlated user/logon entities. Token open and field
counts remain bound to the exact retained manifest. See
[endpoint token scope](../../panopticon-agent/docs/windows-endpoint/PROCESS_TOKEN.md).

Held-object IsWow64Process2 reports retain separate process/native machine codes,
the API's WOW64 Boolean and query status. Unknown codes remain raw; null/refused
or unsupported results are preserved with their source/domain/code. Manager does
not replace them with architecture inferred from a hostname, OS, image path or
collector platform. Architecture report counts remain in manifest-bound health;
neither field retention nor a recognized symbol qualifies live ARM64/ABI support.
