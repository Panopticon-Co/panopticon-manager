# Wave 6 integration verification — 2026-10-27

## Cross-VM E2E Verified

The remaining acceptance scenario passed from PANO-NEW-WIN-01 (`10.77.10.31`)
to this regular PANO-NEW-MGR service (`10.77.10.10:443`) over VMnet10, from
21:57:39 to 22:00:04 IST, 27 October 2026. The native Windows agent self-enrolled
over verified TLS; no temporary Windows-local Manager was involved. The guest
TLS probe negotiated TLS 1.3 and recorded the separate local/peer addresses.

The test checkpoint held 3,577 records. Independent readback after clean shutdown
found **4,059 canonical records**: 3,429 observations, 418 state, 91 health, 62 gap
and 59 evidence records, with 4,059 persisted capture-age entries. Observations
include 10 process, 289 live Sysmon file and 4 network records. System-state and
file samples were read back directly from the deployed database.

The Manager-held native-exact record for owned ping.exe PID 10220 supplied the
boot identity and creation ticks `134375921207039503` for
`cross-vm-kill-4ba6219b7f50`. Dispatch, accept and native termination completed;
Manager retained a schema-2 SUCCEEDED result with completion observed. Its actual
body validates against contracts, and its immutable digest matches independent
database readback. The target exited before cleanup and agent shutdown returned 0.
The run observed no HTTP 422. One initial challenge/upload pair received 401 during
enrollment; native retries recovered, followed by 167 successful challenge/upload
pairs. Bootstrap credential copies were removed; the guest's protected identity,
spool and remote configuration remain for reproducible use.

Evidence lives in the coordinated agent PR:
`docs/windows-endpoint/evidence/20261027-cross-vm/`, including `summary.json`,
`persisted-samples.json`, `network-link.json` and `SHA256SUMS.json`.
Deployed application revision: `9e9df440a3ec3cdf0209721bbfa7533dcad0d57f`.
Local checks passed: 285 Manager tests with native tools/no skips, full Ruff,
48/48 agent CTest, 139 Response Engine tests and contract fixture/scanner checks.

This closes the stated Wave 6 cross-VM transport acceptance using existing live
sources. The optional FIM marker was not observed; file proof uses live Sysmon.
Minifilter/API-hook/kernel-network producer qualification, loss-free collection,
capacity/retention and fleet/soak behavior remain separate work. Merging the
coordinated PRs remains an operator action.

## Historical deployment checkpoint before Windows unlock

The regular service on PANO-NEW-MGR (`10.77.10.10`) now runs application revision
`9e9df440a3ec3cdf0209721bbfa7533dcad0d57f` behind its original nginx HTTPS listener.
Readiness reports schema 18. A new 8-GiB data disk supplies the active DB at
`/srv/panopticon-data/manager/panopticon.db`; enrollment/command state was copied
and verified before upgrade. The full original database remains unchanged at
`/var/lib/panopticon-manager/panopticon.db` as the historical archive. Active
counts exclude archived telemetry. All three prior enrollments were preserved.
The old source checkout and private deployment configuration were backed up.

The root filesystem had filled. VMware's resize required more host scratch space
than available; no resize completed. The powered-off original VMDK was compressed
at the host filesystem level without deleting guest files. An additional data
disk was used instead. Manager's systemd override requires that mount and retains
the original private credential file. Root free space remains low because it
contains the preserved historical DB; capacity/retention work remains separate
from this transport acceptance task. Linux endpoint VMs were not reconfigured.

Fresh local verification: 285 Manager tests passed with native producer tools and
no skips; full Ruff check passed. Agent CTest passed 48/48. The earlier loopback
runtime evidence remains valid for its stated scope. An existing Officer is
uploading successfully to the upgraded remote service.

**The PANO-NEW-WIN-01 cross-VM run is blocked at BitLocker recovery**, after a
firmware-policy change. Its four commented encryption entries have been restored.
The operator must unlock Windows before VMnet10, verified TLS/enrollment, live
file/process/system ingestion and the remote native command/result round trip can
be accepted. PRs remain drafts and this checkpoint is not readiness to merge.

## Deployment upgrade from the existing lab

The deployed lab database uses a pre-feature migration number 13, with
`endpoint_records.received_at/raw_sha256/schema_version` and no incident tables.
That is a different layout from main's migration 13. Startup now recognizes only
that exact layout, installs the missing incident/current endpoint tables, and
renames the historical table to `endpoint_records_legacy_v13` atomically. Historical
bodies stay in place without duplication or detection replay. Enrollment, commands,
results and legacy Linux events retain their original tables. New canonical
records use `endpoint_records`. Unknown partial layouts fail without modification.
Regression tests cover preservation of the original table root page, bodies and
enrollment state, idempotency and refusal of an unknown layout.

## Audit before changes

The workspace root is an uncommitted container repository. Actual checkouts are
under `review/`. Agent `codex/windows-telemetry` was at d85fd89 with unrelated local
remote-access and validation-tool changes; those files were preserved. Manager
`codex/windows-record-ingest` was clean at dcce5ee, contracts master at 00f2181,
and Response Engine main at cc61fcc. Recent history and tracked diffs were checked
before implementation; origin refs were refreshed.

The handoff was behind published feature branches. Isolated integration worktrees
under `wave6/`, each on `codex/wave6-integration`, start from:

| Repository | Audited feature base |
| --- | --- |
| Agent | windows-endpoint-completion, d5ce056 |
| Manager | windows-endpoint-v2-ingest, c379a3d |
| Contracts | windows-endpoint-telemetry-contract, 6cf4322 |
| Response Engine | windows-command-result-v2, 8bf7e6f |

Manager's feature base already implements both endpoint v2 routes in
`manager/routers/endpoint.py`, with typed canonical 1.0 envelopes in
`manager/wire/endpoint.py`, durable record/receipt tables and migrations,
`endpoint_freshness.py`, and ordered state projections in `endpoint_state.py`.
Its command router already accepts/retains v2 results through the pinned Response
Engine model. Those implementations were reused and tested. No Detection Engine
source or pin was changed by this integration work.

## Changes and validation

The conventional contracts result schema now publishes Windows revision 2,
including indeterminate completion and optional execution metadata. Revision 1
is explicitly archived for Linux. Versioned fixtures and revision documentation
record the existing two-revision decoding behavior. ACQUIRE_FILE is documented
and tested as an internal agent extension, excluded from shared remote dispatch.

Response Engine's reusable lifecycle now allows DISPATCHED/ACCEPTED to reach the
terminal INDETERMINATE state, matching Manager. The agent pipeline and family
schemas admit etw_kernel; production-pipeline fixtures cover all three new source
names. The entire fixture set was regenerated together to preserve epoch scope.

`tests/test_wave6_transport.py` exercises synthetic enrollment, challenge, new
source ingestion/readback, dispatch from retained exact process identity,
acceptance, v2 result retention, idempotent retry and immutable collision refusal.
It also checks Manager rejects ACQUIRE_FILE. The native test tools are selected
with OFFICER_BUILD_DIR; no native-producer skips should be counted as passes.

## Live Windows test VM evidence

Final checks: Manager **283 passed, zero skips** with the current native tools;
Response Engine **139 passed**; agent **48/48 CTest passed** after a clean MSVC
x64 Debug build with warnings-as-errors; all contracts fixtures validated.
Changed Python files pass Ruff and all four repositories pass `git diff --check`.

PANO-NEW-WIN-01, accessed only through its configured VMware guest helper. Manager
ran inside this Windows VM on an owned loopback HTTPS port with an isolated DB,
using this integration checkout and its pinned packages. This does not establish
connectivity to the separate PANO-NEW-MGR VM over VMnet10.

The current Debug agent self-enrolled using its native verified-TLS channel.
3,187 live canonical records persisted. An owned ping.exe was observed with exact
boot/creation identity. A KILL_PROCESS constructed from that retained identity
was dispatched, executed, reported SUCCEEDED with completion observed, and its
schema-2 result plus execution object were retained. The native process exited.
The actual retained result also validates against the current published schema.

The agent stopped cleanly (exit 0); the run-owned test certificate was removed
from the VM's Root store. Host trust and all Linux VMs were unchanged. The harness
used `--transport-only --trusted-tls`: no detection-rule outcome was a pass gate.

Evidence in the sibling agent repository:
`docs/windows-endpoint/evidence/20261027-wave6-vm/live-manager-e2e.json`.
SHA-256: `41254ae1c7c750c16294da5b6e3efbfad442c1783a8ff61750822a3d3c9ab518`.
Agent binary SHA-256:
`4d99ac53134a4ef58c8c35cc905f0b1f6dc0bce11c2613d9a3634e331e980b20`.

Limits: new-source fixtures are synthetic and provisional. No minifilter load,
hook interception, kernel-network collector, COLLECT_PROCESS_INFO live command,
fleet deployment, loss-free collection, or long-running soak is claimed.
