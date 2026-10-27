# Wave 6 integration verification — 2026-10-27

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
