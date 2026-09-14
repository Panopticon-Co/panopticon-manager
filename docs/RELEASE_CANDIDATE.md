# Panopticon — Release Candidate Evidence (Phase 16)

Last verified: 2026-09-14. This document is the authoritative, evidence-based
release-candidate record for the Panopticon polyrepo. It supersedes no
individual repository's own README/docs — those remain the entry point for
build/test instructions — but consolidates cross-repository release
evidence in one place, as required for a capstone demonstration.

No semantic version number is assigned: this project has no established
versioning convention, and one is not invented here.

## 1. Release candidate status

**RELEASE-CANDIDATE.** Not RELEASE-READY without qualification: two
detection-reachability items (below) remain genuinely unverified/deferred by
design, and this is stated honestly rather than hidden.

## 2. Architecture freeze statement

The architecture verified below matches the established design with no
changes this phase:

```
Endpoint Agent → HTTPS telemetry → Manager → Detection Engine →
Alert/recommendation → Response Engine → authorization/lifecycle →
typed command → Endpoint Agent → validated OS-specific execution →
typed result → Manager audit
```

Repository ownership boundaries (Windows/Linux telemetry+execution+identity
in the agents; HTTP/persistence/ingestion/orchestration/auth/lifecycle/audit
in Manager; detection+alerting+recommendation in the Detection Engine;
contract+policy+tiering+translation in the Response Engine; canonical wire
contracts in Contracts; presentation-only in Console; architecture docs in
Diagrams) is unchanged and **frozen** — no redesign was performed or is
recommended.

## 3. Repository matrix

| Repository | Branch | HEAD | Changed this phase | Latest CI | Result |
|---|---|---|---|---|---|
| panopticon-agent | main | `fb54c4a` | No (Phase 15) | `34834485943` | success |
| panopticon-linux-agent | main | `335dae0` | No (Phase 13) | `34826983727` | success |
| panopticon-detection-engine | main | `149003e` | No (Phase 15) | `34836268838` | success |
| panopticon-manager | main | `fd5e785` | Yes (Phase 16) | `34839583104` | success |
| panopticon-response-engine | main | `cc61fcc` | No | `34810651076` | success |
| panopticon-contracts | master | `00f2181` | No (Phase 13) | `34824940445` | success |
| panopticon-console | main | `296e1ad` | No | `34797141658` | success |
| panopticon-diagrams | main | `d4fd92c` | No | `34799781963` | success |
| Panopticon-Co/.github | main | `fcf2870` | Yes (Phase 16) | N/A (no CI) | — |

## 4. Test matrix

| Suite | Result | Count | Evidence |
|---|---|---|---|
| Manager pytest | passed | 155 | local run + CI `34839583104` |
| Manager ruff | clean | — | local run |
| Detection Engine pytest | passed | 188, 2 skipped | local run + CI `34836268838` |
| Detection Engine full-spectrum simulation | ran clean | 24 events, 20 attacks intercepted | local run (matches CI step) |
| Response Engine pytest + ruff | passed / clean | 73 | local run + CI `34810651076` |
| Contracts fixture validation | OK | all fixtures + lifecycle checks | local run + CI `34824940445` |
| Console tests | passed | 31 | local run + CI `34797141658` |
| Diagrams source-consistency validator | passed | 335 checks | local run + CI `34799781963` |
| Windows agent CTest | passed | 11/11 | Phase 14/15 local MSVC + CI `34834485943` (no C++ changed this phase) |
| Linux agent CTest (gcc + clang/ASan/UBSan) | passed | 2/2 both configs | Phase 14 local Docker build + CI `34826983727` (no C++ changed this phase) |

## 5. Native build evidence

- **Windows**: real local MSVC 14.44/vcpkg/Ninja build, CTest 11/11 passing
  (Phase 13–15), confirmed unaffected by Phase 15/16 (no agent source
  changed). Latest CI run `34834485943` (windows-latest, MSVC/vcpkg) green.
- **Linux**: real local build inside a genuine Ubuntu 24.04 Docker container
  (real Linux kernel, WSL2-backed), CTest 2/2 passing (Phase 14), confirmed
  unaffected by Phase 15/16 (no agent source changed). Latest CI run
  `34826983727` (ubuntu-24.04, gcc build + clang/ASan/UBSan sanitizers) green.
- No agent rebuild was performed this phase — correctly so, since no agent
  code changed and current CI/native evidence is not stale.

## 6. Security evidence

- Banned-execution scan (`system()`, `popen()`, `exec*`, shell execution,
  `bash -c`/`sh -c`, generic `EXECUTE_COMMAND`, remote shell) — clean across
  all files touched in Phases 13–16. The only two historical grep hits
  (`WinHttpOpen(` and a documented, pre-existing `subprocess.Popen` that
  spawns one hardcoded local binary) are confirmed false positives, not
  vulnerabilities.
- Manager auth/replay/hijack/enrollment adversarial suite: 12 dedicated
  tests (Phase 13), unchanged and passing.
- Response security (PID-reuse, command hijack, replay, duplicate
  handling, lifecycle/expiry enforcement): covered by the existing 95-test
  E2E/security suite, unchanged and passing.
- No new occurrence of any banned execution primitive was introduced.
- No schema relaxation, `extra="forbid"` weakening, or new unauthenticated
  route was introduced.

## 7. Contract evidence

`panopticon-contracts` was not modified this phase — genuinely not
required, since no wire-shape change was needed to fix either the Phase 15
or Phase 16 findings. Fixture validation and the enrollment/command/result
schema checks pass (`00f2181`, CI `34824940445`).

## 8. Identity/enrollment evidence

Unchanged since Phase 13/14, re-confirmed not regressed:

- Endpoint-local ECDSA P-256 identity, proof-of-possession enrollment,
  one-time nonce, bootstrap authorization, `host_id` uniqueness enforcement.
- Live-proven (Phase 14, real Linux agent binary against a real Manager over
  real TLS): first-run enrollment, identity persistence across restart with
  the bootstrap token deleted, live revocation causing genuine 401
  rejection with durable spool retention (not data loss), legitimate
  re-enrollment under a fresh `agent_id` reclaiming the same `host_id`, and
  replay of previously-stuck telemetry once trust was restored.
- Windows identity/keypair code verified at CI + local-CTest tier
  (11/11 including `officer-keypair-tests`); live Windows enrollment itself
  is environment-blocked in a non-interactive session (see §12).

## 9. Telemetry evidence

- Linux `/proc` telemetry: real, live-proven (Phase 14) — real process
  observation → real Schema 0.4 event → real HTTPS delivery → real Manager
  ingest, verified by direct DB inspection of `raw_json`.
- Windows telemetry: real Sysmon/ETW collectors exist and are unit/CTest
  verified; live telemetry generation is environment-blocked in this
  session (no elevation/Event-Log-Readers membership available
  non-interactively — see §12).
- Schema 0.4, HTTPS ingestion, Manager persistence: proven live.
- Windows durable spool (`SegmentSpool`, Phase 12): CTest-verified, unit
  tier; not live-exercised this phase (no agent code changed).
- Linux spool/retry primitives: live-proven under a genuine auth failure
  (revocation) — data durably retained, then replayed on recovery, with a
  real agent binary, no unit-test bypass.

## 10. Detection evidence

- `DET-LNX-001` (reverse-shell `/dev/tcp/` pattern): **TRUE-PRODUCTION-E2E**,
  live-proven (Phase 14) — a real OS process, observed by the real agent's
  `/proc` collector, delivered over real TLS, matched by the real
  `RuleEvaluator`.
- `DET-PERS-007` (startup-folder persistence → `QUARANTINE_FILE`):
  **TRUE-PRODUCTION-E2E**, proven via a real `POST /api/v1/ingest` call in
  `panopticon-manager/tests/test_real_ingest_detection_reachability.py`
  (Phase 15) — no internal bypass. Root cause of its prior unreachability
  (a mislabeled `event_type` field) is fixed and regression-tested.
- `DET-INJ-001` (process injection → `KILL_PROCESS`): **explicitly NOT
  production-reachable.** Its `injection_type`/`target_process`/
  `source_process` fields have no place in the strict wire schema
  (`extra="forbid"`), and no endpoint collector observes process injection
  (Windows Sysmon decoder has no case for Event ID 8 CreateRemoteThread or
  10 ProcessAccess; the Linux agent has no equivalent). This requires new
  telemetry collection, not a mapping fix, and is correctly **deferred** —
  not implemented in Phase 16 per explicit scope freeze.
- Other `TERMINATE_PROCESS`-mapped rules (`DET-CRED-001`, `DET-MALW-002`,
  `DET-LAT-003`, and others) declare `event_type: process_create`, which
  real telemetry does produce, so `KILL_PROCESS` is plausibly reachable via
  one of them — **this remains unverified** (no real-ingest test exists for
  any of them); auditing all `TERMINATE_PROCESS`-mapped rules was correctly
  out of scope for a fix targeted at two specific rules.

## 11. Response evidence

| Action | Status | Evidence |
|---|---|---|
| `KILL_PROCESS` | Dispatch/execution/audit machinery proven; trigger-rule wire-reachability NOT proven | internal-bypass test (renamed for accuracy, Phase 15/16); real dispatch/poll/accept/execute/result/audit proven live via a directly-dispatched `QUARANTINE_FILE` command (Phase 14) — same command-lifecycle code path |
| `QUARANTINE_FILE` | TRUE-PRODUCTION-E2E | real-ingest test (Phase 15) + live real agent binary execution (Phase 14, real file moved to a real quarantine directory) |
| `ISOLATE_HOST` | TRUE-PRODUCTION-E2E (per existing Manager test suite) | pre-existing E2E suite, unchanged, passing |
| `RELEASE_HOST_ISOLATION` | Analyst/operator-initiated by design — never detection-triggered | contract-supported, implemented |
| `COLLECT_PROCESS_INFO` | Implemented, contract-supported, boundary-level/opt-in | no shipped rule opts in |
| `COLLECT_NETWORK_CONNECTIONS` | Implemented, contract-supported, boundary-level/opt-in | no shipped rule opts in |
| `COLLECT_FILE` | Contract-supported, implemented on both agents, detection-unwired | no `translate_recommendation` mapping exists |

## 12. E2E evidence and environment-blocked paths

- **Real, live, TRUE-PRODUCTION-E2E (Phase 14, Linux, real Ubuntu 24.04
  Docker container against a real Manager over real TLS):** enrollment →
  identity persistence → revocation → durable retry → re-enrollment →
  replay → real detection (`DET-LNX-001`) → real command dispatch → real
  agent poll/accept/execute (`QUARANTINE_FILE`) → real file quarantined →
  real result → real audit trail (`created, dispatched, accepted,
  result_received`, `SUCCEEDED`).
- **Real, live, TRUE-PRODUCTION-E2E (Phase 15/16, wire-ingest boundary):**
  real `POST /api/v1/ingest` (fully wire-schema-valid, manually
  live-verified this phase against a fresh Manager instance) → real
  background `DetectionWorker` → real `OfficerIngestionAdapter` → real
  `RuleEvaluator` → `DET-PERS-007` → real `Alert` → real
  `QUARANTINE_FILE` recommendation → real authorization → real dispatch.
- **Environment-blocked, not faked:** live Windows ETW/Sysmon telemetry
  generation requires interactive UAC elevation or "Event Log Readers"
  group membership, neither obtainable in this non-interactive session
  (confirmed via a real timed-out elevation attempt in Phase 14, not
  assumed). The underlying Windows identity/keypair/spool code is verified
  at CI + local-CTest tier.
- **Not attempted, and not claimed:** a single synchronized run with both a
  live Windows agent and a live Linux agent against the same Manager
  instance simultaneously. Each was proven separately against the same
  Manager, which is the strongest honest claim available in this
  environment.

## 13. Reliability evidence

- Durable telemetry retention under auth failure and replay on recovery:
  live-proven on Linux (Phase 14).
- Windows `SegmentSpool` durability: CTest-verified (Phase 12), not
  live-exercised this phase.
- Command lifecycle expiry sweep, stale-claim recovery (`DetectionWorker`),
  and audit-trail completeness: covered by the existing Manager test suite,
  unchanged and passing.

## 14. Demonstration procedure

See `docs/DEMO.md`, Sections 1–10, for the full, byte-for-byte-verified
capstone walkthrough (TLS setup, Manager startup, agent+analyst enrollment,
`DET-PERS-007`/`QUARANTINE_FILE` trigger, authorization, dispatch,
acceptance, result, audit verification). This phase live-tested every curl
command in that walkthrough against a real running Manager instance and
fixed three genuine reproducibility defects found in the process (wrong
analyst-enrollment header/env-var/response-field names, a DER-vs-raw-r||s
signature mismatch in the enrollment step, and a multi-line JSON body that
NDJSON parsing rejects) — see the Phase 16 commit for detail.

## 15. Known limitations

- `DET-INJ-001` requires new upstream process-injection telemetry
  (Windows Sysmon Event ID 8/10, or an equivalent on Linux) that does not
  exist today. Deferred by design (see §10).
- Complete real-ingest reachability of every `TERMINATE_PROCESS`-mapped
  rule is not proven — only `DET-PERS-007` (a `QUARANTINE_FILE` rule) has a
  dedicated real-ingest test.
- `COLLECT_PROCESS_INFO`/`COLLECT_NETWORK_CONNECTIONS` are implemented but
  detection-unwired — no shipped rule requests them.
- `COLLECT_FILE` has no `translate_recommendation` mapping and remains
  detection-unreachable.
- `RELEASE_HOST_ISOLATION` is intentionally analyst/operator-initiated
  only, never detection-triggered — this is a design choice, not a gap.
- Live Windows telemetry/enrollment demonstration requires a manual,
  interactive prerequisite (Administrator elevation, or the demo user
  added to "Event Log Readers") that this non-interactive environment
  cannot arrange itself — a genuine environment limitation, not a product
  defect.
- A single simultaneous Windows+Linux live run against one Manager has not
  been performed.

## 16. Explicitly deferred work

- `DET-INJ-001` process-injection telemetry collection (new Sysmon Event ID
  8/10 decoding, a new wire-schema category, adapter mapping, and a
  Linux-side equivalent or explicit non-support) — a telemetry-expansion
  feature, out of scope for a detection-reachability fix, per this phase's
  own scope freeze.
- Auditing every `TERMINATE_PROCESS`-mapped rule for real-ingest
  reachability.
- Per-request cryptographic signing, key rotation, and Manager batch-id
  dedup — all previously and again explicitly deferred with reasoning
  (ADR 004, Phase 13/14 reports); nothing this phase changes that.
- A synchronized live Windows+Linux dual-agent demonstration.

## 17. Final release assessment

Panopticon's core architecture — endpoint telemetry, cryptographic
enrollment, detection, authorized response, endpoint execution, and audit —
is implemented, tested, and, for its strongest paths, proven live end to
end with real running components, not mocks. Two specific, honestly-scoped
gaps remain (`DET-INJ-001`'s telemetry dependency, and unverified
reachability of the remaining `TERMINATE_PROCESS`-mapped rules), and one
environment-specific manual prerequisite blocks a live Windows telemetry
demonstration in this particular non-interactive session. None of these are
hidden or minimized. On that basis, Panopticon is assessed as a genuine
**RELEASE-CANDIDATE**: ready to be presented as the capstone demonstration
of this project, with its remaining gaps stated precisely rather than
glossed over.
