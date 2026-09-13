# Response Engine — implementation state / handoff

Last updated: 2026-09-13, after a sixth pass that (1) wired the
panopticon-contracts golden fixtures into all four implementer repos'
real test suites (verified green on actual GitHub Actions CI in every
case, not just local pytest/ctest), (2) found and fixed two real contract
mismatches the initial contracts audit missed (a missing `created_at` wire
field, and panopticon-linux-agent silently tolerating unrecognized
top-level command fields), (3) independently verified panopticon-agent's
receipt-code collapse is byte-for-byte identical to panopticon-linux-agent's
and locked both with regression tests, (4) resolved the outstanding Windows
`start_time_ticks` telemetry-producer gap end-to-end, and (5) found and fixed
three unrelated, already-red CI runs (ruff line-length violations in
panopticon-response-engine and panopticon-manager, and a missing
`submodules: true` on panopticon-response-engine's checkout step) that had
been silently failing across multiple prior sessions' commits despite local
verification passing — see "NEW this pass" below for full detail. Built on
top of a fifth pass that created
[`Panopticon-Co/panopticon-contracts`](https://github.com/Panopticon-Co/panopticon-contracts)
(canonical cross-repo wire contract docs, JSON Schema, and golden fixtures),
and a fourth pass that threaded
`TERMINATE_PROCESS -> KILL_PROCESS` start-time data across five repos
(response-engine ADR, schema, both agents' producer/consumer sides,
detection engine, and Manager) and landed Windows agent response support
(`panopticon-agent@e4f2b0c`, all 7 closed actions, merged and independently
re-verified after a background implementation pass). This document exists
so a future session (or a compacted context) can reconstruct exactly what is
real, what is verified, and what is next, without re-deriving it from
scratch. Re-verify against the actual repos before trusting anything here as
still current — treat this as a snapshot, not a source of truth.

**NEW this pass (sixth): Priorities 1, 2, 3, and 5 of the post-contracts
directive completed and verified on real CI.**

- **Priority 1 (wire fixtures into implementer tests) — complete for all
  four repos**, every one verified on real GitHub Actions CI, not just
  local:
  - `panopticon-response-engine`: vendored `panopticon-contracts` as a
    test-only git submodule (`tests/vendor/panopticon-contracts`);
    `tests/test_contract_fixtures.py` proves `Command`/`CommandResult`
    accept/reject the canonical fixtures (59 tests total, up from 43).
  - `panopticon-manager`: `tests/test_response_contract.py` (sibling-repo
    checkout, matching the existing `test_ingest_contract.py` convention for
    `panopticon-agent`'s event schema) calls the REAL
    `authorize_and_enqueue()` path for every closed action and validates the
    actual stored `commands.command_json` against
    `panopticon-contracts/schema/command.schema.json` (102 tests total, up
    from 95).
  - `panopticon-linux-agent`: no JSON-file-reading test harness exists here,
    so fixture *scenarios* were hand-reproduced as literal test cases after a
    direct source audit (see Priority 2 below) rather than loading fixture
    files.
  - `panopticon-agent`: `tests/response_tests.cpp` now directly loads
    `panopticon-contracts` fixture files (sibling checkout, resolved via a
    new `PANOPTICON_CONTRACTS_DIR` CMake compile definition mirroring the
    existing `OFFICER_EVENT_SCHEMA_PATH` pattern) and proves every valid
    fixture parses and every parse-level-invalid fixture is rejected.
  - `panopticon-contracts/docs/COMPATIBILITY.md` records the full matrix.
- **Priority 2 (reconcile the two contract facts) — both facts investigated
  against real source, not assumed, and both were real, not documentation-only
  bugs**:
  - **Fact A was actually incomplete, not just under-documented**: Manager's
    `authorize_and_enqueue` injects **three** fields into the wire `Command`
    (`host_id`, `schema_version`, AND `created_at`), not two —
    `panopticon-contracts`' first published revision omitted `created_at`
    entirely, which both native agents actually require and validate
    (`created_at < expires_at`). Fixed in `panopticon-contracts`: schema,
    docs, and every fixture updated; re-verified green on its own CI.
  - **Fact B surfaced a real, if low-severity, security-invariant gap**:
    direct source comparison found `panopticon-agent`'s parser explicitly
    enumerates and rejects any unrecognized top-level command field
    (`allowed_keys`), but `panopticon-linux-agent`'s hand-rolled
    substring-scanning parser did not check for extra fields at all — a
    smuggled field would have been silently ignored rather than rejected. No
    handler ever acted on an unrecognized field, so this was not exploitable,
    but it violated the documented closed-envelope invariant. **Fixed** (the
    implementation, not the contract, per the directive's explicit
    instruction) by adding `has_only_known_top_level_keys()` to
    `panopticon-linux-agent/src/command.cpp`, plus a regression test.
    Verified via Docker (`ubuntu:24.04`) build+ctest and real GitHub Actions
    CI, including the pre-existing ASan/UBSan sanitized job.
- **Priority 3 (Windows result mapping) — independently verified, not
  assumed**: read `panopticon-agent/src/response/command.cpp`'s
  `serialize_command_result` directly and confirmed its `ReceiptCode` ->
  wire `outcome` collapse is byte-for-byte identical to
  `panopticon-linux-agent`'s (`succeeded->succeeded`,
  `execution_failed->failed`, everything else `->rejected`). Both repos now
  have an explicit regression test locking this mapping so they cannot
  silently drift apart.
- **Priority 5 (Windows `start_time_ticks`) — resolved end-to-end.** Root
  cause: `panopticon-agent`'s ETW collector
  (`decode_process_start` in `etw_process_collector.cpp`) already read the
  raw `CreateTime` FILETIME off the kernel event to compute a human-readable
  timestamp, then discarded the raw tick value — the exact quantity
  `GetProcessTimes()` independently recomputes in the response subsystem for
  PID-reuse-safe `KILL_PROCESS` targeting. Threaded this value, unchanged,
  through `RawProcessEvent` -> `ProcessMetadata` -> the wire
  `process.start_time_ticks` field the schema already declared (from an
  earlier pass). Sysmon's XML events expose only a formatted timestamp with
  no raw tick count, so Sysmon-sourced events deliberately leave this field
  null (documented at the call site) — a Sysmon-sourced `TERMINATE_PROCESS`
  recommendation will still correctly fail closed, the existing safe
  behavior for a source that cannot supply a PID-reuse-safe target. No
  existing test needed modification (the deserializer already requires the
  field present-but-possibly-null on every event, satisfied automatically
  since the serializer now always emits it); added a dedicated regression
  test. Verified via a real MSVC build: full rebuild + ctest, 9/9 passed.
  **Practical implication**: a real Windows endpoint's ETW-sourced
  `TERMINATE_PROCESS` recommendation can now actually reach a dispatched
  `KILL_PROCESS` command for the first time — previously this path was
  unreachable in practice on Windows regardless of how correct the
  Detection Engine -> Response Engine translation logic was, because the
  required field never existed on the wire.
- **Found and fixed three already-red CI runs, unrelated to this pass's own
  changes, that had been silently failing across multiple prior sessions**:
  a `ruff` line-length violation in `panopticon-response-engine/tests/
  test_policy_and_recommendation.py` (from the fourth pass's TERMINATE_PROCESS
  work); the same class of bug in `panopticon-manager/tests/
  test_response_engine.py` (blocking PR #4's CI on every run since it
  landed); and `panopticon-response-engine`'s CI checkout step missing
  `submodules: true`, which is a bug introduced by this pass's own submodule
  addition but is recorded here as a reminder that a submodule addition is
  incomplete without also updating the consuming CI workflow. **Lesson for
  future sessions**: local `pytest`/`ctest` passing is not sufficient
  evidence a change is actually green — this pass caught all of the above
  only by explicitly running `gh run watch` against the real GitHub Actions
  run after every push, which prior sessions had not consistently done.

**NEW this pass (fifth): `panopticon-contracts` created.** Audited the actual wire
behavior across `panopticon-response-engine`, `panopticon-manager`,
`panopticon-linux-agent`, and `panopticon-agent` (not their docs) and
published a new, separate repository —
[`Panopticon-Co/panopticon-contracts`](https://github.com/Panopticon-Co/panopticon-contracts) —
as the canonical, versioned home for the cross-repo `Command`/`CommandResult`
wire contract, its JSON Schema, and deterministic golden fixtures. It is
**not** a microservice or a new runtime dependency: no repo imports it at
build/run time yet (see "Not yet done" below). Concretely it contains:

- `docs/CONTRACT.md` — the reconciled wire contract, including two
  previously-undocumented facts found during the audit: (1) the wire
  `Command` envelope Manager actually sends has `host_id`/`schema_version`
  injected at dispatch time, fields `response_engine.contract.Command`'s own
  Pydantic model does not declare; (2) `panopticon-linux-agent`'s 8-value
  local `receipt_code` enum collapses onto `CommandResult.outcome`'s 3-value
  wire vocabulary (`succeeded`/`failed`/`rejected`) via a specific mapping
  previously discoverable only by reading `src/command.cpp`.
- `docs/VERSIONING.md`, `docs/COMPATIBILITY.md`, `docs/SECURITY.md` (15 named
  adversarial invariants, each tied to a fixture), and
  `docs/adr/0001-panopticon-contracts.md`.
- `schema/command.schema.json` / `schema/command_result.schema.json` — JSON
  Schema (draft 2020-12), including per-action target-shape `if/then` rules
  and one explicitly documented schema-vs-implementation gap (JSON Schema's
  `date-time` format cannot express "UTC offset only," which both native
  agents enforce in code, not schema).
- `fixtures/` — one valid command per closed action, 9 adversarial/invalid
  command fixtures (expired, malformed JSON, missing field, unknown action,
  wrong-typed target, wrong target shape for the action, smuggled `shell`
  field, non-UTC timestamp, oversized `correlation_id`), plus 3 narrative
  scenario fixtures for replay/cross-agent/correlation-mismatch that a static
  schema can't express alone, the full 6-entry rejected-outcome vocabulary,
  and lifecycle transition fixtures (valid/invalid/expiry/cancellation/
  duplicate-operation).
- `scripts/validate_fixtures.py` — validates every fixture against schema
  (verified locally: all pass) and includes a `--grep-repos` mode searching
  for banned execution patterns (`system(`, `popen(`, `exec*`, shell
  invocations, `EXECUTE_COMMAND`). **Actually run** against
  `panopticon-response-engine`, `panopticon-manager`, `panopticon-linux-agent`,
  `panopticon-agent`, and `panopticon-detection-engine`'s real response-path
  source (excluding vendored/venv trees and the two known negative-test hits
  that assert `EXECUTE_COMMAND` is rejected): **zero violations found.**
- `.github/workflows/ci.yml` — confirmed green on a real GitHub Actions run
  (`gh run list`, run id `34757871084`, `success`, 11s) immediately after the
  initial push, not just locally.

**Historical note (all three items below were resolved in the sixth pass —
see "NEW this pass (sixth)" above the fifth-pass section this originally
belonged to; kept here rather than deleted so the fifth pass's own record
stays accurate to what was true at the time it was written):** at the time
this fifth-pass section was written, none of `panopticon-manager`,
`panopticon-linux-agent`, or `panopticon-agent` had been wired to load
`panopticon-contracts`' fixtures yet, the Windows agent's `receipt_code`-
equivalent collapse mapping had not been independently re-read against the
Linux mapping, and `panopticon-agent`'s Schema 0.4 producer change to emit
live `process.start_time_ticks` telemetry was still outstanding. All three
are now done.

**Resolved**: `gh pr create` succeeded on retry —
[panopticon-manager#4](https://github.com/Panopticon-Co/panopticon-manager/pull/4)
is open with commits `ccc25d2`, `f777ff6`, `b1553b1`, `3b9c27f`.

**Capability discovery, this pass**: this session's Windows environment has
a working Docker Desktop install (the daemon was stopped, not absent —
`Start-Process 'Docker Desktop.exe'` plus a short poll brought it up). That
means `panopticon-linux-agent`'s actual Linux/CMake/Ninja build and its
`panopticon-linux-core-tests` suite ARE runnable from this environment via
`docker run ubuntu:24.04 ...` matching its CI job, even though there is no
native Linux toolchain and no persistent WSL distro with build tools. This
un-blocks C++-side verification (build, CTest, and — with the sanitizer
image's extra packages — ASan/UBSan) that earlier passes had assumed
required the not-yet-available VMware environment. It does NOT unblock
anything that needs real kernel networking/nftables/namespaces beyond what
a container provides, or the isolation helper's actual privileged
CAP_NET_ADMIN behavior against a real interface — those remain genuinely
environment-dependent per directive §28.

## Architectural decision

**The Response Engine's persistence, HTTP transport, and orchestration stay
inside the Manager deployable. Its pure domain contract — the closed
action/target schema, tier classification, recommendation translation, and
the lifecycle state machine — is extracted into its own repository,
[`panopticon-response-engine`](https://github.com/Panopticon-Co/panopticon-response-engine),
consumed by Manager as a pinned git submodule (`vendor/response_engine`)
installed editable into the same process. One deployable backend throughout
— no network RPC, no second service, no microservice infrastructure.**

This is a two-step decision, recorded across three ADRs:

1. `docs/adr/004-response-engine.md` — the original in-Manager design.
2. `docs/adr/005-response-engine-stays-a-manager-module.md` — an initial
   audit that rejected *both* a separate repository and a separate
   deployment, conflating the two questions. Status: superseded (its
   no-microservice conclusion stands; its no-repository conclusion does
   not).
3. `docs/adr/006-response-engine-package-extraction.md` — the corrected
   decision: repository boundary and deployment boundary are independent
   (proved by this same codebase's `vendor/eyedetect` submodule, ADR 001).
   The Response Engine's *pure* logic gets its own repository; its
   persistence/transport/orchestration do not move, and nothing here
   introduces a network hop, a second process, or any distributed-systems
   infrastructure.

See `panopticon-response-engine`'s own `docs/adr/001-repository-boundary.md`
and `docs/OWNERSHIP.md` for the full ownership/dependency-direction
reasoning from that repository's side.

## Current implementation state (verified by reading code + running tests)

- `vendor/response_engine` (pinned git submodule, `panopticon-response-
  engine` @ its initial `0.1.0`) — the closed action/target contract
  (`response_engine.contract`), tier classification
  (`response_engine.policy`), recommendation translation
  (`response_engine.recommendation`), and the canonical lifecycle state
  machine (`response_engine.lifecycle`, new — not yet enforced by Manager's
  persistence layer, see below). Installed editable via `requirements.txt`'s
  `-e ./vendor/response_engine`.
- `manager/detection/response.py` — imports `classify_tier` and
  `translate_recommendation` from `response_engine`; owns lifecycle staging
  (`on_alert_created`) and analyst decisions (`authorize_response_action`,
  `reject_response_action`, `expire_stale_response_actions` — added earlier
  in this session).
- `manager/routers/response_actions.py` — analyst HTTP surface:
  `GET /api/v1/response-actions`, `POST .../authorize`, `POST .../reject`,
  `POST /api/v1/analysts/enroll`. All four gated by `require_analyst_token`
  (`manager/auth.py`), a distinct identity space from agent bearer tokens.
- `manager/routers/commands.py` — imports `Action`/`Command`/`CommandResult`
  from `response_engine.contract` (re-exported for backward-compatible
  imports); `authorize_and_enqueue()` is the *only* function that ever
  writes a `commands` row (used by both the raw `POST /api/v1/commands`
  endpoint and the Response Engine); `poll()` and `submit_result()` are the
  agent-facing dispatch/result-reporting surface.
- `manager/routers/commands.py` also now exposes
  `POST /api/v1/agents/{agent_id}/commands/{command_id}/accept`
  (`DISPATCHED -> ACCEPTED`), an optional agent acknowledgement. A result is
  legal from either `DISPATCHED` or `ACCEPTED`, so an agent that never calls
  `accept()` keeps working unchanged — see "Not yet done" below, item 1 is
  now resolved.
- Test suite: `uv run pytest -q tests/` — **94 passed** in Manager (6 new
  ACCEPTED-state tests added this pass in `tests/test_command_route.py`;
  every pre-existing test still passes unchanged). This pass also fixed a
  pre-existing bug surfaced by adding `ACCEPTED` to `_OPEN_LIFECYCLE_STATES`:
  the expiry sweep's SQL had a hardcoded 3-placeholder `IN (?, ?, ?)` clause
  that broke as soon as a 4th open state existed
  (`sqlite3.ProgrammingError: Incorrect number of bindings supplied`) — now
  built from `len(_OPEN_LIFECYCLE_STATES)`. `panopticon-response-engine`'s
  own suite: **39 passed** (this pass's commit there only changed
  `lifecycle.py`'s docstring, not any test-relevant code).
  `uv run ruff check .` — clean in both repos.
- CI: Manager's `.github/workflows/ci.yml` is unmodified — its existing
  `submodules: recursive` checkout and `pip install -r requirements.txt`
  step pick up the new submodule and its editable install automatically.
  `panopticon-response-engine` has its own new `.github/workflows/ci.yml`
  (lint + pytest across Python 3.10/3.11/3.12, no cross-repo checkout
  needed). Neither has been verified on a real GitHub Actions run yet — only
  locally. Verify the next push's Actions run is green in both repos.

## Contracts (canonical locations — do not duplicate)

- **Alert**: `panopticon-detection-engine/src/alerting/alert.py`
  (`Alert` dataclass). Byte-identical to the vendored copy in
  `panopticon-manager/vendor/eyedetect/src/alerting/alert.py` as of this
  audit (`diff` exit 0) — re-diff before trusting this after any vendor bump.
- **Detection recommendation**: `ActiveResponseAction` /
  `ActiveResponseEngine.resolve_action`, same file layout as Alert above.
  Recommends exactly 3 actions today: `TERMINATE_PROCESS`,
  `BLOCK_FIREWALL_IP`, `ISOLATE_HOST`. **As of `panopticon-detection-engine@
  b2a02fe`, carries `target_start_time_ticks` (optional) when the triggering
  event's `process.start_time_ticks` was present** — see item 0 above. The
  vendored copy at `vendor/eyedetect` does not yet have this (see "Known
  blockers").
- **Typed command**: `manager/routers/commands.py`'s `Command` model — the
  closed 7-action `Literal` and per-action target schema (`{pid,
  start_time_ticks}` for process actions, `{path}` for file actions, empty
  otherwise) is the single source of truth on the Manager side.
- **Typed command-result**: `manager/routers/commands.py`'s `CommandResult`
  model, consumed by `submit_result()`.
- **7-action enum**: as of the extraction in ADR 006, `response_engine.
  contract.ACTIONS` (Python) is the single source of truth on the Python
  side — `manager/routers/commands.py` no longer defines its own copy. The
  Linux agent's `panopticon-linux-agent/include/panopticon/linux_agent/
  command.hpp` still independently hardcodes the same 7 actions in C++ (it
  cannot depend on a Python package), verified consistent as of this audit.
  `panopticon-linux-agent` ADR 001 and root `CLAUDE.md` both explicitly
  defer a cross-language shared-contracts package until a real milestone
  justifies it — do not create one preemptively; do re-verify consistency
  by hand whenever `response_engine/contract.py` or `command.hpp` changes.
- **Orphaned fifth vocabulary**: `panopticon-detection-engine/src/
  remediation/engine.py`'s `EndpointRemediationEngine` defines an unrelated,
  11-action vocabulary (`KILL_PROCESS_TREE`, `LOCK_USER_ACCOUNT`,
  `REVOKE_CLOUD_ACCESS_KEY`, etc.) that is simulated-only (per root
  `CLAUDE.md`'s own note) and not reconciled with the real 7-action Response
  Engine. Not touched in this pass. Flagged as a duplicated-responsibility
  candidate for deprecation/removal in a future pass — needs an explicit
  decision from whoever owns `panopticon-detection-engine`, not a unilateral
  deletion from a Manager-focused audit.

## Security invariants (verified)

- `authorize_and_enqueue()` is the sole path to a `commands` row; both
  callers (raw endpoint, Response Engine) share it, so validation cannot
  drift (`manager/routers/commands.py:82-141`).
- Agent tokens are per-agent, stored only as SHA-256 digests, compared with
  `hmac.compare_digest` (`manager/auth.py`). `require_agent_token(agent_id,
  authorization)` looks up the digest for that specific `agent_id`, so a
  valid token for agent A can never authenticate as agent B (verified by
  `test_agent_cannot_poll_another_agents_commands` and
  `test_result_cannot_be_submitted_for_another_agents_command`).
- `submit_result()` binds a result to the command's actual `agent_id` and to
  the command's `correlation_id` before accepting it — cross-agent and
  cross-recommendation result forgery are both rejected with 422.
- Closed action enum + strict per-action target schema
  (`Command.enforce_closed_target_schema`) — no free-form execute path
  exists anywhere in the Manager-side contract.
- KILL_PROCESS / ISOLATE_HOST / RELEASE_HOST_ISOLATION are hard-coded
  `ANALYST_APPROVAL` in `_TIERS` — never auto-fire, regardless of alert
  severity (`test_kill_process_isolate_host_and_release_always_require_
  analyst_approval`).
- **Fixed this pass**: `submit_result()` previously let a second, distinct
  `result_id` for an already-resolved command overwrite
  `commands.lifecycle_state` again (a duplicate/replayed-result gap). Now
  guarded: only a command still in `DISPATCHED` accepts a result; anything
  else is accepted (200, so a retrying agent doesn't error-loop) but
  audited as `duplicate_result_ignored` and never changes state. See
  `test_second_distinct_result_never_overwrites_a_terminal_outcome`.
- **Fixed this pass**: neither `commands` nor `response_actions` ever
  transitioned to `EXPIRED` — a timed-out row just became silently
  unpollable/unauthorizable with no lifecycle record of why. Both now sweep
  lazily on read (`_expire_stale_commands` in `poll()`/`submit_result()`;
  `expire_stale_response_actions` in the response-actions list/authorize/
  reject endpoints) rather than via a new background scheduler, since
  Manager has no job infrastructure and none is justified yet. See
  `test_expired_command_transitions_to_expired_lifecycle_state` and
  `test_stale_pending_response_action_expires_and_cannot_be_authorized`.
- **Added this pass**: `accept()` only ever moves a command out of
  `DISPATCHED`; it is bound to the caller's own `agent_id` the same way
  `poll()`/`submit_result()` are (422 if the command belongs to another
  agent), swept by the same expiry check first, and is a no-op (200, not an
  error) both when called twice and when called after a result has already
  landed — a late or replayed `accept()` can never move a terminal command
  backwards into `ACCEPTED`. See `test_accept_rejected_for_wrong_agent`,
  `test_duplicate_accept_is_idempotent`, and
  `test_late_accept_after_terminal_result_does_not_revert_state`.

## Not yet done — genuinely missing, not fabricated as complete

0. **RESOLVED this pass.** Item 2 below (`TERMINATE_PROCESS -> KILL_PROCESS`
   start-time threading) is done end-to-end and verified: ADR
   (`panopticon-response-engine/docs/adr/002-terminate-process-start-time-threading.md`),
   Schema 0.4 gains optional `process.start_time_ticks`
   (`panopticon-agent@fd80031`, schema-only), `panopticon-linux-agent@523473f`
   emits it in canonical telemetry (verified: Ubuntu 24.04 container
   build+ctest green), `panopticon-detection-engine@b2a02fe` threads it
   through `ActiveResponseAction`/`ProcessNode` (verified: 165 passed, 2
   skipped, full suite), `panopticon-response-engine@a500fa0` actually
   translates `TERMINATE_PROCESS` into `KILL_PROCESS` when present (verified:
   43 passed), and this repo's `vendor/response_engine` pin is bumped to
   `a500fa0` with a new end-to-end test proving `on_alert_created` stages a
   real `PENDING`/`ANALYST_APPROVAL` `KILL_PROCESS` response_actions row
   (verified: 95 passed). **`vendor/eyedetect` was deliberately NOT bumped**
   to pick up the matching `panopticon-detection-engine` commit: doing so
   pulls in several unrelated upstream commits that regress two pre-existing
   tests (`test_replay_produces_gate_a_and_b_alerts`,
   `test_certutil_chain_produces_three_alerts` — `CORR-003` stops firing on
   the demo fixture, root cause not investigated). This means **Manager's own
   detection pipeline (via `vendor/eyedetect`) does not yet benefit from this
   fix** — only `panopticon-detection-engine` run standalone does. See "Known
   blockers" below for the exact follow-up needed before `vendor/eyedetect`
   can be safely bumped. Windows telemetry still never carries
   `start_time_ticks` (tracked as item 3 below, `panopticon-agent`'s own
   producer change, deliberately deferred to avoid colliding with the
   concurrent Windows response-engine implementation pass).
1. **RESOLVED this pass.** `panopticon-linux-agent` @ `9f73fcb` ("feat(response):
   send DISPATCHED->ACCEPTED acknowledgement before executing a command")
   adds `curl_https_client::accept_command` and calls it in `main.cpp`
   immediately after `command_gate::validate_and_mark` succeeds and before
   any action handler runs. Best-effort by design: the call's outcome is
   never checked, since Manager still accepts a result submitted straight
   from `DISPATCHED`. Verified with a full Ubuntu 24.04 container build
   (cmake+ninja+ctest matching CI): compiles clean,
   `panopticon-linux-core-tests` passes. A Windows agent still has no
   response path at all (see item 3 below), so it has nothing to adopt yet.
2. **`TERMINATE_PROCESS` can never map to `KILL_PROCESS`.**
   `ActiveResponseAction` carries no process-creation-timestamp field, and
   the Linux agent's `KILL_PROCESS`/`COLLECT_PROCESS_INFO` target schema
   requires `start_time_ticks` specifically to prevent PID-reuse attacks
   (kill/collect targeting the wrong process after the original PID was
   reused). This means the spec's required end-to-end demonstration of "an
   approval-required KILL_PROCESS response" cannot be exercised via the real
   detection-alert-Response-Engine path today — only by hand-crafting a
   `POST /api/v1/commands` call directly. Recommended design (not started):
   thread the triggering process-creation event's timestamp through
   `panopticon-detection-engine/src/correlation/process_tree.py`'s existing
   per-pid tracking into `ActiveResponseEngine.resolve_action`, add a
   `target_start_time_ticks` field to `ActiveResponseAction`, and update
   `manager/detection/response.py`'s `translate_recommendation()` to build a
   real `KILL_PROCESS` command when that data is present, still failing
   closed when it is not. This is a correlation-engine change, not a
   Response Engine change, and touches a security-critical kill path — it
   needs its own careful, reviewed pass, not a rushed addition here.
3. **RESOLVED this pass.** `panopticon-agent` @ `e4f2b0c` implements all 7
   closed actions natively (Win32/WFP), mirroring `panopticon-linux-agent`'s
   poll -> gate -> accept -> execute -> result control flow exactly. Opt-in
   via `--enable-response` (off by default; a bare telemetry deployment is
   byte-identical to before this pass). See `panopticon-agent/RESPONSE.md`
   for the full design. Key points for a reviewer:
   - `KILL_PROCESS`/`COLLECT_PROCESS_INFO` re-observe via `GetProcessTimes`
     and compare the creation-time tuple against the command's
     `start_time_ticks` before acting (the Windows side of the PID-reuse
     defense item 0 above threads data for) — re-checked once more on the
     freshly reopened `PROCESS_TERMINATE` handle immediately before
     `TerminateProcess`, narrowing (not eliminating — no atomic Win32
     primitive exists for this) the reopen-to-terminate TOCTOU window.
   - `ISOLATE_HOST`/`RELEASE_HOST_ISOLATION` use WFP
     (`FwpmEngineOpen0`/`FwpmFilterAdd0`) with a default-block sublayer and a
     single permit filter scoped to the configured Manager address — no
     SSH/RDP break-glass, no general ESTABLISHED/RELATED bypass, matching
     the Linux isolation ADR's invariant.
   - **Architectural decisions flagged for review** (all in `RESPONSE.md`):
     no separate privileged-helper process (unlike Linux's AF_UNIX-split
     helper — isolation runs in the already-elevated `officer-agent.exe`);
     response only starts if a telemetry collector already started (an
     integration-point artifact, not a security requirement); response
     reuses the existing machine-GUID-derived telemetry identity for
     enrollment rather than an independent identity; evidence for
     `COLLECT_NETWORK_CONNECTIONS`/`COLLECT_FILE`/`QUARANTINE_FILE` goes out
     via the existing stdout+Uploader telemetry path, since Manager has no
     dedicated evidence-ingestion endpoint.
   - **ENVIRONMENT-BLOCKED, not claimed as working**: this session's Windows
     environment has no elevation available (`BUILTIN\Administrators` is
     deny-only, no UAC) — live ETW/Sysmon start (a pre-existing limitation,
     confirmed unrelated to this pass), live enrollment/poll/accept/result
     HTTP round-trips against a real Manager, live `TerminateProcess`
     against a genuinely protected target, and live WFP filter *enforcement*
     against a real non-loopback adapter were never exercised — only
     unit-tested in isolation (18 assertions, `officer-response-tests`).
     Matches `panopticon-linux-agent`'s own ADR-004 de-risking-spike caveat
     for the equivalent Linux gap.
   - Verified in this environment: full MSVC/Ninja/vcpkg build from a clean
     merge to `main`, `ctest --test-dir build-officer-x64` — **9/9 passed**
     (5 pre-existing suites unchanged + new `officer-response-tests`),
     independently re-verified (not just trusted from the implementing
     pass's own report).
   - **Resolved in the sixth pass**: `panopticon-agent`'s Schema 0.4 producer
     change to emit `process.start_time_ticks` in live telemetry (deferred at
     the time this item was written, to avoid a file-level collision with the
     concurrent response-engine implementation) has landed — see "NEW this
     pass (sixth)" near the top of this document for the full change and its
     verification.
4. **No isolation-helper crash-mid-operation test and no IPC fuzz test**
   exist in `panopticon-linux-agent` (confirmed by its own audit pass) —
   the ADR asserts fail-closed re-apply-on-restart behavior
   (`isolation_helper_main.cpp:137-144`) but nothing exercises killing the
   helper mid-netlink-apply and verifying recovery. Worth adding to that
   repo's test suite; not attempted here (out of Manager's scope).
5. **The orphaned `EndpointRemediationEngine` vocabulary** in
   `panopticon-detection-engine` (see Contracts section above) is a
   duplicated-responsibility candidate for deprecation, not removed here.

## Next implementation task (recommended order)

1. Get PR #4 reviewed and merged; watch CI go green on the actual GitHub
   Actions run for both `panopticon-manager` and `panopticon-response-engine`
   (not just local `pytest`/`ruff`), and push the `panopticon-linux-agent`
   ACCEPTED-adoption commit (`9f73fcb`, already on `origin/main`) through its
   own CI the same way.
2. **RESOLVED this pass.** `panopticon-linux-agent` @ `a2ee97a` ("fix(isolation):
   reject oversized IPC frames instead of parsing a truncated prefix; add
   robustness e2e suite") fixed a real bug found while implementing this:
   `isolation_helper_main.cpp`'s `recv()` buffer was exactly
   `kIsolationRequestFrameSize` bytes, so a SOCK_SEQPACKET packet larger than
   that was silently truncated by the kernel to fit, and the truncated
   prefix could still parse as a syntactically valid frame -- there was no
   real "reject oversized input" check, only an accidental one for frames
   that happened not to decode. Fixed by sizing the buffer one byte larger
   and requiring an exact-length match. Added `isolation-raw-frame-tool`
   (sends arbitrary raw bytes bypassing the typed encoder) and
   `run_isolation_robustness_e2e.sh`, wired into CI, covering: malformed IPC
   (wrong size, invalid opcode), oversized IPC, an unauthorized peer UID, a
   helper crash (`kill -9`) while isolated, fail-closed re-apply on restart,
   and release after that restart. Verified with repeated full
   Docker-container builds/runs against `ubuntu:24.04` (matching CI):
   consistently green across multiple consecutive runs after fixing a test
   script race (`wait $PID` on a reparented, non-child PID doesn't actually
   block).
3. **RESOLVED this pass.** See item 0 above and
   `panopticon-response-engine/docs/adr/002-terminate-process-start-time-threading.md`.
4. **Mostly resolved.** (a) correlation engine change: done
   (`panopticon-detection-engine@b2a02fe`). (b) Manager translation: done
   (submodule bump, this repo @ `c6daa67`). (c) end-to-end test: done at the
   `response.on_alert_created` unit level
   (`test_on_alert_created_terminate_process_with_start_time_stages_kill_process_pending`)
   proving a `KILL_PROCESS` response_actions row lands `PENDING`/
   `ANALYST_APPROVAL` with the correct `{pid, start_time_ticks}` target, and
   that authorizing it dispatches through the same
   `authorize_response_action` path already covered by
   `test_authorize_response_action_creates_a_dispatchable_command`. **Not yet
   done**: a true end-to-end test that starts from a raw process-creation
   telemetry event ingested through the full pipeline (worker -> rule match
   -> `Alert` -> `on_alert_created`) rather than a hand-built `_Alert`/
   `active_response` dict — blocked on the `vendor/eyedetect` bump (see
   "Known blockers"), since that's what would let a real `Level >= 12` rule
   match produce the recommendation in the first place.
5. **RESOLVED this pass.** Windows agent response support landed at
   `panopticon-agent@e4f2b0c` — see item 3 above for details and caveats.
6. Investigate and fix the `CORR-003`/Gate-B regression blocking the
   `vendor/eyedetect` bump (see "Known blockers"), then bump it and add the
   true end-to-end test described in item 4 above.
7. `panopticon-agent` (Windows) still needs its own Schema 0.4
   `start_time_ticks` producer change once the concurrent Windows
   response-engine work lands, so Windows-originated detections can also
   produce real `KILL_PROCESS` targets (today they still safely fail closed).

## Known blockers

- **`vendor/eyedetect` bump is blocked on a pre-existing, unrelated
  regression, not on this pass's work.** Bumping the pin from
  `3dc75d8` to `panopticon-detection-engine`'s current `main`
  (`b2a02fe`, which includes the `start_time_ticks` fix) causes
  `test_replay_produces_gate_a_and_b_alerts` and
  `test_certutil_chain_produces_three_alerts` to fail: `CORR-003` no longer
  fires on `tools/demo_events.ndjson` / the Gate-B fixture. The likely
  culprit is one of the intervening commits — `356afab` ("fix(rules):
  suppress DET-PROC-011 false positives on test harness scripts") or
  `2e6a001` ("feat(rules): add 6 Linux-specific detection rules...") — but
  this was not root-caused; only isolated by cherry-picking just the
  `start_time_ticks` commit onto the old pin in a scratch check, confirming
  the regression is unrelated to it. Whoever owns `panopticon-detection-
  engine`'s rule set needs to investigate before `vendor/eyedetect` can be
  bumped again; until then, Manager's actual detection pipeline (as opposed
  to `panopticon-detection-engine` run standalone) still cannot produce a
  real `KILL_PROCESS` command from a live alert, even though every other
  link in the chain now works.
- Windows agent response support (item 3/5 above) is implemented and
  merged, but real elevation-dependent behavior on both platforms — live
  `TerminateProcess` against a genuinely protected target, live WFP/nftables
  filter *enforcement* against a non-loopback adapter, live
  enrollment/poll/accept/result HTTP round-trips against a real Manager —
  remains genuinely environment-dependent per directive §28. This session's
  Windows environment has no elevation (`Administrators` deny-only, no UAC);
  neither the Linux nor Windows agent's isolation path can be enforcement-
  tested outside a container/namespace or a real elevated host. That needs
  the VMware environment a teammate is preparing separately — see the
  "Remaining environment-validation checklist" this document should gain
  once every implementable-without-VMware item is exhausted.
