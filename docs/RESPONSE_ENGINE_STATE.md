# Response Engine — implementation state / handoff

Last updated: 2026-09-13, after a seventh pass that built a true end-to-end
vertical-slice test (real detector -> real Alert -> Response Engine ->
authorization -> dispatch -> execution result -> audit) and, in the process,
found and documented a real, previously-unrecorded gap: eyedetect's
active-response vocabulary can never produce `COLLECT_PROCESS_INFO`/
`COLLECT_NETWORK_CONNECTIONS`, and `ActiveResponseAction` has no
`target_start_time_ticks` field at all, so no real detection can ever
produce a `KILL_PROCESS` command today regardless of the `CORR-003` bump
blocker — see "NEW this pass (seventh)" below. Built on top of a sixth pass
that (1) wired the
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
  **As of the detection/response contract hygiene closure below**, resolves
  to one of `TERMINATE_PROCESS`, `COLLECT_PROCESS_INFO`,
  `COLLECT_NETWORK_CONNECTIONS`, `QUARANTINE_FILE`, or `ISOLATE_HOST` (the
  five closed-set-mappable recommendation strings); `BLOCK_FIREWALL_IP` is
  still a string a rule or the internal C2 beacon detector can request, but
  it now always fails closed (`resolve_action` no longer resolves it to
  anything). Carries `target_start_time_ticks` (optional) when the
  triggering event's `process.start_time_ticks` was present — see item 0
  above.
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

**NEW this pass (ninth): Priority 3 (fuzz/robustness) — bounded deterministic
hostile-input suite for Manager's command/result decoding.** No fuzzing
library (e.g. hypothesis) is installed anywhere in this project; per the
operating directive a deterministic suite was used instead.
`tests/test_hostile_input_commands.py` (12 tests) proves
`/api/v1/commands` and `/api/v1/agents/{id}/command-results` fail closed
against: a non-JSON body, truncated JSON, a JSON array/scalar instead of an
object, an empty body, null for every required field, wrong JSON types for
every field, invalid UTF-8 (Starlette itself rejects this with 400, before
FastAPI's pydantic validation ever runs -- also an acceptable fail-closed
outcome, not a bug), a pathologically deeply-nested JSON value, and an
arbitrary-precision (10**300) integer target value. Also confirms duplicate
JSON keys resolve deterministically to the last occurrence (Python's `json`
module's standard behavior) rather than creating any validate-one/read-
another smuggling ambiguity. All pre-existing 122 tests plus these 12 pass
(134 total).

**NEW this pass (eighth): Priority 2 of the post-integration adversarial
directive (active cross-repo adversarial security review) — one real,
exploitable vulnerability found and fixed in `panopticon-manager`, fourteen
new adversarial regression tests added, everything else in the attack model
verified safe by actually attacking it rather than reading source.**

- **Fixed: agent-identity takeover via the shared enrollment bootstrap
  secret.** `manager.auth.enroll()` used `INSERT OR REPLACE` against
  `enrolled_agents`, so re-POSTing `/api/v1/agents/enroll` for an
  *already-enrolled* `agent_id` silently overwrote its `host_id` and minted
  a fresh bearer token, invalidating the legitimate agent's own token with
  no audit trail distinguishing this from first-time provisioning. Since
  `PANOPTICON_ENROLLMENT_TOKEN` is necessarily one shared, fleet-wide
  secret, anyone holding it (not just the operator of a specific endpoint)
  could hijack any already-trusted agent's identity and rebind it to a
  host_id of their choosing. Fixed by changing to a plain `INSERT` and
  catching the resulting `sqlite3.IntegrityError` into a 409 (the same
  pattern `authorize_and_enqueue` already uses for duplicate `command_id`),
  so re-enrolling an existing `agent_id` is rejected outright and the
  original binding/token is untouched. There is still no revoke-then-
  re-enroll flow — that is a separate, not-yet-built feature, not a reason
  this fix was weakened. See
  `test_re_enrolling_an_existing_agent_id_is_rejected_not_silently_overwritten`
  in `tests/test_adversarial_security.py`.
- **Verified safe by active attack, not just source reading** (all in
  `tests/test_adversarial_security.py` unless noted):
  - Agent bearer tokens cannot authenticate as an analyst, and analyst
    tokens cannot authenticate as an agent — `enrolled_agents` and
    `analyst_credentials` are genuinely separate identity spaces.
  - The shared `system:command-token` (used only for the raw
    `/api/v1/commands` POST) cannot be presented as a `Bearer` token to
    authenticate as either an agent or an analyst.
  - `response_id` is the sole authorization scope for
    `/api/v1/response-actions/{id}/authorize` — a forged/guessed
    `response_id` 404s, and authorizing one response_action never touches a
    different, unrelated one's `lifecycle_state` or `command_id`.
  - Revoking an agent's or analyst's credential (`revoked_at` set) takes
    effect on the very next request, including result submission for a
    command already in flight — no caching or grace window.
  - Malformed/hostile `Authorization` headers (empty, `"Bearer"` with no
    token, `Basic` scheme, a 10,000-character token) are all rejected
    cheaply (a length check precedes any digest comparison).
  - The wire `Command` contract's own PID-reuse gate (positive-integer
    `start_time_ticks`, `extra="forbid"` on `target`) rejects a missing,
    zero, or negative `start_time_ticks` and rejects a smuggled extra target
    field (e.g. a `shell_command` key riding alongside a valid `pid`) at
    validation time, independent of any specific caller.
  - `accept()`/`submit_result()` against a fabricated `command_id` that was
    never queued are both rejected (422), not silently accepted or crashing.
  - A repository-wide banned-execution-pattern scan of `manager/`
    (`os.system`, `subprocess`, `popen(`, `eval(`, `shell=True`) found no
    matches — confirmed clean, not merely assumed.
- **Not re-tested here** (already covered with adversarial-style tests
  elsewhere and not repeated): wrong-agent poll/accept/result, command
  replay via duplicate `command_id`, command/result expiry, duplicate-result
  idempotency (`tests/test_command_route.py`); cross-agent hijack of a
  response-engine-issued command, forged/wrong `correlation_id`, and the
  closed seven-action enum against the raw endpoint
  (`tests/test_e2e_response_pipeline.py`).
- **Remaining Priority 2 scope, continuing next**: `panopticon-contracts`,
  `panopticon-response-engine`, `panopticon-linux-agent`, and
  `panopticon-agent` still need their own active-attack passes (this pass
  covered `panopticon-manager` only); target/file-action path-traversal
  security (COLLECT_FILE/QUARANTINE_FILE); Linux isolation-helper IPC/
  privilege-boundary re-verification against the attack model above.

**NEW this pass (seventh): Priority 1 of the post-integration adversarial
directive (true end-to-end vertical slice) — done, with a real, previously
undocumented gap found and recorded rather than papered over.**

- `tests/test_e2e_response_pipeline.py` (new, 6 tests, all passing against
  the real Manager app via `TestClient` plus a real, unmodified
  `DetectionRun`/`AlertSink` instance) proves the full
  `Detection Engine -> Alert -> Response Engine -> authorization -> typed
  command -> dispatch -> ACCEPTED -> execution result -> lifecycle -> audit`
  chain end-to-end:
  - `test_isolate_host_from_real_detector_requires_analyst_approval_then_succeeds`
    feeds five real `file_create` events through the genuine, unmodified
    `ThresholdEngine` default rule (`DET-FREQ-001`, deliberately independent
    of the `vendor/eyedetect` bump blocked by the `CORR-003` regression — see
    "Known blockers" below), gets a real `ISOLATE_HOST`-recommending `Alert`,
    proves an unauthenticated and a forged-token authorization attempt are
    both rejected (401) with the response action still `PENDING`, then has a
    real enrolled analyst authorize it and drives it through
    poll/accept/result to `SUCCEEDED`, asserting the exact
    `command_audit` event sequence (`created`, `dispatched`, `accepted`,
    `result_received`).
  - `test_isolate_host_command_cannot_be_hijacked_by_a_different_agent` proves
    a second, legitimately enrolled agent can neither poll, accept, nor
    submit a result for another host's response-engine-issued command (empty
    poll, 422/422), using a real detector-issued command rather than a
    hand-crafted `/api/v1/commands` POST.
  - `test_safe_collection_auto_dispatches_without_analyst_action_and_succeeds`
    proves the AUTO_SAFE (`COLLECT_PROCESS_INFO`) path end-to-end — dispatch,
    accept, result, `SUCCEEDED`, and the same four-event audit trail — with
    zero analyst action anywhere in the path.
  - `test_kill_process_real_detector_recommendation_fails_closed_without_start_time`
    and `test_result_correlation_id_mismatch_is_rejected` and
    `test_raw_command_with_an_action_outside_the_closed_seven_is_rejected`
    cover the remaining named negative paths not already exercised by
    `tests/test_command_route.py` (expired command, wrong agent, replay,
    duplicate result, and duplicate accept were already covered there and are
    not repeated).
- **Real, previously undocumented finding: eyedetect's active-response
  vocabulary cannot reach two of the directive's named scenarios today, by
  construction, not by bug.** Read directly from
  `vendor/eyedetect/src/alerting/active_response.py`,
  `vendor/eyedetect/src/pipeline_core.py`, and every rule YAML under
  `vendor/eyedetect/rules/`:
  - `ActiveResponseEngine.resolve_action` only ever emits
    `TERMINATE_PROCESS`, `BLOCK_FIREWALL_IP`, or `ISOLATE_HOST`. No rule, no
    code path anywhere in `vendor/eyedetect` ever recommends
    `COLLECT_PROCESS_INFO` or `COLLECT_NETWORK_CONNECTIONS` — the two
    actions `response_engine.policy.classify_tier` marks `AUTO_SAFE`. The
    entire `AUTO_SAFE` branch of `manager/detection/response.py`'s
    `on_alert_created` is therefore unreachable from genuine detector output
    today; it is only exercised (here and in
    `tests/test_response_engine.py::test_on_alert_created_auto_safe_action_is_enqueued_immediately`)
    by monkeypatching `translate_recommendation` at the same boundary.
  - `ActiveResponseAction` (the dataclass `resolve_action` returns) has no
    `target_start_time_ticks` field at all — it was never added when Windows
    `start_time_ticks` was threaded through Manager/agents this session. That
    means `response_engine.recommendation.translate_recommendation`'s
    PID-reuse-safety gate can **never** be satisfied by real `TERMINATE_PROCESS`
    output, so no real detection can ever produce a `KILL_PROCESS` command
    today — every real Level-12/13 process-termination recommendation fails
    closed (`REJECTED`, no command), proven directly against genuine
    `ActiveResponseEngine.resolve_action` output by
    `test_kill_process_real_detector_recommendation_fails_closed_without_start_time`.
  - **This is intentionally not fixed here.** Both gaps live inside
    `vendor/eyedetect`, and the operating directive for this pass explicitly
    scopes eyedetect changes to the pre-existing `CORR-003` regression only.
    Wiring a `target_start_time_ticks` value into `ActiveResponseAction`
    would require the raw enriched event (with `process.start_time_ticks`,
    landed this session on the Windows producer side) to reach
    `ActiveResponseEngine.resolve_action`, which today only ever sees the
    already-flattened `event` dict passed into rule evaluation — a real,
    non-trivial detection-engine change, not a one-line fix. Recorded here as
    a concrete, source-verified follow-up rather than silently declared done.

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
   `test_authorize_response_action_creates_a_dispatchable_command`.
   **RESOLVED this (seventh) pass** for the reachable case:
   `tests/test_e2e_response_pipeline.py` starts from raw `file_create` events
   run through the real, unmodified `DetectionRun`/`ThresholdEngine`
   (`DET-FREQ-001`, independent of the blocked `vendor/eyedetect` bump) to a
   real `ISOLATE_HOST`-recommending `Alert`, through `on_alert_created`,
   analyst authorization, dispatch, accept, and result. A true
   `KILL_PROCESS`-specific version of this (a raw event producing a real
   `Level >= 12` `TERMINATE_PROCESS` recommendation with a valid
   `target_start_time_ticks`) remains genuinely impossible today regardless
   of the `vendor/eyedetect` bump — see the "seventh pass" note above:
   `ActiveResponseAction` has no `target_start_time_ticks` field at all, a
   separate, deeper gap than `CORR-003`.
5. **RESOLVED this pass.** Windows agent response support landed at
   `panopticon-agent@e4f2b0c` — see item 3 above for details and caveats.
6. Investigate and fix the `CORR-003`/Gate-B regression blocking the
   `vendor/eyedetect` bump (see "Known blockers"), then bump it and add the
   true end-to-end test described in item 4 above.
7. `panopticon-agent` (Windows) still needs its own Schema 0.4
   `start_time_ticks` producer change once the concurrent Windows
   response-engine work lands, so Windows-originated detections can also
   produce real `KILL_PROCESS` targets (today they still safely fail closed).

## Phase 8 (2026-09-14): COLLECT_PROCESS_INFO/COLLECT_NETWORK_CONNECTIONS mappings added

Both actions previously had no path from any detection recommendation to a
real command anywhere in the system -- `response_engine.translate_recommendation`
returned `None` for both, and `panopticon-detection-engine`'s
`ActiveResponseEngine.resolve_action` had no branch that could produce
either. Fixed across two repos:

- `panopticon-detection-engine@49a613a`: `resolve_action` gained two new
  `custom_action`-driven branches (a rule must opt in via its own YAML
  `active_response:` field, matching the existing `TERMINATE_PROCESS`/
  `BLOCK_FIREWALL_IP` pattern -- deliberately does **not** auto-fire on
  severity level alone, since inventing a new heuristic for a read-only
  evidence-collection action is rule-authoring policy this engine does not
  own).
- `panopticon-response-engine@8b521aa`: `translate_recommendation` gained
  matching mappings. `COLLECT_PROCESS_INFO` applies the *same*
  PID-reuse-safety fail-closed check as `TERMINATE_PROCESS` (missing/zero/
  wrong-typed `start_time_ticks` produces no command) -- being read-only
  does not make misidentifying the target acceptable.
- `panopticon-manager@00cbf18`: bumped `vendor/response_engine` to pick
  this up; added two **real, non-monkeypatched** end-to-end tests
  (`test_on_alert_created_collect_process_info_is_enqueued_immediately`,
  `test_on_alert_created_collect_network_connections_is_enqueued_immediately`)
  proving `on_alert_created` genuinely stages and auto-enqueues both as
  `AUTO_SAFE` commands through the real `translate_recommendation` call --
  not a faked one, unlike the pre-existing synthetic-mapping test whose
  comment claimed this was impossible until now.

**CODE-VERIFIED and CI-VERIFIED** (all three repos green): the *mapping*
gap is closed. This does **not** by itself mean any real, currently-shipped
detection rule actually sets `active_response: COLLECT_PROCESS_INFO` in its
YAML -- no rule does yet, since nothing previously consumed it. Wiring an
actual rule to opt in is separate, not-yet-requested scope.

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
- **Reconfirmed during the Priority 7 final release audit (2026-09-13)**:
  attempted the `vendor/eyedetect` bump to `b89ccbf` (current
  `panopticon-detection-engine` main, which includes `b2a02fe`'s
  `target_start_time_ticks` fix) again, independently of the prior
  session's cherry-pick isolation noted above. Result is identical:
  `test_certutil_chain_produces_three_alerts` and
  `test_replay_produces_gate_a_and_b_alerts` both fail on `CORR-003`
  going missing from the produced alert set; reverted to `3dc75d8`
  immediately, confirmed all 134 tests green again, and left no dirty
  submodule state. This is not a new regression -- it is the same
  already-documented blocker, reconfirmed rather than newly discovered.
  The bump remains unsafe until `panopticon-detection-engine`'s own
  `CORR-003` regression is fixed upstream; per the driving directive,
  `vendor/eyedetect` is not being modified here to work around it.
- **ROOT CAUSE FOUND during Phase 8 (2026-09-14) -- this was never actually
  a regression.** An organization-wide open-PR audit found
  `panopticon-detection-engine#11` ("correlation: key on PID, enforce the
  window, add CORR-003"), whose head commit **is** `3dc75d8` -- the exact
  SHA this repo's `vendor/eyedetect` has been pinned to all along.
  `git merge-base --is-ancestor 3dc75d8 origin/main` returns false: that
  commit was never merged into `panopticon-detection-engine`'s main branch
  at all. A prior session pinned the vendor submodule directly to an
  open, unmerged PR branch tip instead of a reviewed main commit. Bumping
  to actual current main doesn't "regress" CORR-003 -- main never had it
  merged in the first place. PR #11 is CLEAN/MERGEABLE against current
  main and CI-green (155/2 skipped, all 3 Python versions) as of its last
  push. A companion PR, `panopticon-agent#4` ("collectors: PID->image
  cache backfill + System/TimeCreated for V3 families"), fixes two
  prerequisite live-telemetry bugs from the same Gate-B test session
  (Sysmon's `"<unknown process>"` sentinel breaking `DET-NET-006`'s name
  match, and unreliable Sysmon `UtcTime` blowing the 60s correlation
  window by ~12.5 hours) -- both PRs are the real, reviewed, matched-pair
  fix for this entire blocker, authored by a teammate (`sokhiaryan`), not
  something this session should reimplement. Merging them is a human
  decision (`gh pr merge` is blocked here by an auto-mode guardrail
  regardless of instruction-level approval) -- **STATUS: BLOCKED, REQUIRES
  HUMAN DECISION**, not further engineering investigation. Once merged,
  re-attempt the `vendor/eyedetect` bump against the resulting commit and
  re-verify `test_certutil_chain_produces_three_alerts` /
  `test_replay_produces_gate_a_and_b_alerts` pass for real.
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

## Phase 8 completion: CORR-003 unblocked, KILL_PROCESS true production path proven

The `BLOCKED, REQUIRES HUMAN DECISION` item above is resolved: the human
merged `panopticon-detection-engine#11` and `panopticon-agent#4`
(`mergedAt` 2026-09-14T00:03Z, both confirmed via
`git merge-base --is-ancestor <mergeCommit> origin/main` — a real,
fast-forward ancestry check, not just GitHub's UI state). Both merge commits
are CI-green (`detection-engine` run 34791447192, `agent` run 34791466106).

- **`vendor/eyedetect` bump: CODE-VERIFIED, CI-VERIFIED.** Re-pinned from
  `3dc75d8` (the old, never-merged PR-branch-tip commit) to `98b1c18`
  (the actual merge commit of PR #11 on `panopticon-detection-engine`'s real
  `main`). `panopticon-detection-engine`'s own suite passes 173/175 (2
  environment-only skips) at `98b1c18`, including
  `test_certutil_chain_produces_three_alerts` and
  `test_replay_produces_gate_a_and_b_alerts` — the exact two tests that
  regressed against the old unmerged tip. Manager's full suite passes
  138/138 (`pytest tests/`, matching CI's exact invocation) against the new
  pin, up from 134 before this phase (the +4 are the 2
  `COLLECT_PROCESS_INFO`/`COLLECT_NETWORK_CONNECTIONS` E2E tests already
  added in the prior session, plus the 2 new true-production-path
  `KILL_PROCESS` tests below). `ruff check .` clean.
- **KILL_PROCESS: real detection-engine integration proven, wire-ingest
  reachability NOT proven (corrected label — see Phase 15).** The gap this
  document previously called "real, previously undocumented" — eyedetect's
  `ActiveResponseAction` carrying no `target_start_time_ticks` field, so
  every genuine `TERMINATE_PROCESS` recommendation failed closed — is
  closed: `git log` on `panopticon-detection-engine` shows
  `b2a02fe feat(active-response): thread process.start_time_ticks into
  TERMINATE_PROCESS recommendations`, merged to main as part of PR #11,
  now present at the updated pin.
  `tests/test_e2e_response_pipeline.py::test_kill_process_real_detector_recommendation_succeeds_via_internal_detection_bypass`
  proves the complete, real, unmodified chain with no hand-built
  `ActiveResponseAction`/`Alert`/recommendation anywhere in it: a genuine
  `process_injection` event, matched against real production rule
  `DET-INJ-001` (loaded from `vendor/eyedetect/rules`, the same 84-rule set
  `manager/config.py` points production at) by the real `RuleEvaluator`,
  produces a real `ActiveResponseAction` via
  `ActiveResponseEngine.resolve_action`, which becomes a real `Alert`,
  emitted through the real `AlertSink.emit` -> `response.on_alert_created`
  -> the real (unmocked) `translate_recommendation` -> a `KILL_PROCESS`
  command -> analyst authorization -> dispatch -> agent poll -> accept ->
  execution result -> `SUCCEEDED` -> full `command_audit` trail
  (`created, dispatched, accepted, result_received`). **This was previously
  mislabeled TRUE-PRODUCTION-E2E.** It drives `DetectionRun.process_event()`
  directly with a hand-built `process_injection` event, bypassing
  `POST /api/v1/ingest` and `OfficerIngestionAdapter` entirely. A Phase 15
  investigation (triggered by the same question for `DET-PERS-007`, resolved
  below) confirmed `DET-INJ-001` genuinely cannot be reached through real
  ingest today: its `injection_type`/`target_process`/`source_process`
  fields have no place in the strict wire schema
  (`manager/wire/telemetry.py`, `extra="forbid"`), and no endpoint collector
  — Windows Sysmon/ETW (`panopticon-agent/src/collectors/
  sysmon_telemetry_decoder.cpp` has no case for Sysmon Event ID 8
  CreateRemoteThread or 10 ProcessAccess) or Linux `/proc` — observes
  process injection at all. Closing this would require adding genuinely new
  telemetry collection (a new wire-schema category plus new OS-level
  collector code on at least Windows), not a rule or adapter mapping fix,
  which is out of scope for a detection-to-wire reachability fix and belongs
  to a future telemetry-expansion phase. Status: **internal detection-engine
  integration test only** — real KILL_PROCESS dispatch/execution/audit
  machinery is proven once an Alert exists, but a live endpoint currently
  has no way to produce the Alert that triggers it.
  `test_kill_process_real_detector_recommendation_fails_closed_without_start_time`
  (pre-existing) continues to prove the complementary fail-closed case
  still holds when `start_time_ticks` is genuinely absent from the
  triggering event.
- **PID reuse safety, TRUE-PRODUCTION-E2E.**
  `test_kill_process_pid_reuse_is_rejected_on_a_true_production_path` proves
  that once the real detector's `KILL_PROCESS` command is dispatched with
  `target_start_time_ticks=T1`, the Manager never re-resolves or refreshes
  that value even after PID reuse — the dispatched command still carries the
  original T1 pass-through-only token. An honest endpoint that checks the
  live process's actual start time against T1 is therefore guaranteed to
  observe `T1 != T2` and refuse to act; the test reports the resulting
  `outcome: "failed"` exactly as a real agent would, and confirms the
  Manager correctly resolves it to lifecycle state `FAILED` with a complete
  audit trail rather than ever crediting a phantom termination. The
  PID-reuse identity check itself is enforced agent-side (this was already
  true and unchanged); what this test newly proves is that the Manager's
  half of the contract — never mutating or re-deriving the bound
  `start_time_ticks` after the real detector first observed it — holds on
  the true production path, not just in `response_engine`'s unit tests.
- **`COLLECT_PROCESS_INFO` / `COLLECT_NETWORK_CONNECTIONS`: status
  unchanged, BOUNDARY-LEVEL, not TRUE-PRODUCTION-E2E.** Confirmed still
  accurate after the pin bump: `vendor/eyedetect/src/pipeline_core.py` and
  every rule YAML under `vendor/eyedetect/rules/` were re-checked at
  `98b1c18`, and no rule or code path recommends either action — eyedetect's
  `ActiveResponseEngine.resolve_action` only auto-fires
  `TERMINATE_PROCESS`/`BLOCK_FIREWALL_IP`/`ISOLATE_HOST`; the
  `COLLECT_PROCESS_INFO`/`COLLECT_NETWORK_CONNECTIONS` branches added
  earlier this program exist and are reachable, but only via an explicit
  `custom_action` no current rule sets. This is a real, pre-existing
  eyedetect authoring gap, not a Manager/Response-Engine defect, and is not
  in scope to fix by editing `vendor/eyedetect`.
  `test_safe_collection_auto_dispatches_without_analyst_action_and_succeeds`
  continues to plug in at the `translate_recommendation` boundary
  (monkeypatched) for exactly this reason, and is labeled BOUNDARY-LEVEL,
  not TRUE-PRODUCTION-E2E, deliberately.
- **CI:** `panopticon-manager` has no open PR at the time of writing; these
  changes were verified locally against CI's exact invocations
  (`pytest tests/`, `ruff check .`) and are pending a real GitHub Actions
  run on push. `panopticon-contracts`' fixture/lifecycle validation and its
  `banned-execution-pattern-scan` job were both re-run locally against all
  five implementer repos at their current HEADs (including the two
  newly-merged repos) with a clean result, matching the last real CI run on
  `panopticon-contracts` main (`b4a123e`, run 34774034342, success).
- **Isolation/robustness regression:** not re-run this phase.
  `panopticon-linux-agent` had no code or dependency change in this phase —
  the eyedetect pin bump and the two new Manager-side tests do not touch
  isolation, WFP/nftables, or the restart-recovery path — so the last
  real-CI evidence (3/3 consecutive green runs after the stale-socket-file
  fix) remains the current, valid evidence rather than being superseded or
  re-verified here.

## P1 closure: QUARANTINE_FILE wiring and schema 0.4 compatibility

Two genuine P1 correctness defects identified by a later readiness audit are
now fixed and TRUE-PRODUCTION-E2E-verified:

- **QUARANTINE_FILE dead-end (fixed).** Production rule `DET-PERS-007` set
  `active_response: QUARANTINE_FILE`, but
  `ActiveResponseEngine.resolve_action` (eyedetect) had no branch matching
  that `custom_action`, so the recommendation vanished before it ever
  reached `translate_recommendation`. Fixed in eyedetect commit `dcae72a`
  (adds the missing `resolve_action` branch) and response-engine commit
  `788f08a` (adds the matching `translate_recommendation` mapping to
  `{"path": target_file}`). Both endpoint agents, the wire contract
  (`command.schema.json`), and the Manager's authorization tier
  (`ANALYST_APPROVAL`) already fully supported `QUARANTINE_FILE` — only the
  detection-to-recommendation translation was missing. Proven by
  `tests/test_e2e_response_pipeline.py::test_quarantine_file_real_detector_recommendation_succeeds_via_internal_detection_bypass`:
  real `DET-PERS-007` match → real `resolve_action` → real `Alert` → real
  `AlertSink.emit` → real (unmocked) `translate_recommendation` →
  `QUARANTINE_FILE` command → analyst authorization → dispatch → accept →
  result → `SUCCEEDED` → full audit trail — **but that test drives
  `DetectionRun.process_event()` directly, not `POST /api/v1/ingest`**, so at
  the time this was first written it was mislabeled TRUE-PRODUCTION-E2E. A
  Phase 15 investigation found a second, independent bug hiding behind that
  mislabel: `DET-PERS-007`'s own YAML declared `event_type: file_write`, a
  value no real telemetry source ever produces (real Sysmon Event ID 11
  FileCreate and `OfficerIngestionAdapter` both synthesize `file_create`),
  so the rule was still unreachable through real ingest even after the
  `resolve_action` fix above. Fixed by correcting the rule's `event_type` to
  `file_create` (eyedetect commit `149003e`) — no adapter or wire-schema
  change was needed, since the same telemetry the adapter already produces
  was simply mislabeled in the rule. Status: **TRUE-PRODUCTION-E2E**, now
  genuinely proven from the wire boundary by
  `tests/test_real_ingest_detection_reachability.py::test_det_pers_007_is_reachable_through_real_post_ingest`
  (real `POST /api/v1/ingest` → real background `DetectionWorker` → real
  `OfficerIngestionAdapter` → real `RuleEvaluator` → `DET-PERS-007` → real
  `QUARANTINE_FILE` recommendation, authorized and dispatched — no
  `process_event()` bypass).
- **Schema 0.4 (Linux agent) compatibility (fixed).** eyedetect's
  `OfficerIngestionAdapter.SUPPORTED_SCHEMA_VERSIONS` and
  `src/ingestion/telemetry.SUPPORTED_SCHEMA_VERSIONS` were capped at
  `("0.1", "0.2", "0.3")`, while `panopticon-agent/schema/event.schema.json`'s
  own enum, `manager/routers/ingest.py`'s `_SUPPORTED_SCHEMA_VERSIONS`, and
  `panopticon-diagrams`' validator all already treated `"0.4"` (the Linux
  agent's schema version) as canonical. In practice a real 0.4 event was
  still accepted via a duck-typing fallback (its wire envelope is
  structurally identical to 0.2/0.3's), but the explicit acceptance list did
  not say so. Fixed in eyedetect commit `9e79b55`, with regression coverage
  using the exact wire shape `panopticon-linux-agent`'s
  `serialize_canonical_process_ndjson` emits. Vendored pin bumped to
  `9e79b55` in this repo.
- **Live-ingest identity gap — fixed, not merely documented.** The finding
  originally noted here (`transform_officer_event` silently dropping
  `start_time_ticks`) had a second, independent layer: this repo's own
  `manager/wire/telemetry.TelemetryEvent.ProcessMeta` never declared
  `start_time_ticks` either, so `POST /api/v1/ingest`'s own schema
  validation (`extra="forbid"`) would have rejected a real event carrying it
  regardless of the eyedetect-side fix. Both are now fixed: eyedetect commit
  `b554b5d` (passes the field through) and this repo's commit `b73dcce`
  (accepts it as an optional, nullable, non-negative field matching the
  canonical schema). Proven **TRUE-PRODUCTION-E2E** by
  `tests/test_e2e_response_pipeline.py::test_kill_process_true_live_ingest_preserves_pid_and_start_time_ticks`:
  a real event posted to the real `POST /api/v1/ingest` route, processed by
  the app's own background `DetectionWorker` thread (not test-driven),
  matching real production rule `DET-MALW-001`, produces a `KILL_PROCESS`
  command whose target is bit-for-bit equal to the original
  `{pid, start_time_ticks}` — the first test in this repo to prove process
  identity survives the actual wire ingestion path, as distinct from the
  existing TRUE-PRODUCTION-E2E tests, which call `DetectionRun.process_event`
  directly on an already-normalized event and never exercise
  `transform_officer_event` or `POST /api/v1/ingest` at all.

## Detection/response contract hygiene closure

A full source audit of every `active_response:` value across the 92-rule
eyedetect corpus (not trusting the prior phase logs above at face value)
found two categories of dishonest or unsafe response-capability claims and
fixed both:

- **Six non-closed-set rule values removed, not remapped.** 16 rules set
  `active_response` to `REVOKE_USER_SESSIONS` (8), `LOCK_USER_ACCOUNT` (2),
  `FORCE_PASSWORD_RESET` (2), `TERMINATE_POD_WORKLOAD` (2),
  `REVOKE_CLOUD_ACCESS_KEY` (1), or `RESTRICT_BUCKET_PERMISSIONS` (1) — none
  of which `ActiveResponseEngine.resolve_action` has ever had a branch for,
  and none of which has a real endpoint capability or a
  `translate_recommendation` mapping. These were **not** mapped onto an
  unrelated closed-set action (e.g. `REVOKE_CLOUD_ACCESS_KEY` was not turned
  into `ISOLATE_HOST`); the `active_response` field was removed from each
  rule instead, leaving detection semantics completely unchanged. Fixed in
  eyedetect commit `f86a8ce`.
- **A real bug, not just stale metadata: `resolve_action`'s severity default
  did not check whether the rule requested something else.**
  `ActiveResponseEngine.resolve_action`'s `ISOLATE_HOST` branch read
  `custom_action == "ISOLATE_HOST" or level >= 14` — the `level >= 14` half
  applied unconditionally, regardless of `custom_action`. This meant any of
  the 16 rules above with `level >= 14` (14 of the 16) were **not** actually
  failing closed as the prior phase logs in this document assumed — they
  were silently resolving to a real `ISOLATE_HOST` recommendation via this
  fallback, bypassing whatever the rule's own (unsupported) `active_response`
  requested. The same bug would have shadowed `QUARANTINE_FILE`/
  `COLLECT_PROCESS_INFO`/`COLLECT_NETWORK_CONNECTIONS` for any rule using
  those at `level >= 14` (none currently do, but nothing prevented it).
  Fixed in eyedetect commit `33b72f8` by gating the severity default on
  `custom_action is None`, matching the pattern the `TERMINATE_PROCESS`
  branch already used. Regression coverage in
  `tests/test_active_response_collect_actions.py::test_unsupported_active_response_fails_closed_even_at_isolate_host_severity`
  and its two companion tests (vendored via eyedetect commit `62d336a`).
- **`BLOCK_FIREWALL_IP` → `ISOLATE_HOST` opportunistic downgrade removed.**
  5 rules (`DET-NET-003`, `DET-WEB-001`, `DET-LAT-004`, `DET-NET-008`,
  `DET-WEB-003`) plus the internal C2 beacon detector's hardcoded
  `custom_action="BLOCK_FIREWALL_IP"` call all fed into a
  `response_engine.recommendation.translate_recommendation` branch that
  silently substituted a real `ISOLATE_HOST` command (full host isolation)
  for what eyedetect actually recommended (a narrow, IP-scoped block) — a
  "locked decision" documented in `panopticon-contracts/docs/CONTRACT.md`
  and `response-engine`'s own ADR-001, but the same category of dishonest,
  unrelated-action substitution this closure's own directive explicitly
  named as unacceptable (e.g. "`REVOKE_CLOUD_ACCESS_KEY` must NOT become
  `ISOLATE_HOST`"). There is no per-IP firewall action in the closed set and
  none was added; `translate_recommendation` now returns `None` for
  `BLOCK_FIREWALL_IP`, exactly like any other unsupported action. The `active_response: BLOCK_FIREWALL_IP` field was removed from the 5 rule
  files (detection semantics unchanged); the internal beacon detector's
  alert now correctly carries no `active_response`. Fixed in eyedetect
  commits `33b72f8`/`f86a8ce`, response-engine commit `cc61fcc`, and
  documented in `panopticon-contracts` commit `629116b`. Vendored pins
  bumped to eyedetect `62d336a` and response-engine `cc61fcc` in this repo.

**Final response-action disposition** (see `docs/DEMO.md` for the full
demo-facing matrix):

| Action | Status |
|---|---|
| `KILL_PROCESS` | See Phase 15 note below — not TRUE-PRODUCTION-E2E via `DET-INJ-001` |
| `ISOLATE_HOST` | TRUE-PRODUCTION-E2E |
| `QUARANTINE_FILE` | TRUE-PRODUCTION-E2E (via `DET-PERS-007`, real wire ingest, Phase 15) |
| `COLLECT_PROCESS_INFO` | IMPLEMENTED, CONTRACT-SUPPORTED, BOUNDARY-LEVEL / OPT-IN (no shipped rule opts in) |
| `COLLECT_NETWORK_CONNECTIONS` | IMPLEMENTED, CONTRACT-SUPPORTED, BOUNDARY-LEVEL / OPT-IN (no shipped rule opts in) |
| `COLLECT_FILE` | CONTRACT-SUPPORTED, IMPLEMENTED on both endpoint agents, DETECTION-UNWIRED (no `translate_recommendation` mapping, no rule requests it) |
| `RELEASE_HOST_ISOLATION` | Intentionally analyst/operator-initiated only, by design — never detection-triggered |

**Phase 15 `KILL_PROCESS` note:** the TRUE-PRODUCTION-E2E claim above was
grounded exclusively in `DET-INJ-001`, which a Phase 15 investigation
confirmed is not reachable through real `POST /api/v1/ingest` — its
`injection_type`/`target_process`/`source_process` fields cannot survive
the strict wire schema, and no endpoint collector observes process
injection at all (see the detailed entry earlier in this document). Other
real `TERMINATE_PROCESS`-mapped rules (`DET-CRED-001`, `DET-MALW-002`,
`DET-LAT-003`, and others) declare `event_type: process_create`, which real
telemetry does produce, so `KILL_PROCESS` is plausibly reachable through
one of them — but auditing all `TERMINATE_PROCESS`-mapped rules was out of
scope for a fix targeted specifically at `DET-INJ-001`/`DET-PERS-007`, so
this is not claimed here as verified.

No shipped rule requests `COLLECT_PROCESS_INFO`/`COLLECT_NETWORK_CONNECTIONS`
today; one was not manufactured purely to exercise the `AUTO_SAFE` path, per
this closure's own instruction not to invent rule coverage for symmetry.
`COLLECT_FILE` remains contract-supported and endpoint-implemented but with
no detection mapping, for the same reason — no shipped rule has a
semantically legitimate reason to request it today, and inventing one would
be coverage-chasing, not a real fix. The orphaned `EndpointRemediationEngine`
vocabulary noted above is unchanged by this closure (still simulated-only,
still not reconciled with the real Response Engine) — out of scope, not
newly discovered.

## Phase 13: agent enrollment cryptographic identity

`manager/auth.enroll()` now requires ECDSA P-256 proof of possession, not
just the shared bootstrap secret — see
`docs/adr/004-agent-enrollment-identity.md` for the full design and threat
model. Ongoing authenticated operations (telemetry, command polling, result
submission) are unchanged: still the pre-existing bearer-token check. A
concrete, previously-undiscovered gap was fixed alongside this: `host_id`
had no uniqueness constraint at all, so an unrelated `agent_id` could
previously enroll claiming an already-trusted endpoint's `host_id`
verbatim; `enroll()` now rejects that (`409`) while still allowing a
revoked endpoint's `host_id` to be legitimately re-enrolled under a fresh
identity. Twelve adversarial tests
(`tests/test_enrollment_identity.py`) cover valid enrollment, invalid/forged
signatures, key substitution, nonce replay/expiry, missing fields,
unauthorized bootstrap tokens, host_id takeover, and revoked-endpoint
rejection.
