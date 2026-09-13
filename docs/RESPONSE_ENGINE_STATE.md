# Response Engine — implementation state / handoff

Last updated: 2026-09-13, after a second Manager-focused pass that
implemented the `ACCEPTED` lifecycle state. This document exists so a future
session (or a compacted context) can reconstruct exactly what is real, what
is verified, and what is next, without re-deriving it from scratch.
Re-verify against the actual repos before trusting anything here as still
current — treat this as a snapshot, not a source of truth.

**Outstanding**: commits `ccc25d2`, `f777ff6`, `b1553b1` are pushed to
`origin/feat/response-engine-extraction-and-fixes` in `panopticon-manager`
but `gh pr create` has failed repeatedly with transient GitHub API 502/
GraphQL errors (an external outage, not a local problem — `git push` itself
succeeds every time). Open the PR manually or retry `gh pr create` once
GitHub recovers:
`https://github.com/Panopticon-Co/panopticon-manager/compare/main...feat/response-engine-extraction-and-fixes`

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
  `BLOCK_FIREWALL_IP`, `ISOLATE_HOST`. Carries no process-start-time field.
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

1. **`ACCEPTED` is implemented in Manager but not yet adopted by any real
   agent.** `POST /api/v1/agents/{agent_id}/commands/{command_id}/accept`
   exists, is authenticated, idempotent, and tested (see above) — but
   neither `panopticon-linux-agent` nor a Windows agent has been changed to
   actually call it. It is deliberately optional/backward-compatible (a
   result from plain `DISPATCHED` still works), so this is not a breaking
   gap, just an unfinished adoption: the Linux agent's poll/execute/report
   loop could call `accept()` right after it validates a command and before
   it starts executing, giving Manager a real "the endpoint has this and is
   about to run it" signal instead of only ever seeing DISPATCHED-then-
   terminal. Not done in this pass because it requires a `panopticon-linux-
   agent` change (out of a Manager-only session's repo) and, once Windows
   exists, the same there.
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
3. **The Windows agent (`panopticon-agent`, "Officer") implements no
   response/command path at all** — confirmed telemetry-only by grep across
   the entire repo for command-polling, `KILL_PROCESS`/`ISOLATE_HOST`
   handling, or any HTTP client beyond telemetry upload. The Response
   Engine's Manager-side design is already OS-agnostic (it just addresses
   commands by `agent_id`), so nothing here blocks a Windows implementation
   — but the implementation itself (poll loop, process termination via the
   Windows API, host isolation via WFP/Windows Firewall, a Windows-side
   equivalent of the Linux isolation helper's privilege separation) is a
   substantial, standalone engineering effort not started in this pass.
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

1. Get this Manager-only pass's changes reviewed and merged (PR creation is
   currently blocked by a transient GitHub API outage — see top of this
   document); watch CI go green on the actual GitHub Actions run (not just
   local `pytest`/`ruff`).
2. Update `panopticon-linux-agent`'s command-execution loop to call the new
   `accept()` endpoint right after it validates a dispatched command and
   before it starts executing, so `ACCEPTED` actually appears in practice
   instead of only being reachable via a direct test/API call. This is a
   small, additive change to that repo (one new outbound HTTP call in its
   existing poll/execute/report loop) — no wire-contract change was needed
   in Manager to support it, since `accept()` was designed to be optional.
3. Design and review the `TERMINATE_PROCESS -> KILL_PROCESS` start-time
   threading as its own ADR in `panopticon-detection-engine`, with explicit
   attention to PID-reuse correctness, before writing code.
4. Only after 3 is designed: implement, in order, (a) the correlation
   engine change, (b) the Manager translation update, (c) an end-to-end test
   proving a real `Level >= 12` process-creation detection can produce an
   analyst-approval-gated `KILL_PROCESS` command and that authorizing it
   dispatches correctly.
5. Windows agent response support is a separate, large body of work — scope
   it as its own milestone rather than folding it into a Response Engine
   pass.
6. Add the isolation-helper crash/IPC-fuzz tests to `panopticon-linux-agent`
   (item 4 above) — genuinely still outstanding from the prior directive's
   explicit ask and not touched in either Manager pass, since it requires
   that repo's C++/CMake/Linux build environment.

## Known blockers

None that block further Manager-side work. Items 2 and 3 above are
correctness-sensitive design decisions, not "blocked," and should not be
rushed past design review.
