# ADR 006: extract the Response Engine's domain contract into panopticon-response-engine

- Status: accepted
- Date: 2026-09-13
- Supersedes: ADR 005's no-separate-repository conclusion (its
  no-separate-deployment conclusion is preserved, not reversed)

## Context

ADR 005 audited whether the Response Engine (built in ADR 004) should
become its own repository and/or its own deployed service, and concluded
neither was justified — reasoning that a small, fully-tested, in-process
module had no independent scaling or team boundary that would justify a
network service. That conclusion about a *microservice* was correct, but
it answered a broader question than was asked: whether a repository
boundary requires a deployment boundary. It does not, and this codebase
already proves it — `vendor/eyedetect` (ADR 001) is a separate repository
consumed entirely in-process via a git submodule, with no network hop and
no independent deployment.

A follow-up architectural review made this distinction explicit: Panopticon
already follows a repository-per-domain convention across
`panopticon-agent`, `panopticon-linux-agent`, `panopticon-detection-engine`,
`panopticon-manager`, and `panopticon-console`. Consistent with that
convention, and consistent with `vendor/eyedetect`'s own precedent, the
Response Engine's *domain logic* (as opposed to its persistence and HTTP
wiring, which stay in Manager) is cohesive enough to warrant its own
repository: recommendation translation, tier classification, the closed
action/target contract, and the lifecycle state machine are all pure,
side-effect-free logic with no dependency on Manager's SQLite schema, its
FastAPI routers, or its authentication.

## Decision

**Extract that pure domain/contract logic into
[`panopticon-response-engine`](https://github.com/Panopticon-Co/panopticon-response-engine),
consumed by Manager as a pinned git submodule at `vendor/response_engine`,
installed editable (`pip install -e vendor/response_engine`) into Manager's
own process. One deployable backend, unchanged from before this ADR — no
network RPC, no second service, no Kubernetes/queue/service-mesh
infrastructure of any kind.**

What moved out of Manager, verbatim (behavior-preserving — all 87 of
Manager's existing tests pass unchanged after this extraction):

- `manager/routers/commands.py`'s `Action` Literal, `Command`, and
  `CommandResult` (with their target-schema validation) -> now
  `response_engine.contract`, imported back into `commands.py` and
  re-exported so every existing `from manager.routers.commands import
  Command` call site is unaffected.
- `manager/detection/response.py`'s `_TIERS` dict and `classify_tier()` ->
  now `response_engine.policy` (`Tier` enum + `classify_tier`).
- `manager/detection/response.py`'s `translate_recommendation()` -> now
  `response_engine.recommendation`, unchanged in behavior.
- A **new** canonical lifecycle state machine
  (`response_engine.lifecycle.ResponseActionState` /
  `is_legal_transition`) that did not exist as code anywhere before this
  extraction -- it formalizes the transition rules that were previously only
  implicit in scattered SQL `WHERE lifecycle_state = '...'` guards across
  `commands.py` and `response_actions.py`. It is not yet wired into
  Manager's persistence layer as an enforced check (see "Consequences"
  below) -- it exists so the rule is written down once, testable in
  isolation, and available to enforce against later.

What stayed in Manager, unchanged: all persistence (`response_actions`/
`commands` tables and migrations), all HTTP transport (FastAPI routers,
analyst/agent bearer-token authentication), and all orchestration
(`on_alert_created`, `authorize_response_action`, `reject_response_action`,
`expire_stale_response_actions`, `_expire_stale_commands`, the duplicate-
result guard added earlier this session).

See `panopticon-response-engine`'s own `docs/adr/001-repository-boundary.md`
for the full ownership/dependency-direction/versioning reasoning, and its
`docs/OWNERSHIP.md` for the precise boundary.

## Consequences

- Manager's `requirements.txt` gains `-e ./vendor/response_engine`; CI's
  existing `pip install -r requirements.txt -r vendor/eyedetect/
  requirements.txt` step picks it up automatically (no separate install
  step needed), and `actions/checkout`'s existing `submodules: recursive`
  already fetches it.
- `manager/routers/commands.py` and `manager/detection/response.py` no
  longer contain any hand-maintained copy of the action enum, target
  schema, tier table, or recommendation-translation logic -- they import all
  four from `response_engine`.
- The new lifecycle module (`response_engine.lifecycle`) is not yet
  consulted by Manager's actual state transitions -- `commands.py` and
  `response_actions.py` still transition state via direct SQL `UPDATE`
  statements guarded by `WHERE lifecycle_state = '...'` clauses, which
  happen to already be consistent with the canonical state machine (verified
  by inspection, not by a shared runtime check). Wiring
  `is_legal_transition` in as an actual guard on every transition is
  legitimate follow-up work, not done in this pass to avoid changing
  Manager's persistence code and its contract-extraction in the same
  breath -- see `docs/RESPONSE_ENGINE_STATE.md`.
- The `ACCEPTED` lifecycle state and the `TERMINATE_PROCESS -> KILL_PROCESS`
  process-start-time gap (both already documented as missing in
  `docs/RESPONSE_ENGINE_STATE.md` before this extraction) are unaffected by
  this ADR -- extracting the contract did not, by itself, add the missing
  agent-side acknowledgement protocol or the missing correlation-engine
  timestamp threading. Those remain real, separately-scoped follow-up work.
- Bumping the Response Engine contract is now the same one-command operation
  `vendor/eyedetect` already has: `git submodule update --remote vendor/
  response_engine` + a commit, with the exact version pinned and auditable.
