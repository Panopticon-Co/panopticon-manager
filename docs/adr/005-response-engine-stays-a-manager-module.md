# ADR 005: Response Engine stays a bounded module inside Manager — no separate deployable

- Status: **Superseded by ADR 006** (2026-09-13, same day) — this ADR's
  no-separate-deployable conclusion still holds and is unchanged, but its
  no-separate-repository conclusion was reconsidered: this ADR conflated
  "no network service" with "no separate repository," treating them as the
  same question. A repository boundary and a deployment boundary turned out
  to be independent — Manager already vendors `panopticon-detection-engine`
  as an in-process git submodule, proving exactly that. See ADR 006 for the
  corrected reasoning; the deployment-model argument below (one process, no
  network hop, no microservice) is preserved unchanged in ADR 006.
- Date: 2026-09-13

## Context

A later development pass asked, before writing any more Response Engine code,
whether "Response Engine" should become its own repository and/or its own
deployed service, now that ADR 004 has it working end-to-end (alert →
recommendation → tier classification → `response_actions` staging →
`authorize_and_enqueue` → typed `commands` row → agent poll/result). The
Panopticon workspace's standing architecture is logical services on one
deployable backend (root `CLAUDE.md`): a separate git repository does not by
itself imply a separate deployed process, and this workspace's own roadmap
explicitly defers Kubernetes/queues/service-discovery/API-gateways until a
demonstrated technical requirement exists. This ADR records why the audit
that preceded it did not manufacture one.

Audit method: read `manager/detection/response.py`, `manager/routers/
response_actions.py`, `manager/routers/commands.py`, `manager/auth.py`,
`manager/migrations.py`, all four `docs/adr/*.md` in this repo, and the
equivalent response/command/isolation code in `panopticon-linux-agent`,
`panopticon-console`, and `panopticon-detection-engine`, plus running this
repo's own test suite (`uv run pytest -q tests/` — 84 passed). No functional
change preceded this decision; this ADR ratifies what ADR 004 already built,
against the explicit "logical services, one deployable" framing.

## Decision

**Keep the Response Engine as a strongly separated logical module inside the
Manager deployable (option A in the terms above), not a new repository and
not a new deployed service.**

- **Ownership boundary**: `manager/detection/response.py` (recommendation
  translation, tier classification, lifecycle staging) and `manager/routers/
  response_actions.py` (the analyst-facing HTTP surface) own the Response
  Engine's domain and application logic outright. Nothing outside these two
  files decides whether a recommendation becomes a command.
- **Package/API boundary**: enforced by a single function, not a network
  call. `authorize_and_enqueue()` (`manager/routers/commands.py:82-141`) is
  the sole path that ever writes a `commands` row; the raw
  `POST /api/v1/commands` endpoint and `authorize_response_action()` are its
  only two callers, so validation (target-agent enrollment, expiry, closed
  action/target schema) can never drift between the manual and
  recommendation-driven paths. This is the same guarantee a service boundary
  would give (one enforced contract, one set of invariants), at in-process
  function-call cost instead of network cost.
- **Dependency direction**: Response Engine code depends on `manager.db`,
  `manager.auth`, and `manager.routers.commands` — never the reverse, and
  never on `vendor/eyedetect` internals beyond the `Alert.active_response`
  dict shape already read by `on_alert_created()`. Detection Engine
  (`vendor/eyedetect`, called from `manager/detection/factory.py` and
  `manager/detection/worker.py`) depends on nothing in the Response Engine;
  it only produces an `Alert`, and `AlertSink.emit` hands that `Alert` to
  `on_alert_created()` after the alert row is durably committed.
- **Deployment model**: one process, one `uvicorn` app, one SQLite database.
  There is no second thing to deploy, version, or keep alive. AUTO_SAFE
  authorization happens synchronously inside the same per-event transaction
  the detection worker already holds (`manager/detection/worker.py`'s
  `BEGIN IMMEDIATE`) — a real network hop here would turn one atomic
  detect-and-respond transaction into a distributed one for no operational
  benefit at current scale (a single-analyst-team, single-Manager-instance
  EDR MVP).
- **Integration model**: Detection → Response is a Python function call
  (`on_alert_created`). Response → Endpoint Agent is the existing typed HTTP
  command queue (`GET /api/v1/agents/{id}/commands`,
  `POST /api/v1/agents/{id}/command-results`), already OS-agnostic — see
  "Cross-platform boundary" below. Response → Console/analyst is the existing
  `response_actions` REST surface, consumed through Console's same-origin
  proxy (unchanged by this ADR).
- **Testing model**: unit and integration tests live in `panopticon-manager/
  tests/` alongside the rest of Manager's test suite (`test_response_engine.py`,
  `test_response_actions_route.py`) and run in the same `pytest` invocation,
  the same CI job, against the same in-process `TestClient` — no separate
  test harness, no contract-testing framework, no service mesh to fake out.
- **Versioning strategy**: the Response Engine has no independent version.
  It ships with Manager's own version/release cadence. The only versioned
  artifact it touches is the `commands` payload's `schema_version` field
  (`manager/routers/commands.py:110`, currently `"1"`), which is Manager's
  wire contract with agents, not a Response-Engine-specific concern.

**Why the repository boundary would not provide value here**: the audit
found no evidence of a second team, a second release cadence, an
independent scaling requirement, or a language/runtime mismatch that would
justify the operational cost of a second deployable — the classic reasons to
split a service out. `response.py` and `response_actions.py` together are
~350 lines, fully covered by the existing 84-test suite, and their only
consumers (the detection worker and the analyst HTTP client) are already
in-process or already HTTP, respectively. Splitting them into a separate
repo would add a network hop to the AUTO_SAFE auto-fire path (currently
transactionally atomic with the alert write), a second set of credentials to
manage, and a second deployment to keep in sync with Manager's schema
migrations — costs with no corresponding benefit at this scale.

**Why this does not need a microservice deployment**: nothing about the
Response Engine's workload (low request volume, single-writer SQLite,
single-analyst-team approval queue) benefits from independent scaling,
independent failure isolation, or a different runtime than the rest of
Manager. The frozen security model requires that the *only* code path from
recommendation to typed command is `authorize_and_enqueue()` — an in-process
function call is a strictly stronger guarantee of that invariant than a
second service trusting a second network boundary would be.

## Consequences

- No new repository, no new CI pipeline, no new deployment target was
  created as a result of this audit.
- Two real, narrowly-scoped gaps in the existing in-Manager implementation
  were found and are fixed in the same change that adds this ADR (see
  `docs/RESPONSE_ENGINE_STATE.md` for the full list): (1) `command_results`
  had no guard against a second, differently-`result_id`'d result flipping
  `commands.lifecycle_state` after a terminal outcome already landed; (2) no
  `response_actions` or `commands` row ever transitions to `EXPIRED` — a
  `PENDING` response action or an `AUTHORIZED` command that times out simply
  becomes unpollable/unauthorizable forever, with no lifecycle record of why.
- Larger, genuinely cross-repo gaps were found and are *not* addressed in
  this change, because they require careful, security-reviewed design work
  beyond a Manager-only audit pass: the Windows agent (`panopticon-agent`,
  "Officer") implements no command-polling or response-execution path at
  all (telemetry-only today), and `TERMINATE_PROCESS` can still never map to
  `KILL_PROCESS` because no process-creation-timestamp data flows from
  Detection Engine's correlation layer through `ActiveResponseAction` — both
  are recorded as prioritized next tasks in `docs/RESPONSE_ENGINE_STATE.md`
  rather than rushed.
- The 7-action enum remains independently hand-maintained in at least four
  places (`manager/routers/commands.py`, `manager/detection/response.py`,
  `panopticon-linux-agent/include/panopticon/linux_agent/command.hpp`, and
  implicitly in any future Windows agent implementation), consistent with
  `panopticon-linux-agent`'s own ADR 001 ("shares the wire contract, not
  source code; a future contracts package is deferred") and root
  `CLAUDE.md`'s explicit instruction not to scaffold `panopticon-contracts`
  before a milestone justifies it. This is an accepted, currently-verified-
  consistent duplication, not an oversight — worth a shared contracts
  package only once a second consumer language change or a real drift
  incident makes the manual-sync cost outweigh the premature-abstraction
  cost.
