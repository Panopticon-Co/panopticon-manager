# Manager Threat Model

**Updated 2026-09-13.** This was a stub through Phase 4; a dedicated
adversarial security review (attack, not just read) has since covered most
of its originally planned scope. This document records what that review
actually proved, not what is merely designed to be true. Full narrative and
regression-test references live in `docs/RESPONSE_ENGINE_STATE.md`'s
"eighth" and "ninth" pass sections — this file is the durable summary,
that one is the dated lab notebook.

## Identity boundaries — CODE-VERIFIED + test-verified by active attack

`tests/test_adversarial_security.py` attacks these directly rather than
just reading source:

- Agents and analysts are genuinely separate identity spaces
  (`enrolled_agents` vs. `analyst_credentials`): an agent's bearer token
  cannot authenticate as an analyst and vice versa.
- The shared `system:command-token` (used only for the raw
  `/api/v1/commands` POST used by non-agent internal callers) cannot be
  presented as a `Bearer` token to authenticate as either an agent or an
  analyst.
- `response_id` is the sole authorization scope for
  `/api/v1/response-actions/{id}/authorize` — a forged/guessed `response_id`
  404s, and authorizing one response action never touches a different,
  unrelated one's `lifecycle_state` or `command_id`.
- Revoking a credential (`revoked_at` set) takes effect on the very next
  request, including mid-flight command result submission — no caching or
  grace window.
- Malformed/hostile `Authorization` headers (empty, bare `"Bearer"`, wrong
  scheme, a 10,000-character token) are rejected cheaply, before any digest
  comparison.

## Fixed: agent-identity takeover via the shared enrollment secret

`manager.auth.enroll()` used to `INSERT OR REPLACE` against
`enrolled_agents`, so re-POSTing `/api/v1/agents/enroll` for an
already-enrolled `agent_id` silently overwrote its `host_id` and minted a
fresh bearer token — no audit trail distinguished this from first-time
provisioning. Since `PANOPTICON_ENROLLMENT_TOKEN` is necessarily one
shared, fleet-wide secret (not per-agent), anyone holding it could hijack
any already-trusted agent's identity and rebind it to a host_id of their
choosing. **Fixed**: a plain `INSERT` now raises `sqlite3.IntegrityError`
into a `409` on re-enrollment of an existing `agent_id`, leaving the
original binding/token untouched. There is still no revoke-then-re-enroll
flow — a separate, not-yet-built feature, not a reason this fix is
incomplete. Regression coverage:
`tests/test_adversarial_security.py::test_re_enrolling_an_existing_agent_id_is_rejected_not_silently_overwritten`.

## Command/result contract-level protections — CODE-VERIFIED

- The wire `Command` contract's PID-reuse gate (positive-integer,
  non-zero `start_time_ticks`; `extra="forbid"` on `target`) rejects a
  missing/zero/negative `start_time_ticks` and rejects a smuggled extra
  target field (e.g. a `shell_command` key riding alongside a valid `pid`)
  at validation time, independent of the caller.
- `accept()`/`submit_result()` against a fabricated `command_id` that was
  never queued are both rejected (`422`), never silently accepted.
- A `CommandResult.correlation_id`, if present, must match the stored
  command's own `correlation_id` or the result is rejected
  (`manager/routers/commands.py`).
- Hostile/malformed request bodies (non-JSON, truncated, oversized, wrong
  field types, null for required fields, deeply nested JSON, huge integers,
  duplicate JSON keys) against `/api/v1/commands` and
  `/api/v1/agents/{id}/command-results` fail closed with `400`/`422`, never
  a crash or a partial write — see `tests/test_hostile_input_commands.py`.
- A repository-wide banned-execution-pattern scan of `manager/` (`system(`,
  `popen(`, `exec*`, `/bin/sh`, `/bin/bash`, `bash -c`, `sh -c`,
  `shell=True`, `EXECUTE_COMMAND`) found no occurrence in response-path
  code.

## Explicitly NOT claimed

- **No multi-tenancy.** All analysts see all alerts/agents/hosts by design
  — this is single-tenant software. The security review above is careful
  to distinguish this (a visibility decision) from authorization/integrity
  (an analyst cannot forge approval, cannot bypass the KILL_PROCESS
  approval tier, cannot manipulate another response action's lifecycle) —
  the latter is what was actually attacked and verified, the former is an
  accepted product decision, not a vulnerability.
- **Telemetry-contains-credentials handling** (process command lines
  routinely carry passwords/tokens) has not had a dedicated redaction pass
  — this remains open, unaddressed scope, not silently resolved.
- **TLS pinning failure modes and agent-key-at-rest-under-DPAPI local-admin
  threats** are Windows-agent-side concerns (`panopticon-agent`) rather
  than Manager-side; see that repository's own security documentation
  rather than assuming this file covers them.
- **SQL injection / unbounded-query surface** in the filtered alert query
  API has not had a dedicated adversarial pass distinct from the general
  hostile-input work above; `manager/routers/alerts.py` uses parameterized
  queries throughout by inspection, but this has not been actively
  attacked the way the command/result and auth surfaces have.
