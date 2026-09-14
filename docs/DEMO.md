# Panopticon Manager — Capstone Demo Runbook

Last verified: 2026-09-14, against `panopticon-manager` @ `main` (commit
`1be8b18`), `vendor/eyedetect` pinned at `98b1c18`, `vendor/response_engine`
pinned at `8b521aa`. Manager's full suite: **138 passed** (`pytest -v tests/`,
the exact invocation `.github/workflows/ci.yml` runs).

This runbook reproduces the same real, unmodified pipeline that
`tests/test_e2e_response_pipeline.py::test_kill_process_real_detector_recommendation_succeeds_with_a_true_production_path`
exercises automatically — the difference is you drive it by hand, over HTTP,
against a running Manager process, so a panel can watch each stage happen.

## What this demo honestly is (read this before promising anything to a panel)

- This demonstrates the **Detection Engine -> Alert -> Response Engine ->
  authorization -> dispatch -> execution result -> audit** chain running
  inside Manager against the real, vendored `eyedetect` rule set and the
  real `response_engine` translation/policy code — no hand-built
  `Alert`/`ActiveResponseAction`/recommendation anywhere in the path.
- The "agent" side of this demo is **simulated by curl/HTTP calls that mimic
  exactly what an enrolled endpoint agent does** (poll, accept, submit a
  result) — it does **not** involve a live Windows or Linux endpoint agent
  binary. `panopticon-agent` (Windows/"Officer") and `panopticon-linux-agent`
  both implement this same protocol for real, but running one live against
  this Manager instance requires a machine those agents actually target
  (Windows with ETW/Sysmon, or Linux with the isolation helper) — hardware
  not available in this session. If a physical/VM endpoint becomes
  available, the only change needed is to enroll the real agent and let it
  poll `/api/v1/agents/{agent_id}/commands` instead of curl.
- The injected "attack" is a **synthetic but schema-real** Schema 0.4
  `process_injection` event POSTed straight to Manager's ingest endpoint —
  not a live process-hollowing attack actually executed on an endpoint. It
  is byte-for-byte the same event shape
  `tests/test_e2e_response_pipeline.py::_process_injection_event` builds,
  chosen because it is what real production rule `DET-INJ-001`
  (`vendor/eyedetect/rules/process/DET-INJ-001_process_injection_hollowing.yaml`)
  actually matches on.
- "KILL_PROCESS" execution and "ISOLATE_HOST" execution are both **reported
  as results by the curl script, not actually performed on any host** — this
  MVP phase's remediation policy is dry-run/non-destructive by design (see
  root `CLAUDE.md`), so no process is really killed and no host is really
  isolated by this runbook, matching what the codebase actually does today.

## Prerequisites

- Python 3.10–3.12, `pip install -r requirements.txt -r vendor/eyedetect/requirements.txt`
  from `panopticon-manager/`.
- Submodules checked out: `git submodule update --init --recursive`.
- `curl` and `jq` (or just read the raw JSON) for the manual walk-through
  below. `jq` is optional — every example also works without it.
- Optional: `panopticon-console` checked out as a sibling directory, to show
  the read-only alert/response-queue viewer.

## 1. Start Manager

From `panopticon-manager/`:

```bash
export PANOPTICON_ENROLLMENT_TOKEN=demo-enrollment-secret
export PANOPTICON_COMMAND_TOKEN=demo-command-secret
export PANOPTICON_ANALYST_BOOTSTRAP_TOKEN=demo-analyst-bootstrap
uvicorn manager.app:app --host 127.0.0.1 --port 8000
```

(Check `manager/config.py` for the exact environment variable names this
checkout expects — bootstrap tokens gate agent/analyst enrollment; a fresh
SQLite DB is created and migrated automatically on first request.)

Confirm it's up:

```bash
curl -s http://127.0.0.1:8000/healthz
curl -s http://127.0.0.1:8000/readyz
```

## 2. Start the detection worker

The detection worker consumes ingested events and runs them through the
vendored `eyedetect` rule set (`vendor/eyedetect/rules`, 92 rules as of this
pin — see README.md). Follow `manager/detection/worker.py`'s entry point as
configured in this checkout (a background process or a management command,
per `docs/MANAGER_ARCHITECTURE.md`) — it must be running for ingested events
to become alerts.

## 3. Start the console (optional, for visual output)

From `panopticon-console/` (sibling checkout):

```bash
export PANOPTICON_MANAGER_TOKEN=<an analyst bearer token from step 4>
python app.py --alerts-file ../panopticon-detection-engine-output/alerts.ndjson \
  --manager-url http://127.0.0.1:8000
```

Open `http://127.0.0.1:8787`. This is a read-only viewer: it shows the alert
NDJSON file and proxies `GET /api/v1/response-actions` from Manager. It
cannot authorize, reject, or dispatch anything — those actions require a
direct authenticated call to Manager (curl, below), by design (see
`panopticon-console/app.py`'s module docstring).

## 4. Enroll an agent and an analyst

```bash
AGENT_TOKEN=$(curl -s -X POST http://127.0.0.1:8000/api/v1/agents/enroll \
  -H "Content-Type: application/json" \
  -H "X-Panopticon-Enrollment-Token: $PANOPTICON_ENROLLMENT_TOKEN" \
  -d '{"agent_id": "demo-agent", "host_id": "DEMO-HOST"}' | jq -r .token)

ANALYST_TOKEN=$(curl -s -X POST http://127.0.0.1:8000/api/v1/analysts/enroll \
  -H "Content-Type: application/json" \
  -H "X-Panopticon-Analyst-Bootstrap-Token: $PANOPTICON_ANALYST_BOOTSTRAP_TOKEN" \
  -d '{"analyst_id": "demo-analyst"}' | jq -r .token)

echo "agent token:   $AGENT_TOKEN"
echo "analyst token: $ANALYST_TOKEN"
```

(Exact header names come from `manager/routers/agents.py` /
`manager/routers/response_actions.py` — confirm against this checkout if
they've changed since this doc was last verified.)

## 5. Trigger real production rule DET-INJ-001

Post the same event shape the true-production-E2E test constructs
(`tests/test_e2e_response_pipeline.py::_process_injection_event`):

```bash
curl -s -X POST http://127.0.0.1:8000/api/v1/ingest \
  -H "Authorization: Bearer $AGENT_TOKEN" \
  -H "Content-Type: application/x-ndjson" \
  --data-binary '{
    "schema_version": "0.4",
    "event_id": "evt_9999999999999999999999999999999999999999999999999999999999999999",
    "event_type": "process_injection",
    "host_id": "DEMO-HOST",
    "timestamp": "2026-09-14T12:00:00.000Z",
    "process": {"pid": 4433, "start_time_ticks": 133012345670000000},
    "source_process": {"name": "winword.exe", "pid": 5150},
    "target_process": {"name": "lsass.exe", "pid": 4433},
    "injection_type": "ProcessHollowing"
  }'
```

**Expected stage-by-stage output:**

1. **Detection** — the worker's next poll cycle runs this event through the
   real `RuleEvaluator`; `DET-INJ-001` matches (`target_process.name` in the
   protected set, `injection_type: ProcessHollowing`).
2. **Alert** — a row appears in `alerts` (`rule_id = 'DET-INJ-001'`). Verify:
   ```bash
   curl -s http://127.0.0.1:8000/api/v1/alerts \
     -H "Authorization: Bearer $ANALYST_TOKEN" | jq '.[] | select(.rule_id=="DET-INJ-001")'
   ```
3. **Recommendation / Response Engine translation** — `response.on_alert_created`
   calls the real `translate_recommendation`, which maps the real
   `ActiveResponseAction(action="TERMINATE_PROCESS", target_start_time_ticks=...)`
   to a `KILL_PROCESS` recommendation. A `response_actions` row appears,
   `lifecycle_state = PENDING`, `tier = ANALYST_APPROVAL`:
   ```bash
   curl -s http://127.0.0.1:8000/api/v1/response-actions \
     -H "Authorization: Bearer $ANALYST_TOKEN" | jq '.'
   ```

## 6. Authorization

```bash
RESPONSE_ID=<response_id from the previous step's output>
curl -s -X POST http://127.0.0.1:8000/api/v1/response-actions/$RESPONSE_ID/authorize \
  -H "Authorization: Bearer $ANALYST_TOKEN"
```

**Expected**: `200`, `lifecycle_state` -> `AUTHORIZED`, a `commands` row is
created with `action = "KILL_PROCESS"` and
`target = {"pid": 4433, "start_time_ticks": 133012345670000000}` — the
same original tick value observed on the triggering event, never re-derived.

## 7. Dispatch (agent poll)

```bash
curl -s http://127.0.0.1:8000/api/v1/agents/demo-agent/commands \
  -H "Authorization: Bearer $AGENT_TOKEN" | jq '.'
```

**Expected**: one `KILL_PROCESS` command, `lifecycle_state` -> `DISPATCHED`,
carrying a `correlation_id` you'll need for the result below.

## 8. Acceptance

```bash
COMMAND_ID=<command_id from the previous step>
curl -s -X POST http://127.0.0.1:8000/api/v1/agents/demo-agent/commands/$COMMAND_ID/accept \
  -H "Authorization: Bearer $AGENT_TOKEN"
```

**Expected**: `200`, `lifecycle_state` -> `ACCEPTED`.

## 9. Result (simulated execution)

```bash
curl -s -X POST http://127.0.0.1:8000/api/v1/agents/demo-agent/command-results \
  -H "Authorization: Bearer $AGENT_TOKEN" -H "Content-Type: application/json" \
  -d '{
    "result_id": "demo-result-1",
    "command_id": "'"$COMMAND_ID"'",
    "outcome": "succeeded",
    "detail": "process terminated",
    "correlation_id": "<correlation_id from step 7>"
  }'
```

**Expected**: `200`, `lifecycle_state` -> `SUCCEEDED`.

## 10. Audit trail

```bash
curl -s http://127.0.0.1:8000/api/v1/commands/$COMMAND_ID/audit \
  -H "Authorization: Bearer $ANALYST_TOKEN" | jq '.'
```

(If no dedicated audit-read route exists in this checkout, inspect the
`command_audit` table directly — the test asserts the exact sequence
`["created", "dispatched", "accepted", "result_received"]`.) The console's
response-actions panel also reflects the final `SUCCEEDED` state if it was
started in step 3.

## Optional: PID-reuse rejection scenario

Repeat steps 5–7 with a fresh `event_id`/`host_id`/`agent_id`, but for step 9
report a **failure** instead, exactly as
`tests/test_kill_process_pid_reuse_is_rejected_on_a_true_production_path`
does:

```bash
curl -s -X POST http://127.0.0.1:8000/api/v1/agents/demo-agent-2/command-results \
  -H "Authorization: Bearer $AGENT_TOKEN_2" -H "Content-Type: application/json" \
  -d '{
    "result_id": "demo-result-pidreuse",
    "command_id": "'"$COMMAND_ID_2"'",
    "outcome": "failed",
    "detail": "identity mismatch: live process start_time_ticks=133012999999999999 != command target start_time_ticks=133012345670000000; refusing to terminate",
    "correlation_id": "<correlation_id_2>"
  }'
```

This demonstrates the security property live, without a real reused PID:
the dispatched command's `target.start_time_ticks` never changes after the
detector first observed it (verify this directly from step 7's output for
this second run), so an honest endpoint's own T1-vs-T2 comparison is what
would refuse the kill — Manager's job is only to never silently re-resolve
that value, which this scenario proves by inspection of the dispatched
payload.

## Cleanup

- Stop `uvicorn`, the detection worker process, and the console (Ctrl+C
  each).
- Delete the demo SQLite database file (path from `manager/config.py`,
  typically a `.db` file in the working directory or a configured data dir)
  if you want a clean slate for a repeat run.
- Rotate/discard the demo bootstrap tokens used above — they are not
  intended for anything beyond this local walk-through.

## Known environment limitations (state these plainly to a panel)

- **No live endpoint agent in this demo.** Both `panopticon-agent`
  (Windows/"Officer") and `panopticon-linux-agent` implement the real
  poll/accept/execute/result protocol this runbook simulates with curl, but
  running either live requires hardware this session does not have (a
  Windows host with ETW/Sysmon, or a Linux host/VM with the isolation
  helper's privileged capabilities). The manager-side pipeline proven here
  is identical either way — only the "who executes the command" side is
  substituted.
- **No real process is terminated and no real host is isolated.** Per the
  project's MVP remediation policy, "execution" here is a human/script
  reporting a result, not a live `TerminateProcess`/WFP/nftables call —
  this matches the codebase's actual current capability, not a simplification
  invented for the demo.
- **`COLLECT_PROCESS_INFO` / `COLLECT_NETWORK_CONNECTIONS`** can be shown
  dispatching automatically (`AUTO_SAFE`, no analyst step) only by directly
  calling `manager.detection.response.on_alert_created` with a
  monkeypatched `translate_recommendation`, as
  `tests/test_e2e_response_pipeline.py::test_safe_collection_auto_dispatches_without_analyst_action_and_succeeds`
  does — no real, currently-shipped `eyedetect` rule sets a
  `custom_action` that reaches either mapping, so this scenario cannot be
  triggered by posting a real event to `/api/v1/ingest` today. Do not
  demonstrate this path as if a real detection produced it.
- **`COLLECT_FILE`, `QUARANTINE_FILE`, `RELEASE_HOST_ISOLATION`** have no
  `response_engine.translate_recommendation` mapping at all (verified by
  reading `vendor/response_engine/response_engine/recommendation.py`) — they
  can only be demonstrated by posting a raw, hand-crafted
  `POST /api/v1/commands` directly (bypassing detection entirely), which
  `tests/test_response_contract.py` does for wire-schema validation. Do not
  claim these are detection-triggered in a live demo.
