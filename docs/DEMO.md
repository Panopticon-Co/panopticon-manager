# Panopticon Manager — Capstone Demo Runbook

Last verified: 2026-09-14, against `panopticon-manager` @ `main` (commit
`1be8b18`), `vendor/eyedetect` pinned at `98b1c18`, `vendor/response_engine`
pinned at `8b521aa`. Manager's full suite: **138 passed** (`pytest -v tests/`,
the exact invocation `.github/workflows/ci.yml` runs).

## Phase 14 addendum: what was actually run live, and two corrections

A Phase 14 verification pass ran this pipeline against a **real** Manager
process (uvicorn over genuine TLS with a self-signed demo certificate) and
the **real** `panopticon-linux-agent` binary (built and executed inside a
real Ubuntu 24.04 container, not a mock), plus a real local MSVC build of
`panopticon-agent`. It reached further than this runbook's curl-simulated
walkthrough in one respect and found two things this runbook previously got
wrong:

- **Enrollment, identity persistence, revocation, and durable replay-after-
  revocation were all proven with the real Linux agent binary**, not curl:
  first-run enrollment, a restart that reused the same identity without
  re-enrolling, a live revocation (server-side `revoked_at`) that caused the
  agent's subsequent authenticated telemetry to be genuinely rejected (401)
  while the agent durably retained the undelivered events in its spool
  instead of dropping them, and a legitimate re-enrollment under a fresh
  `agent_id` that reclaimed the same `host_id` and successfully replayed the
  previously-stuck spool contents once trust was restored.
- **A real, agent-observed detection was also proven**: a genuine process
  (`bash -c 'echo /dev/tcp/127.0.0.1/9; sleep 6'`, chosen to contain the
  substring `/dev/tcp/` in its command line without ever actually opening a
  socket) was launched, observed by the real agent's live `/proc` collector,
  delivered over genuinely-verified TLS, and matched production rule
  `DET-LNX-001` for a real `Alert` row — no crafted event, no bypass.
- **A real QUARANTINE_FILE command was fully executed end-to-end by the real
  agent binary**: dispatched via the raw command-token route (a direct
  enqueue, not a rule match — see the correction below for why), the live
  agent polled it, accepted it, moved a real disposable file into a real
  quarantine directory, and reported a result that produced the full
  `["created", "dispatched", "accepted", "result_received"]` audit trail and
  a `SUCCEEDED` lifecycle state.
- **Correction 1 — the curl payloads in Sections 5 and the crafted event in
  "Trigger real production rule DET-INJ-001" above are not valid against the
  current wire schema** (`manager/wire/telemetry.py`'s `TelemetryEvent`,
  `extra="forbid"`): a real ingest call needs the full nested
  `event`/`source`/`agent`/`host`/`user`/`process` shape, not the flat shape
  shown above. The flat shape predates a schema tightening and was never
  re-verified against a live call.
- **Correction 2 (Phase 14, since fixed for one of the two rules in Phase
  15) — `DET-INJ-001` and `DET-PERS-007` were not actually reachable
  through a real `POST /api/v1/ingest` call**, contrary to this file's
  earlier "TRUE-PRODUCTION-E2E" label for `QUARANTINE_FILE`. Root causes
  turned out to be different for each rule:
  - **`DET-PERS-007` (fixed in Phase 15).** The rule's own YAML declared
    `event_type: file_write`, a value no real telemetry source ever
    produces — real Sysmon Event ID 11 FileCreate observations (already
    collected live by `panopticon-agent`'s
    `sysmon_telemetry_decoder.cpp`) and `OfficerIngestionAdapter` both
    synthesize `file_create`, exactly matching the already-correct sibling
    rule `DET-FILE-001`. The fix was a one-line rule correction
    (`event_type: file_write` -> `file_create`, eyedetect commit
    `149003e`) — no adapter or wire-schema change was needed, since the
    telemetry the adapter already produces was simply mislabeled in the
    rule. Now genuinely proven reachable from the wire boundary by
    `panopticon-manager/tests/test_real_ingest_detection_reachability.py`.
  - **`DET-INJ-001` (still not reachable — this requires new telemetry
    collection, out of scope for a rule/adapter fix).** Its
    `injection_type`/`target_process`/`source_process` fields have no
    place in the strict wire schema at all (`extra="forbid"`), and no
    endpoint collector observes process injection in the first place —
    `panopticon-agent`'s Sysmon decoder has no case for Event ID 8
    (CreateRemoteThread) or 10 (ProcessAccess), and the Linux agent has no
    equivalent mechanism either. Closing this gap means adding genuinely
    new OS-level telemetry collection, not correcting a mapping.
  Both rules were, and `DET-INJ-001` still is, genuinely exercised by
  `tests/test_e2e_response_pipeline.py` only through `run.process_event(event)`
  — an internal test helper that calls the same detection/response code
  Manager runs in production, but bypasses the wire-schema/adapter layer
  entirely. That inner path is real and unmocked; treat any claim that a
  specific rule is "TRUE-PRODUCTION-E2E" as meaning "reachable via a real,
  schema-valid `POST /api/v1/ingest`," and verify it the way this addendum
  did, not by trusting the rule's own YAML label.
- **Windows**: the real `officer-agent.exe` (rebuilt locally with MSVC,
  11/11 CTest passing including `officer-keypair-tests`) could not reach
  live enrollment in this environment because it refuses to proceed past
  collector startup with zero working telemetry collectors
  (`src/main.cpp`, `return 4` when `started == 0`), and both ETW
  (`StartTraceW`) and the already-installed `Sysmon64` service
  (`EvtSubscribe`) returned a real "Access is denied" without local
  Administrator elevation or "Event Log Readers" membership, neither of
  which this non-interactive session can grant itself. This is an honest
  environment limitation, not a code defect — the same enrollment/identity
  code underneath is already proven by CI and by 11/11 local CTest.

This runbook reproduces the same real, unmodified pipeline that
`tests/test_e2e_response_pipeline.py::test_kill_process_real_detector_recommendation_succeeds_via_internal_detection_bypass`
exercises automatically — the difference is you drive it by hand, over HTTP,
against a running Manager process, so a panel can watch each stage happen.
Note the corrected test name: per the Phase 15 addendum below, this
particular scenario (DET-INJ-001 / process_injection) is proven at the
internal detection-engine level, not through a real `POST /api/v1/ingest`
call — the manual walkthrough here injects the same crafted event Manager
would receive if a real endpoint could produce it, which today none can
(see the addendum for why).

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

Phase 13 requires the agent to prove possession of a locally-generated
ECDSA P-256 private key before Manager will issue it a bearer token — see
`docs/adr/004-agent-enrollment-identity.md`. `openssl` stands in here for
what the real agent's own key generation/signing does natively (Windows
CNG / OpenSSL respectively):

```bash
openssl ecparam -genkey -name prime256v1 -noout -out /tmp/demo-agent-key.pem

NONCE=$(curl -s -X POST http://127.0.0.1:8000/api/v1/agents/enrollment-challenge | jq -r .nonce)
echo -n "$NONCE" | base64 -d > /tmp/nonce.bin
openssl dgst -sha256 -sign /tmp/demo-agent-key.pem -out /tmp/sig.bin /tmp/nonce.bin
SIGNATURE=$(base64 -w0 /tmp/sig.bin)
# The last 65 bytes of a P-256 SubjectPublicKeyInfo are exactly the raw
# uncompressed point (0x04 || X || Y) this contract expects.
PUBLIC_KEY=$(openssl ec -in /tmp/demo-agent-key.pem -pubout -outform DER 2>/dev/null | tail -c 65 | base64 -w0)

AGENT_TOKEN=$(curl -s -X POST http://127.0.0.1:8000/api/v1/agents/enroll \
  -H "Content-Type: application/json" \
  -H "X-Panopticon-Enrollment-Token: $PANOPTICON_ENROLLMENT_TOKEN" \
  -d "{\"agent_id\": \"demo-agent\", \"host_id\": \"DEMO-HOST\", \"public_key\": \"$PUBLIC_KEY\", \"nonce\": \"$NONCE\", \"signature\": \"$SIGNATURE\"}" | jq -r .access_token)

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

## 5. Trigger real production rule DET-PERS-007

> This section previously demonstrated `DET-INJ-001` with a flat, simplified
> event shape. Neither works against this checkout: the flat shape is
> rejected by the strict wire schema, and `DET-INJ-001` cannot be reached by
> any real ingest payload regardless of shape (see the Phase 15 correction
> above). This section now uses `DET-PERS-007`, which a Phase 15 real-ingest
> test (`tests/test_real_ingest_detection_reachability.py`) confirms actually
> works end to end. To see the `DET-INJ-001`/`KILL_PROCESS` internal-only
> path instead, run
> `tests/test_e2e_response_pipeline.py::test_kill_process_real_detector_recommendation_succeeds_via_internal_detection_bypass`.

Post a full, wire-schema-valid `TelemetryEvent` (`manager/wire/telemetry.py`)
representing a real Sysmon Event ID 11 FileCreate observation in a Windows
Startup folder — the exact shape `panopticon-agent`'s Sysmon collector
produces, and the same shape
`tests/test_real_ingest_detection_reachability.py` posts:

```bash
curl -s -X POST http://127.0.0.1:8000/api/v1/ingest \
  -H "Authorization: Bearer $AGENT_TOKEN" \
  -H "X-Panopticon-Batch-Id: demo-batch-1" \
  -H "X-Panopticon-Agent-Id: demo-agent" \
  -H "X-Panopticon-Protocol: 1" \
  -H "Content-Type: application/x-ndjson" \
  --data-binary '{
    "schema_version": "0.4",
    "event": {"id": "evt_9999999999999999999999999999999999999999999999999999999999999999", "category": "file", "type": "create", "timestamp": "2026-09-14T12:00:00.000Z"},
    "source": {"kind": "sysmon", "provider": "Microsoft-Windows-Sysmon", "channel": "Microsoft-Windows-Sysmon/Operational", "record_id": 1},
    "agent": {"id": "demo-agent", "version": "0.1.0"},
    "host": {"id": "DEMO-HOST", "hostname": "DEMO-HOST", "os": {"name": "Windows 11 Pro", "build": "26100"}},
    "user": {"name": null, "domain": null, "sid": null},
    "process": {"entity_id": "proc_dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd", "pid": 6001, "name": "explorer.exe", "executable": "C:\\Windows\\explorer.exe", "command_line": "C:\\Windows\\explorer.exe", "start_time_ticks": null, "parent": {"entity_id": null, "pid": 600, "name": "userinit.exe"}, "hash": {"sha256": null}},
    "file": {"operation": "create", "path": "C:\\Users\\victim\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\evil.exe", "target_path": null, "previous_path": null, "hash": {"sha256": null}}
  }'
```

**Expected stage-by-stage output:**

1. **Detection** — the worker's next poll cycle runs this event through the
   real `RuleEvaluator`; `DET-PERS-007` matches (`file.path` under a Windows
   Startup folder). The same event also legitimately matches `DET-FILE-001`
   (a detection-only sibling rule, no `active_response`) — expect two alert
   rows, not a bug.
2. **Alert** — a row appears in `alerts` (`rule_id = 'DET-PERS-007'`). Verify:
   ```bash
   curl -s http://127.0.0.1:8000/api/v1/alerts \
     -H "Authorization: Bearer $ANALYST_TOKEN" | jq '.[] | select(.rule_id=="DET-PERS-007")'
   ```
3. **Recommendation / Response Engine translation** — `response.on_alert_created`
   calls the real `translate_recommendation`, which maps the real
   `ActiveResponseAction(action="QUARANTINE_FILE", target_file=...)` to a
   `QUARANTINE_FILE` recommendation. A `response_actions` row appears,
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
created with `action = "QUARANTINE_FILE"` and
`target = {"path": "C:\\Users\\victim\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\evil.exe"}` —
the same original path observed on the triggering event, never re-derived.

## 7. Dispatch (agent poll)

```bash
curl -s http://127.0.0.1:8000/api/v1/agents/demo-agent/commands \
  -H "Authorization: Bearer $AGENT_TOKEN" | jq '.'
```

**Expected**: one `QUARANTINE_FILE` command, `lifecycle_state` -> `DISPATCHED`,
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
    "detail": "file quarantined",
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

This scenario is specific to process-identity-sensitive actions
(`KILL_PROCESS`), not the file-based `QUARANTINE_FILE` walkthrough in
Section 5 above, so it cannot be reproduced by repeating steps 5–7 verbatim
— those now use `DET-PERS-007`, a file target with no PID at all. It is
proven only at the internal detection-engine level by
`tests/test_e2e_response_pipeline.py::test_kill_process_pid_reuse_is_rejected_via_internal_detection_bypass`
(see the corrected KILL_PROCESS note above for why DET-INJ-001 cannot
currently drive this live over HTTP). To reproduce the underlying security
property manually against a `KILL_PROCESS` command obtained any other way
(e.g. a raw `POST /api/v1/commands` via the command token), report a
**failure** for step 9 instead of success:

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
- **`QUARANTINE_FILE`** is now a real, detection-triggered,
  **TRUE-PRODUCTION-E2E from the actual wire boundary** (Phase 15): production
  rule `DET-PERS-007` (a `file_create` event under a Windows Startup folder
  or a Linux `/etc/init.d`/`rc.local` path — corrected from the
  wire-unreachable `file_write` this file previously described) sets
  `active_response: QUARANTINE_FILE`. Two independent proofs exist:
  `panopticon-manager/tests/test_real_ingest_detection_reachability.py::test_det_pers_007_is_reachable_through_real_post_ingest`
  drives it through a real `POST /api/v1/ingest` call (no bypass), and
  `tests/test_e2e_response_pipeline.py::test_quarantine_file_real_detector_recommendation_succeeds_via_internal_detection_bypass`
  proves the full chain from an internally-injected event through to a
  `SUCCEEDED` result and audit trail. It can be demonstrated live the same
  way as the `KILL_PROCESS` scenario above, substituting a startup-folder
  `file_create` event for the process-injection one — and unlike
  `KILL_PROCESS`, that substitute event is now genuinely something a real
  Windows agent's Sysmon collector can and does produce.
- **`COLLECT_FILE`, `RELEASE_HOST_ISOLATION`** have no
  `response_engine.translate_recommendation` mapping at all (verified by
  reading `vendor/response_engine/response_engine/recommendation.py`) — they
  can only be demonstrated by posting a raw, hand-crafted
  `POST /api/v1/commands` directly (bypassing detection entirely), which
  `tests/test_response_contract.py` does for wire-schema validation. Do not
  claim these are detection-triggered in a live demo.
- **`BLOCK_FIREWALL_IP`** (an eyedetect recommendation string, never a
  closed-set action) has no mapping either, and deliberately so: an earlier
  version of `translate_recommendation` "downgraded" it to a real
  `ISOLATE_HOST` command, silently substituting full host isolation for a
  narrow, IP-scoped block. That substitution was removed as an opportunistic,
  unrelated-action mapping. A rule or the internal C2 beacon detector may
  still request it, but no command is ever produced — do not demonstrate it
  as if it isolates or blocks anything.

### Final response-action disposition

| Action | Status |
|---|---|
| `KILL_PROCESS` | See note below — not TRUE-PRODUCTION-E2E via `DET-INJ-001` |
| `ISOLATE_HOST` | TRUE-PRODUCTION-E2E |
| `QUARANTINE_FILE` | TRUE-PRODUCTION-E2E |
| `COLLECT_PROCESS_INFO` | BOUNDARY-LEVEL / OPT-IN (implemented, contract-supported; no shipped rule opts in) |
| `COLLECT_NETWORK_CONNECTIONS` | BOUNDARY-LEVEL / OPT-IN (implemented, contract-supported; no shipped rule opts in) |
| `COLLECT_FILE` | CONTRACT-SUPPORTED, IMPLEMENTED on both endpoint agents, DETECTION-UNWIRED |
| `RELEASE_HOST_ISOLATION` | ANALYST-INITIATED (intentionally never detection-triggered) |

**`KILL_PROCESS` note (Phase 15):** this file and `docs/RESPONSE_ENGINE_STATE.md`
previously called `KILL_PROCESS` TRUE-PRODUCTION-E2E on the strength of
`DET-INJ-001`, which is now confirmed wire-unreachable (see Correction 2
above) — that specific citation was wrong. Other real, shipped rules that
also map to `active_response: TERMINATE_PROCESS` (e.g. `DET-CRED-001`,
`DET-MALW-002`, `DET-LAT-003`) declare `event_type: process_create`, a
value real telemetry genuinely produces, so `KILL_PROCESS` is plausibly
reachable via one of those — but this was not verified with a real-ingest
test in this phase (auditing all `TERMINATE_PROCESS`-mapped rules was out
of scope for a fix targeted at `DET-INJ-001`/`DET-PERS-007`). Do not cite
`KILL_PROCESS` as TRUE-PRODUCTION-E2E without a real-ingest test backing a
specific rule, the same way `test_real_ingest_detection_reachability.py`
now does for `DET-PERS-007`.
