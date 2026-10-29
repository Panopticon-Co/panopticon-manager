# Mac session → Windows session: status

Coordination file for tonight's demo integration (see `docs/DEMO_LIVE.md`).
Only the Mac session edits this file. The Windows session reports back in
`panopticon-agent` branch `demo/windows-validation`, `docs/demo/WINDOWS_STATUS.md`.

## Manager branch `demo/live-integration`: READY TO DEPLOY at c399ee3

- **Base:** `origin/main` `add66c0`. The submodule pins are unchanged (engine `9697e6b`,
  response engine `83b8a46`).
- **Changes:**
  - **The detection worker can no longer die silently.** If the rules fail to load, it
    records `fatal_error`. A failing cycle is logged and counted, and the loop continues. A
    write-lock timeout before a record runs retries that record instead of marking it
    `failed`. Stale claims are reverted every lease period, not only at startup.
  - **`/readyz` returns 503 when the worker is not alive**, with the reason and
    `fatal_error`. `/metrics` has `panopticon_detection_worker_up`.
  - **`/api/v1/status`** adds `endpoint_records{pending,claimed,done,failed}`,
    `last_record_at` and `detection_worker{alive,fatal_error,heartbeat_age_seconds,loop_errors}`.
    The live agent's records were previously invisible there.
  - **Startup scripts:**
    - `tools/demo_up.sh` is the one-command start, stop and verify.
    - `tools/demo_check.py` is the re-runnable OK/WARN/FAIL check.
    - `tools/demo_cert.py` makes a self-signed certificate for the no-nginx fallback.
  - **`tests/test_live_demo_path.py`:** canonical records go over HTTP through the worker to
    `GET /api/v1/alerts` (DET-PROC-008, DET-PERS-002, DET-CRED-003 and DET-PROC-003 fire;
    benign `notepad`/`whoami` stay silent), and the status counts are checked.
- **Verified on the Mac:**
  - The manager suite has 469 passed. The 8 failures are environmental and identical before
    and after: 7 freshness tests need Linux `CLOCK_BOOTTIME`, and 1 compares against a stale
    sibling agent checkout.
  - `demo_up.sh` goes from cold to all-green in about 3 s.
  - Synthetic records posted over HTTP reached `done` in about 1 s, with 4 rule alerts plus
    CORR-RISK-001, and the console reads them from the Manager.
- **Deploy:** follow `docs/DEMO_LIVE.md` §1. Stop `panopticon-manager.service` **and**
  `panopticon-console.service` first, because they hold ports 8000 and 8787. Point
  `--state-dir` at a volume with room (check with `df -h`).

## Contract for `tools/demo/demo-up.ps1`: read files, don't parse output

- **Check out anywhere.** `demo_up.sh` resolves its own repo root. It uses `./.venv/bin/python`
  when present, otherwise `--python`. The console is `../panopticon-console` unless you pass
  `--console-dir`.
- **Exit status.** `tools/demo_up.sh ...` exits 0 only when the full stack is verified
  green, and non-zero with a log tail on any failure. It detaches (`nohup`), so it returns
  over SSH. It is safe to re-run after `--stop`.
- **State files** under `--state-dir` (one line each; read them with `ssh ... cat`):
  - `manager.url`: the local Manager URL, e.g. `http://127.0.0.1:8000`.
  - `console.url`: the local console URL, e.g. `http://127.0.0.1:8787`.
  - `bootstrap.token`: copy this into the guest as `C:\pano\bootstrap.token`.
  - `analyst.token`: the console's analyst bearer, for API checks.
  - `db.path`, plus `manager.log`, `console.log`, `manager.pid` and `console.pid`.
- **Readiness check:** `.venv/bin/python tools/demo_check.py --state-dir <dir>` exits 0
  when nothing is FAIL. It is a Python script, not `demo_check.sh`.
- **Stop:** `tools/demo_up.sh --stop --state-dir <dir>`.
- **Agent flags**, exactly as `demo_up.sh` prints them:
  `--source all --manager-url https://10.77.10.10 --enable-response --bootstrap-token-path
  C:\pano\bootstrap.token --identity-path C:\pano\identity --keypair-path C:\pano\agent.key
  --spool-directory C:\pano\spool-demo`. Use a new spool dir and no identity file for a
  fresh DB.
- **Console from the host:** `ssh -L 8787:127.0.0.1:8787 <user>@10.77.10.10`, then browse
  `http://127.0.0.1:8787`.

## Console branch `demo/live-integration`: READY at 86b01c9

- **Changes:**
  - The alert feed has a **Host** column.
  - The pipeline tiles count the agent's canonical records. Before, they read
    "0 processed / No events yet" during a working live run.
  - The sidebar note says whether the detection worker is running.
- **Verified:** console unit tests (78 Python, 13 Node) pass, as does the manager's
  `tools/verify_response_console.py --governance`.
- **Deploy:** check out this branch in `../panopticon-console`, next to the manager
  checkout. That is the default `--console-dir` for `demo_up.sh`.

## Asks for the Windows session

1. Report in `WINDOWS_STATUS.md`:
   - the agent build SHA and binary sha256;
   - time from trigger to alert;
   - `pending` during the first 10 minutes;
   - DB growth per 10 minutes;
   - whether Defender blocked certutil.
2. Note whether one trigger produces **two** alerts for the same rule. The agent reports a
   process start from both ETW and Sysmon with different identities, so a single
   `whoami /priv` can appear twice. That is expected behavior, not a bug, but the presenter
   should know before the audience sees it. Record it in `WINDOWS_STATUS.md`.
3. Export the `raw_json` of the trigger records (`SELECT raw_json FROM endpoint_records
   WHERE ...`) to `docs/demo/captures/` so the Mac can add them as a real-telemetry
   regression fixture.
