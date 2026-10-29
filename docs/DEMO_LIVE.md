# Live demo: Windows agent → Manager → detection → alerts → console

The real path, with no seeded data: the Officer agent in the Windows guest sends canonical
records over verified HTTPS to `POST /api/v2/endpoint/records`. The Manager stores them in
`endpoint_records`, the one detection worker runs the pinned rules, and alerts are persisted.
They are then served by `GET /api/v1/alerts`, and the console shows them through its Manager
proxy.

Lab layout (VMnet10, see `VMWARE_IMPLEMENTATION.md`):
- Manager VM `pano-new-mgr` at `10.77.10.10`, with nginx terminating TLS on 443 using the
  lab CA.
- Windows guest at `10.77.10.31`. The lab CA is already in its LocalMachine\Root store.

## 0. Before you start

- Power on both VMs and log in to the Windows guest. This is manual.
- **Disk.** The Manager's data volume `/srv/panopticon-data` (40 GB, `/dev/sdb`) was 100% full
  on 2026-10-30, holding the 39 GB Oct 27–28 database. The agent produces roughly 40 KB per
  record, at tens of thousands of records an hour once inventories and event logs flow, and
  nothing prunes telemetry.
  - Run the agent only for rehearsal and the demo, and stop it right after.
  - `demo_check.py` prints free space, and `demo_up.sh` refuses to start below 3 GB
    (override with `MIN_FREE_GB=N` only for a short run).
- **One Manager only.** Stop the lab's systemd units (`panopticon-manager.service` and
  `panopticon-console.service`) before `demo_up.sh`. `demo_up.sh` refuses to start if
  port 8000 or 8787 is already taken.

## 1. Start Manager + console (manager VM)

```bash
cd ~/panopticon-manager   # branch demo/live-integration, submodules initialised
git submodule update --init --recursive
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt -r vendor/eyedetect/requirements.txt
sudo systemctl stop panopticon-manager.service panopticon-console.service
tools/demo_up.sh --fresh --bind 127.0.0.1:8000 --public-url https://10.77.10.10 \
  --state-dir /srv/panopticon-data/demo-state
```

- Use `--bind` with whatever upstream address the nginx site proxies to.
- `--fresh` renames any previous demo DB instead of deleting it.
- The script verifies, rather than assumes, each of these:
  - `/readyz` returns 200, which now also requires the detection worker to be alive;
  - analyst enrollment works;
  - the console answers and reads alerts from the Manager;
  - free disk is above the minimum.
- It prints the agent command line and exits non-zero with the relevant log tail on any
  failure.
- Re-check at any time with `.venv/bin/python tools/demo_check.py --state-dir <dir>`.
- Stop with `tools/demo_up.sh --stop --state-dir <dir>`.

**Console from the Windows host.** The console binds to loopback by default because it holds
an analyst token and has no login of its own:

```
ssh -L 8787:127.0.0.1:8787 pano@10.77.10.10   # then browse http://127.0.0.1:8787
```

You can widen it deliberately with `--console-bind 10.77.10.10:8787` on the host-only
network.

**No nginx (fallback).** The Manager can terminate TLS itself:

```bash
python tools/demo_cert.py --san <manager-ip> --san 127.0.0.1 --out <dir>/tls
tools/demo_up.sh --fresh --bind 0.0.0.0:8443 --tls <dir>/tls/cert.pem <dir>/tls/key.pem \
  --public-url https://<manager-ip>:8443
```

Then, in the guest, run `certutil -addstore -f Root cert.pem`.

## 2. Start the agent (Windows guest, elevated)

1. Copy `<state-dir>/bootstrap.token` to `C:\pano\bootstrap.token`.
2. A fresh Manager DB needs a fresh agent identity:
   - delete `C:\pano\identity` if it exists;
   - use a **new** spool directory, because an old spool replays its backlog into the new DB.
3. Run:

```powershell
officer-agent.exe --source all --manager-url https://10.77.10.10 --enable-response `
  --bootstrap-token-path C:\pano\bootstrap.token --identity-path C:\pano\identity `
  --keypair-path C:\pano\agent.key --spool-directory C:\pano\spool-demo
```

Expect a few 401s until enrollment completes, then 200s. `demo_check.py` should then show
`agents 1 enrolled` and `records queue ... done` climbing.

- The first minutes include the event-log backlog. Start the agent 5–10 minutes before
  presenting so the queue (`pending`) has drained.
- **409 then 401 on enrollment** means the agent id is already in this DB. Either start the
  Manager with `--fresh`, or delete the identity file and reuse the existing enrollment.

## 3. Trigger detections (Windows guest)

Each command is harmless and read-only, or creates and then removes a demo artefact.

| Step | Command | Expected in the console |
|---|---|---|
| benign | `notepad.exe` (close it), then `whoami` | nothing new |
| 1 | `whoami /priv` | DET-PROC-008, medium |
| 2 | `schtasks /create /tn PanopticonDemo /tr notepad.exe /sc once /st 23:59 /f` then `schtasks /delete /tn PanopticonDemo /f` | DET-PERS-002, medium |
| 3 | `cmdkey /list` | DET-CRED-003, high. A KILL_PROCESS recommendation is staged under **Response actions** and waits for an analyst; nothing runs automatically. |
| 4 | `certutil -urlcache -split -f http://www.msftconnecttest.com/connecttest.txt %TEMP%\ct.txt` | DET-PROC-003, high. Defender may block the download, but the process-start alert still fires. |
| 5 | `reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v PanopticonDemo /t REG_SZ /d notepad.exe /f` then `reg delete ... /v PanopticonDemo /f` | DET-PERS-001, high. Needs Sysmon EID 13. |

- Several high-severity detections on one host can also raise the correlation alert
  CORR-RISK-001.
- Each alert's detail view shows the host, the process, the full command line, MITRE
  technique and tactic, and the recommended response.
- The same path is covered offline by `tests/test_live_demo_path.py`, which uses synthetic
  records, not endpoint telemetry.

## 4. If something is red

| `demo_check.py` says | Do |
|---|---|
| manager `/readyz 503 detection worker not alive` | Read `manager.log` (`fatal_error` names the cause), then restart: `--stop`, then `demo_up.sh` (no `--fresh`). Pending records are re-claimed. |
| records `failed > 0` | Read `manager.log` for `detection failed for event_id=`. Other records keep flowing. |
| `pending` keeps growing | The worker is behind the agent's backlog. Wait, or start the agent earlier. |
| agents 0 enrolled | Check the agent console for TLS or 401 errors. Confirm the token file and that the identity file is gone. |
| disk FAIL | Stop the agent. Move old `*.bak` DBs off the VM before deleting anything. |

**Fallback if the live path is down at presentation time:** start the stack on the preserved
DB from the last successful rehearsal (`demo_up.sh` without `--fresh`, on that state dir).
Those alerts are genuine detections from that rehearsal; present them as recorded at their
`created_at` time.
