# New Linux VMware lab: enrollment and verification

Recorded setup: 21-22 October 2026 (IST). Documentation and limited read-only
follow-up: 25 October 2026. This report covers the new lab, superseding the VM
inventory in the September [lab progress update](SHREYAS_LAB_PROGRESS_UPDATE.md).

## Lab inventory

| VM name | Private address | Role |
| --- | --- | --- |
| `PANO-NEW-MGR` | `10.77.10.10` | Manager, detection and response dependencies, console |
| `PANO-NEW-LNX-01` | `10.77.10.21` | First enrolled Linux endpoint |
| `PANO-NEW-LNX-02` | `10.77.10.22` | Second enrolled Linux endpoint |

These are VMware inventory names, not a claim about the agents' internal
`agent_id` or `host_id` values. The older September names must not be used as
evidence of the new agents' internal identities.

The Linux telemetry demonstration uses these three VMs on the private VMnet10
network. The 22 October report records the older VM sets as powered off.
Windows host telemetry was also active separately; this was not an exclusively
Linux lab. A Windows VM was additionally powered on at the 25 October check.

## Persistent enrollment and storage

The 22 October local run report records both Linux endpoints as enrolled with
an active 60-second agent timer. Their enrolled identities survived endpoint
reboots. Manager enrollment, database, HTTPS and console survived Manager
reboots. The three new VMs were configured to start at Windows sign-in through
the `PanopticonLabVMs` scheduled task.

VM files are stored under `C:\PanopticonLab\VMs\<VM-name>` on the Windows host.
The Manager's enrollment records reside inside its virtual disk, in the guest
database at `/var/lib/panopticon-manager/panopticon.db`. Each endpoint keeps its
own identity and authentication material inside its guest filesystem.
Persistence means normal restarts retain enrollment; deleting state or
restoring an older snapshot can change that state.

The Manager virtual disk was expanded from 10 GB to 40 GB. A local cold backup
from before expansion is at
`C:\PanopticonLab\Backups\PANO-NEW-MGR-before-expand`; this is historical
recovery material, not evidence of a current backup.

GitHub contains source and documentation. Committing this report neither enrolls
another endpoint nor transfers an existing enrollment. VM images, database
copies, private keys, tokens and endpoint credentials are not part of this
change.

## Recorded Linux verification: 22 October

The local `output/simulation-status-2026-10-22.md` report records:

- 27,276 Linux events stored and processed by detection at its last check.
- Nine alerts in the Manager at that check; no per-endpoint breakdown is
  asserted here.
- A harmless disposable Linux process with `curl | bash` in a shell comment
  triggered `DET-LNX-006`.
- An analyst-authorized `KILL_PROCESS` command stopped the disposable target
  and produced a successful result and audit entries.
- A separate `COLLECT_PROCESS_INFO` command completed.
- Both Linux enrollments and the Manager state survived their recorded VM
  reboot checks.

These are historical results, not a fresh simulation or a current count. The
report does not identify which endpoint executed each response action, so it
does not establish that both endpoints independently passed every response
scenario.

## Read-only follow-up: 25 October

- VMware listed all three new Linux-lab VMs as running.
- Manager `https://10.77.10.10/readyz` returned
  `{"status":"ready","schema_version":13}`.
- Console `https://10.77.10.10:8443/` returned HTTP 200.
- Fresh SSH inspection of the two Linux endpoints was blocked by host-key
  mismatches against the host's existing `known_hosts` entries. Those entries
  were not changed and verification was not bypassed. Confirm the guest keys
  through a trusted VM console before updating saved SSH identities.

No simulation, response command, restart or enrollment was performed for this
documentation update. Readiness and console availability alone do not prove
current endpoint telemetry delivery; that requires a fresh authenticated
inspection of agent state and Manager event timestamps.

## Setup and verification handoff

This is an inventory and verification handoff, not a complete automated
provisioning package. Use the repository's
[VMware implementation guide](VMWARE_IMPLEMENTATION.md) for the broader setup,
while applying the new inventory above and checking current agent instructions.

For a fresh lab:

1. Create a Manager and two Linux endpoints with unique identities on the
   private network. Do not clone an already-enrolled endpoint identity.
2. Deploy explicitly recorded source revisions, configure Manager persistence
   and trusted HTTPS, and configure each endpoint for that Manager.
3. Enroll each endpoint using locally provisioned credentials. Protect its
   identity and authentication state and keep all credentials out of Git.
4. Configure the endpoint service/timer and VM startup persistence. Verify
   enrollment, new event timestamps and state retention after normal restarts.

For the existing lab, inspect enrollment and delivery before attempting any
re-enrollment. Manager readiness and console checks are read-only. Through a
trusted guest administration route, confirm the two agent services/timers and
their unique registered identities, then compare Manager per-agent event
timestamps/counts over a timer interval. Do not publish raw identity files or
database exports as verification evidence.

## Source boundary

At publication preparation, GitHub Manager `main` was `12b393b` and Linux-agent
`main` was `a33b8dc`. Existing Linux enrollment implementation is already in
the Linux-agent repository.

The local Manager branch `codex/windows-record-ingest` at `dcce5ee` contains four
additional commits involving Windows ingestion and telemetry metrics. They are
excluded from this documentation branch. This report does not claim that
GitHub `main` reproduces every feature of the locally deployed Manager.
Windows integration changes require separate review.
