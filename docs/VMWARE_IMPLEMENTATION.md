# VMware implementation record

Started 2026-09-13. Deployment acceptance gates have NOT passed.

## Recheck — 14 September 2026

- All four VMX files are present under C:\PanopticonLab\VMs. All guests were
  powered off. Each VM has NAT plus a custom VMnet10 adapter.
- Windows host VMnet10 is now configured at 10.77.10.1/24. The initial preflight
  below is historical; the four-VM installation has since been completed.
- Created and verified powered-off `10-networked-clean` snapshots for PANO-MGR,
  PANO-LNX-01 and PANO-LNX-02 after finding that no snapshots existed.
- Windows snapshot inspection through vmrun requires the VM encryption password;
  verify or create its baseline through VMware's unlocked UI. Do not record the
  password in this document.
- Free host disk: approximately 98.3 GiB; free physical RAM: approximately 2.8 GiB
  at inspection. Free memory before starting the 8 GiB Manager guest.
- Manager tests rerun: 90 passed, with existing dependency deprecation warnings.
  Ruff and git diff whitespace checks passed. Detection submodule remains pinned.
- Working trees are clean except for the known uncommitted Manager acceptance
  implementation, its tests and lab documents. Remote CI has not been run.
- Guest health, services and post-reboot network persistence were not rechecked
  while guests were off. Panopticon deployment remains the next task.

## Host preflight

- VMware Workstation is installed; no guests were running during inspection.
- Only an existing Debian guest is registered. It uses NAT and resides under
  OneDrive. Leave it untouched; create dedicated lab guests outside OneDrive.
- Host RAM: 15.7 GiB. C: free space: approximately 135 GiB.
- VMnet1 and VMnet8 exist; VMnet10 is not present in the host adapter inventory.
- The playbook calls for at least 200 GB free SSD space. Free space or attach a
  suitable SSD before building the complete four-guest lab and snapshots.
- Existing download names include Windows 11 25H2 x64 and Ubuntu 26.04 Desktop.
  Their provenance/checksums have not been verified. Obtain Ubuntu Server 24.04
  LTS amd64 from https://releases.ubuntu.com/24.04/ for the Linux guests.

## Guest installation handoff

Create VMnet10 in Workstation's elevated Virtual Network Editor: host-only,
10.77.10.0/24, DHCP disabled, host adapter enabled. Verify its host address
(normally 10.77.10.1). Do not configure bridging or port forwarding.

Install guests one at a time, starting with PANO-MGR. Use a nonsynced SSD
directory such as C:\PanopticonLab\VMs after resolving storage capacity.

| Guest | OS | vCPU | RAM | Disk | Host-only address |
| --- | --- | --- | --- | --- | --- |
| PANO-MGR | Ubuntu Server 24.04 LTS | 4 | 8 GB | 80 GB | 10.77.10.10/24 |
| PANO-LNX-01 | Ubuntu Server 24.04 LTS | 2 | 4 GB | 35 GB | 10.77.10.21/24 |
| PANO-LNX-02 | Ubuntu Server 24.04 LTS | 2 | 4 GB | 35 GB | 10.77.10.22/24 |
| PANO-WIN-01 | Windows 11 Pro | 4 | 8 GB | 80 GB | 10.77.10.31/24 |

These are the playbook allocations. With this 16 GB host, do not run all guests
together. Even Manager + one Linux guest consumes 12 GB. Start with those two;
Windows testing needs either a RAM upgrade or a separately validated reduced
allocation for Manager. Do not start Manager + Windows at their full allocations.

Each guest: first NIC Custom VMnet10, optional second NIC NAT for installation.
The host-only interface has no default gateway; only the temporary NAT NIC
supplies internet routing. On Ubuntu, select OpenSSH server during installation,
use a unique local account, update the OS and install open-vm-tools. Set the
hostname and static address, and map manager.internal to 10.77.10.10.
For Windows use UEFI, Secure Boot and a virtual TPM as required by the installer.

Shut down after installation and take 00-os-clean and then 10-networked-clean
snapshots at their respective stages. Disconnect NAT before response testing.
Record VMX path, username and static address; never put passwords here.

## First code change

Linux already calls POST /api/v1/agents/{agent_id}/commands/{command_id}/accept
with its bearer token and an empty body. Manager lacked that route at its
recorded revision. It now atomically transitions DISPATCHED to ACCEPTED and
writes one agent-attributed audit event. Duplicate acceptance is idempotent;
wrong-agent, missing, expired, undispatched and terminal commands are rejected.
Acceptance records validation, not successful execution. The existing result
path still permits a result if the best-effort acceptance acknowledgement was
lost. No database migration or change to the seven-action vocabulary is needed.

Validation: Manager's full suite passed locally on Windows/Python 3.12
(90 tests, including 6 new acceptance cases); Ruff passed. Existing dependency
deprecation warnings remain. Existing GitHub CI discovers the new tests through
its tests/ invocation. Remote CI and Linux/Windows guest execution have not run.

## Remaining integration work, in order

1. G0: guest installation, isolated network, storage and snapshot evidence.
2. G1-G2: pinned Manager + Console deployment, single worker, persistent paths,
   trusted TLS, unique Linux identities and authenticated enrollment.
3. Carry observed process identity through detection recommendations; add an
   explicit safe collection recommendation. Current translation cannot produce
   either requested process demonstration. Never synthesize start-time values.
4. Integrate the response-engine library through a reviewed, published submodule
   pin. Its README claims consumption, but this Manager has only vendor/eyedetect.
5. Demonstrate Linux alert -> collection -> ACCEPTED -> result -> evidence/audit,
   then pending kill -> analyst approval -> typed command -> ACCEPTED -> result.
   Process termination must target a dedicated disposable process by PID AND
   observed start time. Manager's response-action view also needs lifecycle
   reconciliation with command results before claiming the complete round trip.
6. Implement Windows polling, validation, native process collection/termination,
   identity-safe targeting, replay protection and result delivery; validate native
   Windows builds and actual guest execution. Some HTTP delivery code exists,
   but that is not proof of a complete Windows response endpoint.
7. G6-G9: bounded file actions, controlled process response, isolation and recovery.
   Address durable result retry/dispatch recovery before exactly-once claims.
8. Promote exact tested commits through staging, with SQLite-safe backups and
   matching endpoint state. Keep VM deployment separate from normal PR CI.

The two requested end-to-end demonstrations remain outstanding. Unit/API tests
do not substitute for VM evidence, and a manually inserted alert is not proof
that a real detection recommendation traversed the complete pipeline.
