# Panopticon VMware Lab — Progress Update

**From:** Rishi
**To:** Shreyas
**Date:** 14 September 2026

Hi Shreyas,

I’ve completed the initial setup of all four VMs for our Panopticon lab. The operating systems and private network are configured. The next stage is deploying the Panopticon services and validating the full detection-to-response flow.

## Completed so far

| VM | Role | Private IP | Current status |
| --- | --- | --- | --- |
| PANO-MGR | Manager + Console server | 10.77.10.10 | Ubuntu Server installed; private-network SSH demonstrated |
| PANO-LNX-01 | Primary Linux endpoint | 10.77.10.21 | Ubuntu Server installed; private-network SSH demonstrated |
| PANO-LNX-02 | Second Linux endpoint / isolation-test peer | 10.77.10.22 | Ubuntu Server installed; private-network SSH demonstrated |
| PANO-WIN-01 | Windows endpoint | 10.77.10.31 | Windows 11 installed; static private IP configured |

- Organized the lab VMs under `C:\PanopticonLab\VMs`, outside OneDrive.
- Configured **VMnet10 as host-only**, using `10.77.10.0/24`, with DHCP disabled and a host adapter at `10.77.10.1`.
- Kept separate NAT adapters for installation, package downloads and updates. These still need to be disconnected during response demonstrations.
- Resolved the VMnet10 subnet mismatch that was preventing host-to-guest access.
- Confirmed Windows-to-Linux TCP connectivity: **10.77.10.31 → 10.77.10.21:22 succeeded** through the Windows VM’s private adapter.
- Established the `10-networked-clean` snapshot procedure. I still need to verify that the baseline snapshot has been saved for every VM.

### Initial code work

During the repository review, we found that the Linux agent already sends an `ACCEPTED` acknowledgement, but the local Manager revision lacked its receiving endpoint.

A local Manager change now adds:

```text

POST /api/v1/agents/{agent_id}/commands/{command_id}/accept
```

It authenticates the agent, records the `DISPATCHED → ACCEPTED` transition and an audit event, handles duplicate acceptance idempotently, and rejects invalid ownership or lifecycle transitions.

**Local validation:** 90 Manager tests passed, including 6 new acceptance cases; Ruff lint passed. Dependency deprecation warnings remain. This change has not yet been deployed to the VM, and remote CI has not been verified for it.

## Current deployment status (14 September 2026)

The Manager and Console are now deployed on **PANO-MGR**. The Manager is running as a single-worker systemd service behind Nginx HTTPS at `manager.internal`; the Console is available locally on port `8787` and is accessed from the host through an SSH tunnel. Health and readiness checks return successfully.

Both Linux endpoints are enrolled and independently identified:

| Agent | Host | Status |
| --- | --- | --- |
| `linux-01` | `pano-lnx-01` (`10.77.10.21`) | Enrolled; agent service starts and sends telemetry |
| `linux-02` | `pano-lnx-02` (`10.77.10.22`) | Enrolled; agent service starts and sends telemetry |

The Manager database currently contains two enrolled agents and increasing event counts. Linux agent normal builds, ASAN/UBSAN builds and tests passed. The agent is currently a bounded `/proc` snapshot collector: a service run captures a snapshot and exits successfully; it is not yet a continuous process watcher.

## Detection validation and current blocker

Authenticated HTTPS ingestion from Linux02 was verified. A schema-correct synthetic Linux event was accepted by the Manager (`received: 1`, `accepted: 1`). The event count increased, confirming the ingestion and persistence path.

The synchronized detection-engine revision was deployed to the Manager and the Linux rule directory is now present. A corrected, schema-valid synthetic Linux02 event generated one persisted high-severity alert: `DET-LNX-006` (Remote Script Executed via Pipe to Shell), process `bash`, MITRE technique `T1105`. The alert is visible in the Console, confirming the complete Linux ingestion-to-detection-to-console path.

Earlier malformed synthetic events also exposed a detector robustness issue: a nullable process name caused `NoneType has no attribute 'lower'` in process-tree correlation. The successful event uses complete non-null process fields; nullable-field hardening remains a follow-up engineering improvement.

This means the current result is:

```text
Linux agent -> authenticated ingest -> event persistence: verified
Linux event -> Linux rule match -> alert -> Console: verified (`DET-LNX-006`, high)
```

The temporary `401 Unauthorized` response during testing was corrected; later requests returned `200 OK`.

## What is not complete yet

The infrastructure, Manager, Console, Linux enrollment, authenticated telemetry ingestion and a persisted Linux detection alert are working. We have not yet demonstrated response execution or the complete audit chain in this lab.

The Response Engine is an in-process library within the Manager deployment, not a separate VM or network service. The existing Console provides alerts and a read-only response queue; analyst authorization currently belongs to the authenticated API.

## Work I will do next

1. **Harden process-tree normalization** so nullable process fields cannot crash the detection worker.
2. **Complete Linux response integration:** inspect the alert recommendation, test safe process collection, reconcile response/command lifecycle states, and verify evidence and result delivery.
3. **Deploy and complete Windows integration:** verify VMware Tools, install/configure Sysmon and Officer, validate telemetry delivery, and implement/test the missing Windows response execution path.
4. **Validate recovery and repeatability:** test restarts, duplicate/replayed commands, durable result handling, controlled containment, backups and rollback. Run repository CI checks before deploying exact revisions to the lab.

## Required end-to-end demonstrations

### 1. Safe process collection

```text
Detection → Alert + recommendation → Response policy
→ Automatic authorization → COLLECT_PROCESS_INFO
→ Agent ACCEPTED → Execution → SUCCEEDED
→ Evidence → Audit
```

### 2. Analyst-approved process termination

```text
Detection → Alert + recommendation → KILL_PROCESS pending approval
→ Analyst authorization → Typed command dispatch
→ Agent ACCEPTED → Execution → Typed result → Audit
```

The termination test will use a harmless, dedicated process and verify its exact identity to protect against PID reuse. Both demonstrations need actual VM evidence on Linux and Windows; standalone unit tests or manually inserted alerts will not count as proof of the full chain.

## Constraints and open gaps

- The host has **16 GB RAM**, so I’m running the VMs in stages. All four cannot run together at their current allocations; multi-endpoint tests will need a validated memory plan or more RAM.
- Disk allocations are **70 GB for Manager, 35 GB for each Linux endpoint and 64 GB for Windows**. Manager and Windows are below the playbook’s suggested 80 GB allocations. I’ll track disk growth and snapshot headroom; native Windows builds may need to run on the host or in CI.
- Windows response integration is still incomplete. Some delivery code exists, but that does not establish a working Windows response endpoint.
- The Manager checkout does not yet pin the separate Response Engine repository, despite that package’s README claiming consumption. Dependency integration needs to be handled as a tested repository change.
- Process recommendation identity, response-state reconciliation and delivery/recovery gaps must be addressed before claiming the full response pipeline or exactly-once behavior.
- Linux host isolation still requires real VM testing with console recovery access.

## Progress estimate

For the scoped goal of **a repeatable four-VM lab demonstrating detection and both response paths on Linux and Windows**, the infrastructure milestone represents approximately **15%**, pending verification of all baseline snapshots.

This is a proposed milestone-based estimate, not a measured percentage of repository code completion. Existing code gives us a head start, but deployment and integration remain to be proven. Completing this lab will also not, by itself, mean the EDR is production-ready.

**My immediate next task is to inspect the Linux alert details and complete the safe process-collection response path.**

## Lab paused safely

The lab is paused after the successful Linux02 detection demonstration. The next session should begin with the Console analyst connection and the safe process-collection response path. No response action was authorized or executed before shutdown.
