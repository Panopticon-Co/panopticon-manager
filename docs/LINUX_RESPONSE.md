# Linux detection and response provenance

Manager receives the mature Linux sensor envelope on `/api/v2/linux-endpoint/records`.
Central contracts own its schema; Manager retains the original immutable bytes.
`process.exec` records enter the same bounded detection worker as Windows and
legacy events. Each active protocol receives capacity; failed records poison
only themselves and stale leases recover. Migration 23 queues retained process
records once. Other record types remain retained without being falsely mapped
into process events.

The Linux adapter preserves sensor identity separately from authenticated agent
identity. Per-record alerts retain provenance and a domain-verified Linux subject:
raw kernel boot UUID, sensor record hash, host/process entity hash, native PID,
and native start ticks. The command boot digest matches the existing native
Linux decoder. Start ticks become canonical decimal strings for schema 2.
No Windows process entity is fabricated. Inferred or inconsistent process
identity cannot fall back to legacy PID targeting. Aggregated alerts do not
inherit the last triggering process as an exact response target.

Analyst manual requests and recommendation authorization recheck the retained
subject and current enrollment through the existing response path. Existing
role, approval, duplicate, signing and lifecycle controls still apply. Rule
alerts use full agent-scoped digests for replay deduplication. No execution
success is inferred from alert creation, approval or command dispatch.

Validation uses the real centrally governed sensor fixture, the pinned engine's
Linux rules, durable-worker regressions and focused response-domain/API checks.
Manual/native E2E remains deferred by the user.

## Analyst execution evidence

Response queue/detail/export now includes `endpoint_evidence` from retained Linux
`response.action` records. Migration 24 adds a command lookup index over the
original immutable bodies. Records are scoped to the command's authenticated
agent; linkage compares host, action, correlation, file path or native process
PID/start-ticks and boot digest. Disagreement is exposed as `mismatch`, never
silently discarded or treated as command completion. A matched command identifies
which operation was reported; it does not independently prove the OS effect.

The queue previews at most 20 reports; `evidence_truncated` directs the analyst
to full case export. Export includes exact original JSON strings and stored
SHA-256 digests. Projected native start ticks are decimal strings so browser
numbers cannot round them. Telemetry never changes command lifecycle: durable
command receipts remain a separate channel, including late terminal receipts.
The Console gives dry runs explicit precedence over the sensor's `executed`
field, which can be true even when the dry-run report says no signal was sent.

Readiness also exposes a retained Linux `command_channel` provider snapshot and
its reported policy capabilities. Both capture and Manager receive time are
visible. Freshness stays `unverified` and current execution mode stays `unknown`:
receiving a delayed health record is not proof of present policy or support.
These reports are advisory and never weaken authorization or endpoint checks.
