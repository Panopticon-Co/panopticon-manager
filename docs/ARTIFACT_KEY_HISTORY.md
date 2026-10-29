# Feature 2 signing identity — implementation in progress

Migration 28 retains each verified enrollment public key as artifact key version
1. Key material is immutable and cannot be deleted. Retired and compromised keys
remain available for historical signature verification. New enrollment inserts
and identity transitions use the same response audit chain established in item 2.1.

Endpoints use their protected enrollment private key. A missing/corrupt enrolled
key must refuse production, without silently generating a replacement. The v2
manifest and signing input live in panopticon-contracts PR10 and response-engine
PR10. Manager verifies the retained public key, enrollment, signature and key
eligibility; command/content binding is performed by the retention/transfer path.

Rotation uses the existing one-use enrollment challenge. POST a closed version-1
dual-proof proposal to `/api/v1/agents/{agent}/artifact-key-rotations`, authenticated
as that agent. Sign the central domain-separated rotation input with both old and
new private keys. A `response:decide` operator separately approves at
`/api/v1/agents/{agent}/artifact-key-rotations/{request}/approve` before expiry.
Approval rechecks the old active key, retires it, and creates the next version.
Agent GET on the proposal reports status. Drain the local artifact outbox first;
retired keys cannot admit new transfers, but already admitted sessions may finish.
Already accepted artifacts remain verifiable. Rotation is not an endpoint command.

POST `/api/v1/agents/{agent}/artifact-keys/{key}/revoke` with `request_id` and
`reason` requires `response:decide`. It marks the key compromised and blocks future
artifact acceptance, including completion of existing sessions. Previously retained
attestations expose `compromised_key`, compromise time, reason and key version in
case metadata; ordinary retrieval refuses the artifact and records the refusal.
No evidence or old public key is deleted. A producer timestamp cannot prove a
signature predates compromise, so all artifacts under that key are flagged.

POST `/api/v1/agents/{agent}/artifact-enrollment/revoke` with the same decision
shape requires `response:decide`, revokes the old bearer identity and retires its
keys. Reimage enrollment uses a new agent ID and key; the old host binding is
released only after explicit operator revocation. Reusing the old agent ID remains
forbidden. Historical records stay associated with their original identity/case.

GET `/api/v1/agents/{agent}/artifact-keys` requires `response:decide` and returns
public history/status, never private material. Idempotency keys bind entire
proposals and identity decisions. Unauthorized approvals, invalid dual proof,
expired challenges and replay conflicts are refused. Identity refusals are audited.

The contract and Manager identity logic do not by themselves complete item 2.2.
Native signed producers, production transfer integration and Console verification
remain in progress. This branch is a draft and must not ship Feature 2 yet.
