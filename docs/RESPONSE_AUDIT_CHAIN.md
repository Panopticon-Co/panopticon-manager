# Response audit chain — Feature 2, Item 2.1

Migration 27 adds one ordered SHA-256 ledger for `command_audit`,
`response_decision_audit` and `response_artifact_custody`. Database triggers
append the chain entry in the source INSERT's transaction. All Manager and
detection-worker connections register the hash function; an unmanaged connection
without it cannot insert an unchained audit event. Source and ledger UPDATE/DELETE
operations are refused. An authorization that cannot retain its audit rolls back.

Each entry binds sequence, previous hash, source identity, event, actor, response
request ID, command, asset, timestamp, exact source-row snapshot and provenance.
Canonical UTF-8 JSON uses domain `panopticon-response-audit/1`.
Hashes do not protect against an administrator rewriting the entire database.
Use independently retained signed checkpoints for that threat.

## Historical provenance is persisted

Every imported row has `legacy_import=1` in the migration itself. The new chain
protects its snapshot from migration onward, without establishing authenticity
of the original historical event. New trigger-generated entries have
`legacy_import=0`; subsequent inserts cannot claim the legacy flag.

Default verification checks both snapshot and chain integrity, reports separate
legacy/post-migration counts and returns `complete_history_verified=false` if any
legacy row exists. Strict-history verification refuses such history. Neither mode
ignores corrupted links, missing source rows or changed source payloads.

## Query and verify

All endpoints require authenticated `response:decide` permission (approver or
analyst under current roles). Agents, viewers and responders cannot access them.

- `GET /api/v1/response-audit`: filters `request_id` (response ID), `actor`,
  `asset_id`, `since`, `until`; sequence cursor `after`, maximum `limit=200`.
  Each entry exposes `legacy_import` and `provenance`. Time filters require a
  timezone. A paged query is explicitly not a full-chain verification.
- `GET /api/v1/response-audit/verify`: verifies in one read snapshot;
  `strict_history=true` additionally requires post-migration provenance throughout.
  Integrity disagreement returns 503. Manager startup also verifies before starting
  detection work and refuses startup on disagreement.
- `POST /api/v1/response-audit/checkpoints`, JSON `{"request_id":"unique-retry-key"}`:
  signs an exportable anchor using dedicated `PANOPTICON_AUDIT_SIGNING_KEY`
  P-256 PEM private key. It uses bounded private-file checks from command key loading,
  but a separate configured key. Missing/unusable key means 503; no unsigned fallback.
  Retries by the same actor return the original anchor even after more events arrive.

## Signed anchors and independent verification

The checkpoint signs domain `panopticon-response-audit-checkpoint/1` plus canonical
JSON containing ledger UUID, sequence, head hash, provenance counts, actor,
timestamp and retry identity. Authorization uses ES256 with raw 64-byte r||s and
the public-point-derived key ID. Never embed private keys in an export.

Save checkpoint JSON and the public keyring in an independently protected location.
The application's local checkpoint table is not an independent trust store; this
slice does not automatically export to an external service. Operators must pin the
public key through a trusted channel, retain historical public keys across rotation,
and retain recent anchors outside the database. An older valid anchor cannot prove
that newer events never existed: choose the latest independently known anchor.

Read-only offline verification:

```text
python -m manager.audit_chain_cli --database panopticon.db --checkpoint anchor.json --trusted-key audit-public.keys
```

The public keyring contains base64 uncompressed P-256 points, optionally followed
by labels, one per line. Verification rejects tampered signatures, untrusted keys,
cross-ledger anchors, altered source snapshots, broken links and history truncated
behind the anchor. Legitimate appends beyond an anchor remain valid.
The CLI opens the database read-only and exits with status 1 on failure.

Item 2.1 does not add auto-triage, webhooks, restoration, or change isolation policy.
Manifest signing, key-history/revocation, scoped retrieval and resumable transfer
remain later Feature 2 items. This audit slice does not ship Feature 2.
