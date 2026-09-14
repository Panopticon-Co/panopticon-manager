# ADR 004: agent enrollment cryptographic identity

- Status: accepted
- Date: 2026-09-14

## Context

Before this ADR, `POST /api/v1/agents/enroll` accepted only `agent_id` and
`host_id` (both entirely caller-declared) plus a fleet-wide shared bootstrap
secret (`PANOPTICON_ENROLLMENT_TOKEN`), and minted a random bearer token
stored as a SHA-256 digest. This has three concrete gaps, found by direct
source inspection of `manager/auth.py` and `manager/routers/enrollment.py`,
not assumed from prior documentation:

1. **No proof of possession.** Anyone holding the one shared bootstrap
   secret could mint a working identity for any `agent_id`/`host_id` they
   chose. There was no cryptographic material tying a specific issued
   bearer token to a specific physical endpoint — only the bearer token
   itself, a bare string, was ever checked.
2. **No host_id uniqueness.** `enrolled_agents.agent_id` was the only
   `PRIMARY KEY`; `host_id` had no constraint at all. A second, unrelated
   `agent_id` could enroll claiming an already-trusted endpoint's `host_id`
   verbatim, creating two live bearer tokens both nominally representing
   the same host — a real host-identity-confusion risk for anything keyed
   by `host_id` downstream (response actions, audit).
3. **Key substitution had no defense**, because there was no key at all.

## Decision

Enrollment now requires proof of possession of a freshly-generated ECDSA
P-256 (`secp256r1`) keypair, generated on the endpoint and never transmitted:

```
POST /api/v1/agents/enrollment-challenge   (no auth, no body)
  -> {nonce: base64(32 random bytes), expires_at}

POST /api/v1/agents/enroll
  headers: X-Panopticon-Enrollment-Token: <bootstrap secret>
  body: {agent_id, host_id,
         public_key: base64(0x04 || X || Y),   # raw uncompressed point
         nonce: <from the challenge above>,
         signature: base64(DER ECDSA-SHA256 signature over the raw nonce bytes)}
  -> {agent_id, access_token, token_type: "Bearer"}   (unchanged shape)
```

**Why ECDSA P-256, not Ed25519:** the Windows agent already links
`bcrypt.lib` (Windows CNG) for its existing entity-id hashing and random
generation; CNG's `BCRYPT_ECDSA_P256_ALGORITHM` provides P-256 key
generation and signing with zero new dependencies. Neither agent had *any*
asymmetric-crypto dependency before this ADR, so this is the first choice
made, not a second library added alongside an existing one — `cryptography`
(Python/Manager) and OpenSSL (Linux agent, added as a new but extremely
standard dependency) both support P-256 natively. Ed25519 would have
required a new dependency on Windows (CNG's Ed25519 support is recent and
not universally available) for no corresponding benefit here.

**Why the nonce is a separate challenge call, not derived from the request
itself:** a signature over server-chosen, unpredictable, one-time-use bytes
is what makes this proof of possession rather than proof of having seen the
request — signing caller-chosen data (e.g. a timestamp) would let a passive
observer of one valid enrollment forge signatures over predictable future
values. The nonce is consumed exactly once (`enrollment_nonces.consumed_at`,
claimed via a single-row `UPDATE ... WHERE consumed_at IS NULL`, so two
concurrent consumers cannot both win), with a 5-minute TTL — long enough for
a real enrollment round trip, short enough to bound the replay window.

**Why the bearer token is unchanged:** ongoing authenticated operations
(telemetry ingestion, command polling, result submission) continue to use
the existing, already-tested bearer-token check
(`require_agent_token`/`hmac.compare_digest` against a stored digest). This
ADR does not introduce per-request signing for those paths — the security
improvement it targets is entirely at enrollment time: *which* key gets
bound to *which* identity, and proving the caller actually holds it. Adding
live per-request signature verification would be a materially larger wire
protocol change with no concrete threat this phase identified that the
existing bearer-token + TLS layering does not already cover for ongoing
operations.

**host_id uniqueness**: `enroll()` now rejects (`409`) a new `agent_id`
claiming a `host_id` that already belongs to a different, currently
non-revoked `agent_id`. A revoked endpoint's `host_id` is not permanently
poisoned — once `revoked_at` is set, that `host_id` is free for a
legitimate re-image/re-enrollment under a fresh `agent_id`.

## Key rotation: deferred

Not implemented in this phase. The one-shot enrollment constraint
(`agent_id` can never be silently re-enrolled or rebound) combined with
revoke-then-re-enroll already provides an operator-safe recovery path if a
key is suspected compromised: revoke the `agent_id`, then re-enroll a fresh
identity (new `agent_id` recommended, or the same `agent_id` is permanently
unavailable by design — see the one-shot `enroll()` docstring). A live,
authenticated rotation endpoint (sign a challenge with the OLD key to
authorize installing a NEW one, without a full revoke/re-enroll cycle) is a
reasonable Phase 14 candidate if operational experience shows revoke +
re-enroll is too disruptive, but nothing in this phase's threat model
requires it now — this is a deliberate scope decision, not an oversight.

## Consequences

- `enrolled_agents` gains a nullable `public_key` column (migration 11). A
  pre-Phase-13 row (only possible on an in-place upgrade of a live
  deployment, not a fresh dev DB) has `public_key IS NULL` and simply never
  participates in any future signature-based path added on top of this
  identity — it keeps authenticating via the unchanged bearer-token check.
- `enrollment_nonces` is a new table; nonces past their TTL are inert
  (`_consume_nonce` treats expired as absent) but are not actively purged in
  this phase — an operationally reasonable future addition, not a security
  gap (an expired, unconsumed nonce can still only ever be consumed once,
  by definition, before or after the TTL check that already rejects it).
- The enrollment wire contract is now canonical in `panopticon-contracts`
  (`schema/enrollment_request.schema.json`) rather than purely a Manager
  implementation detail, since both agents must construct it identically.
