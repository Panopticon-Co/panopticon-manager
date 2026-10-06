# ADR 007: Linux endpoint records have their own ingest route

**Status:** Accepted
**Date:** 2026-10-06

## Context

The Linux endpoint (`panopticon-sensord`) emits "endpoint record 1.0": event, state, health and
loss records with per-boot sequence numbers, provenance, and explicit "unavailable" fields. The
contract is `schema/linux-endpoint/1.0.schema.json` in `panopticon-contracts`. The Manager's
existing routes accept schema 0.x telemetry events (`/api/v1/ingest`) and, in uncommitted work by
others, a Windows canonical endpoint record (`/api/v2/endpoint/records`). Neither can carry state
inventories, health, coverage or loss accounting.

## Decision

1. `POST /api/v2/linux-endpoint/records` accepts NDJSON with
   `X-Panopticon-Protocol: linux-endpoint/1.0`, bearer-authenticated against the enrolled agent.
2. Each line is parsed strictly (no duplicate keys, no non-finite numbers) and validated against the
   contract schema, which is vendored verbatim in `manager/wire/`. A bad line rejects only itself.
3. A record's `id` must equal `sha256("sensor|boot|seq")[:32]`, so a record cannot borrow another's
   identity or change the sequence number loss accounting relies on.
4. `host.id` must equal the enrolled host. A mismatch fails the whole request with 403 and stores
   nothing: it is an identity violation, not a formatting error.
5. Records are stored once. An identical retransmission is a duplicate and is still acknowledged. A
   different record claiming an occupied id or `(sensor, boot, seq)` slot is an `id_conflict` and is
   never overwritten.
6. The response acknowledges per stream with `acked_through_seq`, the contiguous prefix received,
   and lists `missing_ranges`. A sensor may discard its durable log only up to that value. A stream
   whose first record has seq above 1 is accounted from that record.
7. The latest `health` record per host is kept and readable by that host's agent
   (`GET /api/v2/linux-endpoint/hosts/{host}/health`), so coverage is queryable.
8. Tables are `linux_endpoint_*`, created idempotently by the store and not as numbered
   migrations, because another change set already claims migrations 12 to 16. Two branches both
   adding "migration 12" would leave databases whose version means different things.

## Consequences

* This is storage and accounting only. Linux records are not yet fed to the detection engine; that
  needs an adapter in the Detection Engine, which is the next step.
* The vendored schema must be refreshed whenever the contract changes; the sensord fixtures in
  `tests/fixtures/linux_endpoint` are real output and fail loudly if they stop validating.
* There is no retention or pruning of `linux_endpoint_records` yet.
* The new route does not use the Windows freshness-nonce mechanism. Replay of a whole old batch is
  harmless (duplicates), but freshness of capture is not proven here.
