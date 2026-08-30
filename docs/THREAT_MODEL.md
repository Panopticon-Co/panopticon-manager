# Manager Threat Model

Stub. Filled in starting Phase 4 (enrollment/auth) per `docs/ROADMAP.md`,
in the register of `panopticon-detection-engine`'s existing
`SECURITY_REVIEW_V*.md` docs.

Planned scope (STRIDE over the new network boundary), from the design brief:
enrollment key theft; agent key at rest under DPAPI and what a local admin can
still do; TLS pinning failure modes; spoofed `agent.id`/`host.id` in payloads
(must be a `403`, and is its own detection signal); body-size and line-count
DoS; SQL injection surface in the filtered query API; unbounded queries; the
"telemetry contains credentials" problem (process command lines routinely
carry passwords/tokens — define what's logged, what's redacted, what's
deliberately retained because detection needs it); explicit statement that
there is no multi-tenancy and why that's acceptable here.
