# Security Policy

`panopticon-manager` is the authorization and dispatch boundary of the
Panopticon pipeline — it decides which typed commands an endpoint agent is
told to execute. Vulnerability reports against this repo (or against the
vendored `eyedetect`/`response_engine` submodules as consumed here) are
treated as especially sensitive.

## Reporting a Vulnerability

**Do not open a public GitHub issue for a security vulnerability.** Report
privately via GitHub Security Advisories:

<https://github.com/Panopticon-Co/panopticon-manager/security/advisories/new>

Please include:

- A description of the vulnerability and its impact.
- Reproduction steps, including any sample events, commands, or tokens
  needed (redacted/synthetic — do not send real credentials).
- Affected file(s)/endpoint(s) and, if known, the specific authorization
  invariant being bypassed (see `docs/THREAT_MODEL.md` and
  `docs/RESPONSE_ENGINE_STATE.md`'s "Security invariants" section for the
  invariants this repo currently claims to enforce).

## Response

This is a capstone/research project maintained on a best-effort basis —
there is no guaranteed response SLA. We will acknowledge reports as soon as
reasonably possible and keep the reporter informed as the issue is
triaged and, if applicable, fixed.

## Scope

In scope: `panopticon-manager`'s own code (`manager/`), and how it consumes
the vendored `vendor/eyedetect` and `vendor/response_engine` submodules
(e.g. authorization bypass, command-forgery, cross-agent/cross-analyst
identity confusion, PID-reuse or other target-confusion attacks against
dispatched commands). Vulnerabilities purely internal to the vendored
engines themselves are better reported against their own repositories
([`panopticon-detection-engine`](https://github.com/Panopticon-Co/panopticon-detection-engine),
[`panopticon-response-engine`](https://github.com/Panopticon-Co/panopticon-response-engine)),
though reporting here is also fine if the boundary is unclear.

## Supported Versions

This project does not yet cut versioned releases; security fixes are applied
to `main`.
