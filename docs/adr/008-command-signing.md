# ADR 008: The Manager signs the commands it authorizes

**Status:** Accepted
**Date:** 2026-10-07

## Context

Commands reach an endpoint over its bearer-authenticated poll. The bearer token proves who is polling. It says
nothing about who decided the command. Without a signature, anyone who could write the `commands` table, steal an
operator's command token, or impersonate the Manager to one endpoint could make that endpoint kill a process or
quarantine a file.

The Linux sensor already verifies ES256 command signatures (panopticon-linux-agent ADR 025). It refuses unsigned
commands and commands signed by a key it does not pin, and checks each command's target, boot, expiry and lifetime.
Until now the Manager stored and delivered commands unsigned, so signed commands only existed in that repository's
tests.

The Windows agent verifies no command signature. Its command parser refuses any member it does not know, so an
`authorization` member would make it reject every command.

## Decision

1. **Signing at the authorization decision.** `authorize_and_enqueue` is the single path for the raw command API
   and the Response Engine. It signs the command right after building the payload it stores. The signature is
   stored inside `command_json`, so a later rewrite of the table makes the signature fail at the endpoint. Signing
   at poll time would not protect against that.
2. **The signing input is the sensor's.** `manager/command_signing.py` ports `command_signing_input` from the
   Linux sensor. The input is length-prefixed fields over the command's identity, endpoint, action, created and
   expiry seconds, and process or file target. `tests/fixtures/command_signing_vectors.json` was produced by the
   sensor's own reference signer. The tests check the Python bytes against it, and verify its signatures.
3. **One file-held key.** `PANOPTICON_COMMAND_SIGNING_KEY` names an unencrypted PEM P-256 private key. On POSIX
   the Manager refuses the key if group or other users can access it. The key is re-read when the file changes,
   so it can be rotated without a restart. Endpoints pin keys by id, and their key file can hold the old key and
   the new one during a rotation. `python -m manager.command_signing generate <file>` creates a key and prints the
   endpoint key-file line.
4. **Fail closed when configured.** If the variable is set and the key is missing, unreadable, malformed or
   shared, command creation fails with 503 and nothing is stored. A command that cannot be expressed in the
   signing input is refused with 422; an expiry without a UTC offset is an example. No command is quietly queued
   unsigned while signing is configured.
5. **The endpoint asks for the signature.** `GET /api/v1/agents/{agent}/commands?command_auth=ES256` returns each
   command with its `authorization`. Without the parameter the member is left out, so the Windows agent keeps
   working. This weakens nothing. The decision to require a signature belongs to the endpoint, which refuses
   unsigned commands whatever the Manager sends. Any other value of `command_auth` is refused with 422.
6. **Auditable.** The `created` audit event of a signed command records `signed ES256 key_id=<id>`.
7. **No schema migration.** The signature lives in `command_json`, and policy is per endpoint. Another change set
   claims migrations 12 to 17 (see ADR 007), so no numbered migration is added.

## Consequences

* With no key configured, behaviour is unchanged: commands are unsigned. A Linux sensor that pins keys refuses
  them and reports `signature_required` in its result, so the command closes as `REJECTED` and is visible.
* The private key is online in the Manager process. Anyone who controls that process can sign commands. A
  hardware-held or separate signing service is a later step, and the endpoint side would not change.
* The Windows agent gains nothing until it verifies signatures. When it does, it adds `command_auth=ES256` to its
  poll, and must accept the `authorization` member.
* Key revocation is done at the endpoints, by removing the key id from their key files. The Manager has no
  revocation list of its own.

## Verification (2026-10-07)

`tests/test_command_signing.py`: 23 tests pass on Ubuntu 22.04 (Python 3.10). The key-permission test is
POSIX-only, so on Windows 22 pass and 1 is skipped. The rest of the suite passes on Windows.

End to end, this Manager ran over HTTPS with a generated key, and a real Linux sensor (panopticon-linux-agent
`feat/flagship-endpoint`, Ubuntu 22.04, kernel 5.15) was enrolled and pinned the key's public point:

| Command | Sensor | Result at the Manager |
|---|---|---|
| `COLLECT_PROCESS_INFO` | dry_run | `succeeded`, process details returned |
| `KILL_PROCESS` | dry_run | `rejected` `dry_run`: target verified, no signal sent, process alive |
| `KILL_PROCESS` (sacrificial `sleep`) | enforce | `succeeded`, SIGTERM through pidfd, process gone |
| `KILL_PROCESS` | enforce, a different key pinned | `rejected` `unknown_signing_key`, process alive |
| `KILL_PROCESS` with `target` rewritten in the `commands` table after signing | enforce | `rejected` `signature_invalid`; neither the named nor the substituted process was touched |

Every command has its `created` audit event with `signed ES256 key_id=…`, then `dispatched`. The three
commands the sensor carried out or verified are `accepted`. The two it refused on their signature go straight
from `dispatched` to `result_received` (`rejected`). The sensor wrote a durable ledger entry
(received, decided, submitted) and a `response.action` record for each.
