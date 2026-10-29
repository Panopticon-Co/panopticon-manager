# Artifact access policy 1

Migration 30 installs explicit credential-bound grants and immutable operation
history. It grants nothing to existing analysts. Analyst role policy 2 separates
`artifact:read` eligibility from `artifact:scope:manage`. No endpoint action or
response approval policy changes. Critical assets are denied by default too.

An operator provisions `artifact_admin` through `/api/v1/analysts/enroll` using
the dedicated `PANOPTICON_ARTIFACT_ADMIN_ENROLLMENT_TOKEN` in the existing
enrollment header. The normal analyst enrollment secret cannot create or replace
an administrator. Keep both bootstrap secrets outside browsers. Administrator
credentials cannot request or approve response commands and have no implicit
artifact scope themselves.

POST `/api/v1/artifact-access/grants` as that administrator, using the central
`artifact-access-grant-v1.schema.json`. Identify the current analyst ID, exact
host ID and originating alert ID (the case). Include schema version `"1"`, policy
version `1`, unique request ID and reason. Unknown analysts, viewers and mismatched
host/case pairs are refused. No wildcard matching occurs. Repeating an identical
request ID returns its original result; conflicting reuse is refused. Repeating
a previous grant after revocation cannot resurrect it. A new request ID creates
a new grant after revocation.

GET the same route with optional analyst/host/alert filters for bounded history.
POST `.../grants/{grant_id}/revoke` with the central revoke schema to end access.
Grant identity is immutable, revoke history is irreversible, and audit failure
rolls back the state transition. Shared chained audit events record operation
request ID, authenticated administrator, endpoint, time, policy version and
reason. The existing privileged audit query supports those filters.

Every content and custody retrieval rechecks the live bearer credential, role,
and exact grant inside its transaction. Case/alert/incident serialization and
case export omit artifact manifests/custody outside scope. Token reissue does not
inherit old grants: the new credential needs an explicit grant. Revoked identity,
role removal and grant revocation block the next request. Compromised-key flags
remain queryable by scoped analysts, while normal content retrieval is refused.

Console `/api/evidence/*` uses an individual one-hour in-memory browser session;
it sends that analyst's token to Manager on every retrieval. It never uses the
Console shared token as fallback. Restart or logout ends sessions. Manager remains
the authorization authority even when someone calls its API without Console.
