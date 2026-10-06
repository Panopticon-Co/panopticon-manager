# Immutable endpoint record readback

GET /api/v2/endpoint/{agent_id}/records/{record_id} requires the endpoint's agent
token and scopes lookup to both agent ID and immutable record ID. It returns the
original retained JSON body as application/json, without model reconstruction,
field defaults or latest-category replacement. Unknown records return 404;
missing or wrong-agent credentials return 401.

X-Panopticon-Record-Digest is the stored SHA-256 digest of the original accepted
body. Cache-Control is no-store. This verifies retained-body equality; it does
not attest the endpoint, native source, capture completeness or lifecycle.

The endpoint service manifest supplies ordered page record IDs for individual
readback. A service capture index, assembly verifier and analyst/Console access
remain pending. Existing process capture APIs continue independently.
