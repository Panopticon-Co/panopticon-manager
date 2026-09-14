## Summary

<!-- One or two sentences: what does this PR do and why? -->

## Changes

<!-- Bullet list of the concrete changes. -->

## Testing

<!-- Exact commands run and their results, e.g. `pytest -v tests/`, `ruff check .`.
     Note any tests added/updated, and whether this was verified on real CI
     (not just locally) if that distinction matters for this change. -->

## Security Impact

<!-- Does this touch authorization, token handling, the closed command
     action set, PID-reuse protection, or the audit trail? If yes, describe
     the invariant being preserved/changed and how it was verified. If no,
     say "None." explicitly rather than leaving this blank. -->

## Documentation

<!-- Which docs were updated (README, docs/adr/, docs/API_CONTRACT.md,
     docs/RESPONSE_ENGINE_STATE.md, docs/THREAT_MODEL.md)? If none needed
     updating, say so. -->

## Cross-Repository Impact

<!-- Does this change the wire contract with panopticon-agent,
     panopticon-linux-agent, panopticon-detection-engine,
     panopticon-response-engine, panopticon-contracts, or
     panopticon-console? If yes, link the corresponding PR(s) in those
     repos. -->

## Checklist

- [ ] Tests added/updated under `tests/` for the change
- [ ] `pytest -v tests/` passes locally
- [ ] `ruff check .` passes locally
- [ ] No files under `vendor/` were edited directly
- [ ] If a `vendor/` submodule pin changed, it points at a real, merged
      commit on the upstream repo's default branch — **never** an unmerged
      PR branch tip (verify with `git -C vendor/<name> merge-base
      --is-ancestor <sha> origin/main`)
- [ ] No existing test was weakened or deleted to make CI pass
- [ ] Relevant docs updated in the same PR (see Documentation above)
