# Contributing to panopticon-manager

Thank you for contributing to **panopticon-manager**, the backend control
plane of the Panopticon&Co capstone EDR/XDR platform.

## Development setup

1. **Fork and clone the repository, with submodules:**

   ```bash
   git clone --recurse-submodules https://github.com/<your-username>/panopticon-manager.git
   cd panopticon-manager
   ```

   If you already cloned without `--recurse-submodules`:

   ```bash
   git submodule update --init --recursive
   ```

2. **Create a virtual environment and install dependencies:**

   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   pip install -r requirements.txt -r vendor/eyedetect/requirements.txt
   ```

3. **Run the test suite exactly as CI does:**

   ```bash
   pytest -v tests/
   ruff check .
   ```

   Always scope pytest to `tests/`. A bare `pytest` at the repo root also
   collects the vendored submodules' own test directories under `vendor/`,
   which are independent suites with their own fixtures and will collide
   with this repo's.

## Working with the vendored submodules

`vendor/eyedetect` (panopticon-detection-engine) and `vendor/response_engine`
(panopticon-response-engine) are pinned git submodules, not vendored copies
of source to edit in place.

- **Never edit files under `vendor/` directly.** A fix there belongs upstream
  in the corresponding repo.
- **Never bump a submodule pin as part of an unrelated change.** Pin bumps
  are their own focused commit/PR, with the reason for the bump stated
  explicitly (see `docs/adr/001-repo-topology.md` and
  `docs/RESPONSE_ENGINE_STATE.md`'s "Known blockers" section for the kind of
  investigation a bump can require).
- **A submodule pin must point at a real, merged commit on the upstream
  repo's default branch** — never at an open PR branch tip. (This project
  has previously shipped a pin to an unmerged PR-branch commit by mistake;
  see `docs/RESPONSE_ENGINE_STATE.md`'s "Known blockers" for what that cost
  to detect and unwind. Verify with
  `git -C vendor/<name> merge-base --is-ancestor <pinned-sha> origin/main`
  before proposing a bump.)
- If your change touches the wire protocol between Manager and either
  vendored engine, or the Manager/agent command contract, update the
  relevant ADR/doc (`docs/adr/`, `docs/API_CONTRACT.md`,
  `docs/RESPONSE_ENGINE_STATE.md`) in the same PR.

## Pull request guidelines

- Ensure new endpoints/modules have test coverage under `tests/`.
- Do not weaken an existing test to make it pass — fix the underlying issue,
  or discuss the change explicitly in the PR description if the test's
  assumption is genuinely wrong.
- Use descriptive commit messages; this repo generally follows
  [Conventional Commits](https://www.conventionalcommits.org/) style
  (`feat:`, `fix:`, `docs:`, `build:`, `test:`, etc.).
- Use the PR template (`.github/pull_request_template.md`) — in particular,
  fill in Security Impact and Cross-Repository Impact honestly; this repo
  sits at the authorization/dispatch boundary of the whole pipeline.

## Code style

- Python, formatted/linted with `ruff` (`pyproject.toml`; line length 100).
  `vendor/` is excluded from lint.
- Type hints are expected on new code; this codebase uses `from __future__
  import annotations` throughout.

## Reporting bugs / requesting features

Use the issue templates under `.github/ISSUE_TEMPLATE/`. Security
vulnerabilities should **not** be filed as public issues — see
`SECURITY.md`.
