# Contributing to panopticon-manager

Thank you for contributing to **panopticon-manager**!

## 🛠️ Development Setup

1. **Fork and clone the repository (with submodules):**
   ```bash
   git clone --recurse-submodules https://github.com/<your-username>/panopticon-manager.git
   cd panopticon-manager
   ```

2. **Create a virtual environment and install dependencies:**
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   pip install -r requirements.txt -r vendor/eyedetect/requirements.txt
   ```

3. **Run the test suite:**
   ```bash
   pytest -v tests/
   ruff check .
   ```

## 📋 Pull Request Guidelines

- Ensure new endpoints/modules have test coverage under `tests/`.
- If a change touches the wire protocol or the vendored engine's API, update
  the relevant ADR/doc in the same PR — see `CLAUDE.md`.
- Use descriptive commit messages following the [Conventional Commits](https://www.conventionalcommits.org/) specification.
