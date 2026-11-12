# Contributing to muzzle

Thank you for helping. This page covers the development setup, how changes
land, and how to add a runner. The full design is in [docs/SPEC.md](docs/SPEC.md).

## Development setup

You need Python 3.10 or newer, [uv](https://docs.astral.sh/uv/), and for the
sandbox tests `bubblewrap` (and `podman` from M5).

```sh
git clone https://github.com/rj-karan/muzzle.git
cd muzzle
uv sync                                   # creates .venv with dev tools
uv run pre-commit install --install-hooks # ruff, mypy, gitleaks, commit message check
uv run muzzle --version
```

## Running the checks

```sh
uv run ruff check . && uv run ruff format --check .   # lint and format
uv run mypy                                           # strict types over src and tests
uv run pytest -m "not sandbox and not e2e" --cov      # unit tests, coverage must stay >= 85%
uv run pytest -m "sandbox or e2e"                     # needs bubblewrap; proves the sandbox holds
uv run pre-commit run --all-files                     # everything the commit hook runs
```

CI runs the same commands on Python 3.10 to 3.13, plus CodeQL, pip-audit,
gitleaks and Semgrep. A flaky test is fixed or removed, never retried.

## How a change lands

Nothing reaches `main` without an issue, a branch, a pull request and green CI.

1. **Open an issue** with the matching template and labels. Security problems
   go through a [private advisory](SECURITY.md) instead.
2. **Branch from `main`**, named after the issue:
   `feat/17-bash-runner`, `fix/31-symlink-check`, `docs/…`, `chore/…`, `ci/…`.
3. **Write the test first** where practical. A bug fix always adds a test
   that fails before the fix.
4. **Commit in small steps** with [Conventional Commits](https://www.conventionalcommits.org/):
   `feat(runners): add bash runner`, `fix(fetch): reject symlinks in archives`.
   Allowed types: `feat`, `fix`, `docs`, `chore`, `refactor`, `test`, `ci`,
   `build`, `perf`, `style`, `revert`. The commit hook enforces this.
5. **Open a pull request** that fills the template and says `Closes #N`.
   The title must also be a Conventional Commit; it becomes the squash commit.
6. **Wait for CI.** Fix failures on the branch. Never disable, skip or weaken a
   check to get green.
7. The maintainer squash-merges; the branch is deleted automatically.

Update `CHANGELOG.md` under *Unreleased* and any affected docs in the same
pull request.

## Hard rules

These come from the security model and are not negotiable:

- The host never imports, sources or executes fetched content. Parsing only.
- Subprocess calls use argument lists, never `shell=True`.
- Archives are extracted with path and symlink checks.
- No real malware in the repo. Fixtures are harmless synthetic samples that
  only match the rules.
- Sandbox policy code is covered 100% by tests.

## Adding a runner

A runner is one module in `src/muzzle/runners/` that implements the `Runner`
protocol from `runners/base.py`:

| Method | Purpose |
|---|---|
| `detect(path) -> float` | Confidence 0.0 to 1.0 that this runner owns the file |
| `resolve_deps(path) -> DepSet` | Packages, system binaries and interpreter version, from a manifest or inferred from the code |
| `install_cmd(deps) -> list[str]` | Command that installs the deps; runs inside the sandbox |
| `run_cmd(path, args) -> list[str]` | Command that runs the script; runs inside the sandbox |
| `vet(path, deps) -> list[Finding]` | Language-specific checks |

Then:

1. Open a **New runner** issue first.
2. Add fixtures under `tests/fixtures/<lang>/`: a hello world, one with
   dependencies, and one per vetting rule the runner adds.
3. Register it in `pyproject.toml` under `[project.entry-points."muzzle.runners"]`.
4. Make it pass the shared contract suite in `tests/unit/runners/`.
5. Add an `area:runner-<lang>` label if it does not exist and a page under
   `docs/runners/`.

Third-party runners can live in their own package and register through the
same entry-point group.

## Code style

- Ruff for lint and format (configured in `pyproject.toml`), line length 100.
- mypy strict; every function is fully typed.
- Google-style docstrings on public modules, classes and functions.
- `pathlib` over `os.path`; no stray `print`, use the report layer.

## Releases

Maintainers only. See *Release steps* in [docs/SPEC.md](docs/SPEC.md):
move the Unreleased changelog entries, bump the version in a pull request, tag
`vX.Y.Z` on `main`, and `release.yml` does the rest.
