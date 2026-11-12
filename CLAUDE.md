# CLAUDE.md

Instructions for Claude Code and any other agent or contributor working in this
repository. The full design is in `docs/SPEC.md`; read it before changing
behaviour. When this file and the spec disagree, open an issue labelled
`question` and ask instead of guessing.

## What this project is

muzzle is a CLI that fetches a script, works out its dependencies, vets it,
and runs it inside a sandbox. **The sandbox is the protection; the scan is the
warning.** Every change must keep the design safe even when the scan says
clean.

## Hard security rules

These are not negotiable and are checked in review, by Ruff's bandit rules,
and by Semgrep in CI.

1. **The host never imports, sources or executes fetched content.** Parsing
   only: `ast.parse`, tokenizers, regex, file magic. No `import`, no `exec`,
   no `eval`, no `source`, no running an interpreter on it outside the sandbox.
2. **Subprocess calls use argument lists, never `shell=True`.** No string
   commands, no `os.system`, no `os.popen`.
3. **Archives are extracted with path and symlink checks.** Reject absolute
   paths, `..` components, symlinks and hardlinks that point outside the
   destination, and enforce size and member-count limits.
4. **No real malware in the repo.** Test fixtures are harmless synthetic
   samples that only match the rules. If a sample would do damage when run,
   it does not belong here.
5. **Every sandbox must hold the rules in `docs/SPEC.md` → Security model →
   Sandbox rules:** no `$HOME`, SSH keys, browser profiles, cloud credentials,
   Docker socket or D-Bus; new PID, mount, IPC and user namespaces; no new
   privileges; all capabilities dropped; read-only root; private tmpfs for
   `/tmp` and the working directory; network off by default; dependency
   installs inside the sandbox with registry-only network; environment
   scrubbed to an allowlist.
6. **Sandbox policy code is covered 100% by tests.** Overall coverage stays
   at or above 85%.
7. **Rules flag behaviour aimed at the host, not network activity towards a
   target the user named.** Security tools legitimately open sockets and
   spawn shells. Every finding carries a rule ID, severity, file, line and a
   one-line explanation. A hardcoded IP or domain not in `--allow-host` is
   always shown to the user.

## Workflow for every change

Nothing lands on `main` without an issue, a branch, a pull request and green
CI. This applies to agents exactly as it does to people.

1. **Issue first.** Open it with the right template, labels and milestone. Do
   not write feature code before the issue exists.
2. **Branch from `main`**, named after the issue: `feat/17-bash-runner`,
   `fix/31-symlink-check`, `docs/…`, `chore/…`, `ci/…`.
3. **Tests first where practical.** A bug fix always adds a test that fails
   before the fix.
4. **Run the checks locally before pushing:**
   ```sh
   uv run ruff check . && uv run ruff format --check .
   uv run mypy
   uv run pytest -m "not sandbox and not e2e" --cov
   uv run pytest -m "sandbox or e2e"        # when bubblewrap is available
   uv run pre-commit run --all-files
   ```
5. **Commit in small steps with Conventional Commits:**
   `feat(runners): add bash runner`. Types: `feat`, `fix`, `docs`, `chore`,
   `refactor`, `test`, `ci`, `build`, `perf`, `style`, `revert`. The commit
   hook rejects anything else.
6. **Open a pull request** that fills the template and says `Closes #N`. The
   PR title is also a Conventional Commit; it becomes the squash commit.
7. **Wait for CI.** If it fails, fix the cause on the branch. **Never skip,
   disable, weaken, retry-into-passing or `--no-verify` a check to get
   green.** A flaky test is fixed or removed.
8. **Squash-merge**, let the branch be deleted, confirm the issue closed.
9. **Update `CHANGELOG.md` under Unreleased and any affected docs in the same
   pull request.**

Never push to `main` directly. Branch protection blocks it, and that is the
intent, not an obstacle.

## Branch protection on main

- Pull request required; direct pushes and force pushes blocked; admins
  included.
- Required checks: `lint`, `types`, `tests`, `CodeQL`.
- Linear history; squash merges only; branches deleted on merge.

## Code quality

- Python 3.10+, `uv` for everything, Typer for the CLI, Rich for output.
- Ruff for lint and format, mypy `strict`, full type hints, Google-style
  docstrings on public modules, classes and functions.
- `pathlib` over `os.path`. No stray `print`; output goes through the report
  layer.
- `cli.py` holds no logic. Commands call `pipeline.py`.
- One module per runner under `src/muzzle/runners/`; runners are discovered
  through the `muzzle.runners` entry-point group and must pass the shared
  contract suite.
- Keep a Changelog format and Semantic Versioning. MIT licence.

## CI expectations

- Third-party Actions are pinned to a commit SHA with the version in a
  comment. Dependabot bumps them.
- Every workflow and job declares minimum `permissions`.
- uv downloads are cached; a CI run stays under five minutes.
- `integration.yml` lifts the hosted runner's user-namespace restriction and
  proves `bwrap` works before running sandbox tests. If that step fails, the
  runner image changed; fix the step, do not skip the tests.

## Milestones and releases

Work one milestone at a time, in order, one pull request per issue. At the
end of a milestone: move Unreleased changelog entries under the new version
and bump `pyproject.toml` through a pull request, tag `vX.Y.Z` on `main`,
then stop and report what shipped, what is open, and any decision needed.

## When unsure

Open an issue labelled `question` and wait. Do not guess at security
behaviour, naming, or anything the spec leaves open.
