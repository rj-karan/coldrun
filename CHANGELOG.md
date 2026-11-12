# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Bubblewrap sandbox backend and the policy model behind every backend: new user, PID, mount, IPC, UTS and network namespaces, no capabilities, `no_new_privs`, read-only `/usr`, private tmpfs `/tmp` and `/run`, scratch directory at `/work`, script mounted read-only, synthetic `/etc/passwd`, resolver and CA files only when network is allowed, environment cleared to an allowlist, `--rw` refused for `/`, `$HOME` and credential directories, TIOCSTI-aware TTY passthrough, and a probe that reports bubblewrap's own error with a `coldrun doctor` hint (#12).
- Type detection: shared shebang, extension and file-magic signals (`detect.py`), every registered runner scores the file, the best above 0.5 wins, ties and low confidence produce an error naming the candidates and `--lang`; `--lang` forces a runner (#10).
- Fetch step: local file and http(s) URL fetchers place the source in a private 0700 quarantine directory under `~/.cache/coldrun/quarantine/` with a `source.json` (origin, SHA-256, size, time). 64 MiB size cap, redirects limited to http(s), GitHub `blob` URLs rewritten to raw. XDG-aware config and cache paths in `config.py` (#9).
- `Runner` protocol, `DepSet` and `Finding` models, and an entry-point registry (`coldrun.runners` group) that loads built-in and third-party runners, skips broken plugins with a logged reason, and a shared contract test suite in `tests/unit/runners/contract.py` (#11).

### Changed

- **Breaking:** the project is renamed from `muzzle` to `coldrun`: package, console script, entry-point group `coldrun.runners`, config path `~/.config/coldrun/` and cache path `~/.cache/coldrun/` (#50). The PyPI name `muzzle` belongs to another maintainer; `coldrun` is free everywhere.

## [0.0.1] - 2026-11-12

Foundation release (published under the former name `muzzle`): an empty `muzzle --version` that passes every check on a pull request. No fetching, vetting or sandboxing yet; that starts in M1.

### Added

- Package scaffold with the spec layout and `muzzle --version` (#1, #2).
- Ruff lint and format, mypy strict and pre-commit hooks including a secrets scan and a Conventional Commits check (#3).
- GitHub Actions workflows: CI (ruff, mypy, pytest 3.10 to 3.13, coverage, wheel build), integration (bubblewrap and Podman on the runner), CodeQL, security (pip-audit, gitleaks, Semgrep), PR lint, release and docs; Dependabot for uv and Actions (#5).
- Bubblewrap smoke test in `tests/integration` proving user namespaces work on the runner (#5).
- Issue templates (bug, feature, new runner, false positive), pull request template, CODEOWNERS, CONTRIBUTING, SECURITY and CODE_OF_CONDUCT (#4).
- CLAUDE.md with the repo workflow, branch protection, code quality bar and the hard security rules for agents and contributors (#8).

[Unreleased]: https://github.com/rj-karan/coldrun/compare/v0.0.1...HEAD
[0.0.1]: https://github.com/rj-karan/coldrun/releases/tag/v0.0.1
