# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Package scaffold with the spec layout and `muzzle --version` (#1, #2).
- Ruff lint and format, mypy strict and pre-commit hooks including a secrets scan and a Conventional Commits check (#3).
- GitHub Actions workflows: CI (ruff, mypy, pytest 3.10 to 3.13, coverage, wheel build), integration (bubblewrap and Podman on the runner), CodeQL, security (pip-audit, gitleaks, Semgrep), PR lint, release and docs; Dependabot for uv and Actions (#5).
- Bubblewrap smoke test in `tests/integration` proving user namespaces work on the runner (#5).
- Issue templates (bug, feature, new runner, false positive), pull request template, CODEOWNERS, CONTRIBUTING, SECURITY and CODE_OF_CONDUCT (#4).

[Unreleased]: https://github.com/rj-karan/muzzle/compare/main...HEAD
