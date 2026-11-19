# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed

- The YARA and Semgrep rule files were missing from every wheel and sdist from 0.3.0 to 1.0.0, so installs from PyPI vetted scripts with no rules and reported them as low risk. A top-level `rules` symlink made the build drop them; it is gone. Missing rule files are now a medium finding that asks before running, and CI installs the built wheel and checks it refuses a malicious sample. The sandbox itself was not affected (#110).

## [1.0.0] - 2026-11-20

Completes milestone M5: Node, Go, Ruby and Python 2 runners, a Podman backend for runners that ship an image, a documentation site, a man page and shell completions, and AUR packages. `uvx coldrun` and `pipx install coldrun` are checked on clean Arch and Kali after every release.

### Added

- Node runner: dependencies from `package.json` beside the script, else `require` and `import` statements (relative paths and builtins skipped); installed with the system `npm --ignore-scripts` over registry-only network and found through `NODE_PATH`. Toolchains come from `/usr/bin`; a Node from mise or nvm is hidden by the sandbox and the error says so (#32).
- Go runner: dependencies from `go.mod` beside the script, else imports whose first element is a host; `go get` into the cached environment through `proxy.golang.org` and `sum.golang.org` only, then the script is built offline (`GOPROXY=off`) in a temporary module and runs from `/work` (#33).
- Ruby runner: dependencies from a `Gemfile` beside the script (names), else `require` lines outside the standard library, mapped to gem names where they differ; `gem install` into the cached environment from rubygems.org only, found through `GEM_HOME` with Ruby's own gems still visible (#34).
- Python 2 runner: a `python2` shebang, or Python 2-only syntax (print statement, `except X, e:`, `print >>`) under a bare `python` shebang or `.py`, runs in a pinned `python:2.7.18-slim` image on the Podman backend. Dependencies come from the same sources as Python 3, with imports read line by line and Python 2's renamed standard library skipped; the image's pip installs them over registry-only network through the bridge. The Python 3 runner now scores a bare `python` shebang 0.9 so Python 2 code can win (#31).
- Podman backend for runners that ship a container image: rootless, `--cap-drop=all`, no new privileges, read-only root, private `/tmp` and `/run`, `--userns=keep-id`, a pid limit, network off unless asked, scrubbed environment, and `--allow-host` through the same host-side proxy (the bridge now also runs on Python 2.7). Backends are picked per runner: image runners go to Podman, host-toolchain runners to bubblewrap; a mismatched `--backend` is a clear error. `--listen` stays bubblewrap-only (#30).
- Source signals: a force-push to a GitHub origin in the last 30 days is a medium finding, read from the repository activity API (#91).
- Man page and shell completions: `packaging/man/coldrun.1` and bash, zsh and fish scripts in `packaging/completions/`, generated from the CLI by `packaging/generate.py` and kept fresh by a test. The CLI answers completion requests without Typer's `--install-completion`, which would edit the shell rc file (#38).
- AUR packages `coldrun` (tagged release) and `coldrun-git` in `packaging/aur/`, installing the man page and completions. A CI job builds both in an Arch container from the checkout, runs `namcap`, checks `.SRCINFO`, installs the release package and runs it (#37).
- Documentation site at https://zororj.me/coldrun/ (mkdocs-material): overview, usage, threat model, runners and how to write one, the JSON report schema, and an FAQ. Built with `--strict` on every docs pull request and deployed from main (#35).
- Install check: after every release, and on demand, CI installs the package from PyPI with `uvx` and `pipx` on clean Arch and Kali containers and runs it (#107).

### Changed

- Installer output now always goes to stderr, so it never mixes with the script's stdout or the `--json` document.

### Security

- `--listen` bound every host interface in v0.4.0, so a callback port was open on any network the machine was on. It now binds `127.0.0.1` unless given an address: `--listen 10.10.14.5:4444` for a VPN interface, or `--listen 0.0.0.0:4444` to choose every interface on purpose. Addresses must be literal IPv4 and each port may appear once (#100).

## [0.4.0] - 2026-11-18

Completes milestone M4: a script reaches only the hosts you allow, a callback arrives on a forwarded port, and scripts can come from archives, GitHub repositories, gists and exploit-db.

### Added

- GitHub, gist and exploit-db sources: a repository URL or `tree/REF[/PATH]` URL downloads the ref's tarball through the safe archive path and runs the script at the top or at PATH; a gist page URL is read from the API file by file; `edb:ID` or an exploit-db URL downloads the raw exploit under the name the site gives it. For GitHub origins a repository or owner account younger than 30 days is a medium finding, read from the API (`GITHUB_TOKEN` raises the rate limit; a failed check is info). Force-push detection is split out to #91 (#28).
- Archives as sources: a local or downloaded tar (plain, gz, bz2, xz) or zip is extracted into quarantine with path traversal, absolute path, symlink and hardlink escape, device entry, member count and total size checks; the one script at the top (after lone directories) is the entry and runs with its sibling files visible read-only under `/work/src`. A file beside the script that would shadow a popular or stdlib module (a planted `requests.py`) is refused (#29).
- `--listen PORT` (repeatable): the host opens the port and hands the listening socket into the sandbox, where the bridge delivers each callback to the script's listener on `127.0.0.1:PORT`. Outbound policy is unchanged, and it is refused with `--net full`, where the script can bind the port itself (#27).
- `--allow-host HOST[:PORT]` (repeatable, implies `--net allow`): the sandbox keeps its empty network namespace; a host-side proxy on a unix socket, exposed inside as `127.0.0.1:3128` through the standard proxy variables, connects only to the listed destinations and resolves names on the host, so other hosts are refused and get no DNS. Dependency installs now use the same path with the registry hosts only (`pypi.org`, `files.pythonhosted.org`) instead of full network (#26).

## [0.3.0] - 2026-11-17

Completes milestone M3: scripts and their dependencies are vetted before anything runs. Synthetic exfiltration, persistence and obfuscation samples are refused; benign network tools are not.

### Added

- `--json` on `run`, `scan` and `deps`: one document on stdout matching `docs/report.schema.json` (schema version 1); human output and the script's stdout go to stderr (#25).
- `coldrun scan SOURCE`: fetch, detect, resolve and vet, print findings and the verdict, never build or run. Exits 100 on a high verdict (#24).
- Script rules: three Semgrep rules for Python (decoded exec, download-and-execute, computed imports) and seven YARA rules for any language (download to shell, cron, shell rc, systemd or autostart persistence, credential paths, obfuscated shell, encoded blobs), each with a match and a nomatch fixture. yara-python comes from the new `vet` extra, semgrep is an external tool (`uv tool install semgrep`); `coldrun doctor` reports both (#22).
- GuardDog dependency vetting: every resolved PyPI, npm, Go, RubyGems or crates package is scanned before install; GuardDog's package risk label sets the severity (no risks: info, low, suspicious: medium, high_risk: high), install hooks are at least medium, plain capability hits are hidden, and a PyPI release older than 30 days is capped at low; a missing or failed scan is a low finding. `coldrun doctor` reports guarddog (#21).
- Risk score model: `vet.scoring.score` folds findings into a low, medium or high verdict with reasons; findings about hosts in `--allow-host` are dropped, any other hardcoded host is always surfaced (#20).

## [0.2.0] - 2026-11-16

Completes milestone M2: a Python script with three third-party imports and a Bash script using jq and curl both run with zero manual setup.

### Added

- `coldrun deps SOURCE [--lang NAME]`: fetch, detect and print the resolved dependencies without installing or running anything (#19).
- Environment cache: dependencies install once into `~/.cache/coldrun/envs/<key>` (key = runner, interpreter and resolved packages), bound read-only on later runs; `coldrun cache list` and `coldrun cache clean`; the report shows the environment as installed or cached (#18).
- Bash runner: commands the script invokes are resolved as system binaries; a missing one stops the run with exit 102 and the exact `pacman -S` or `apt install` line from a command-to-package table (#17).

### Added

- Python 3 runner: dependencies from a PEP 723 block, a `requirements.txt` beside the script, or third-party imports inferred with `ast` (stdlib and local modules excluded, common import-to-distribution names mapped); installed with `uv pip install --target` inside the sandbox and run with the host `python3`. Host executables outside `/usr` that a runner needs (uv) are exposed read-only as `/usr/local/bin/<name>` (#16).

## [0.1.1] - 2026-11-12

Completes milestone M1: a local hello-world script runs sandboxed with no network and no home access. This is what 0.1.0 was meant to ship; that tag was cut before the pipeline landed.

### Added

- `coldrun run SOURCE [flags] [-- args]`: the eight-step pipeline wired end to end with `--net`, `--rw`, `--out`, `--backend`, `--lang`, `--yes` and `--force`; a minimal `sh` runner so shell scripts run inside bubblewrap; files the script writes in `/work` are copied to `--out`; a basic decision gate (high refuses unless `--force`, medium asks unless `--yes`); `python -m coldrun` (#15).
- The release workflow publishes to PyPI only when the repository variable `PYPI_TRUSTED_PUBLISHER` is `true`, so releases stay green until trusted publishing is configured on pypi.org (#60).

### Fixed

- Semgrep findings in the sandbox probe and doctor: the probe raises `SandboxError` instead of asserting, and the two `subprocess` imports carry a justified suppression; `semgrep (own code)` and `pip-audit` are now required checks (#62).

## [0.1.0] - 2026-11-12

Core pipeline building blocks. Released early, before `coldrun run` existed, so this version can fetch, detect, sandbox and report but has no `run` command; use 0.1.1.

### Added

- `coldrun doctor`: checks Python, bubblewrap, unprivileged user namespaces, TIOCSTI, podman, uv and the cache directory, prints pass/warn/fail with the exact fix, exits 1 on failures (#14).
- Report layer: `Report` model filled in as the pipeline advances, a Rich summary of source, runner, dependencies, findings by severity, sandbox and network policy, what was blocked, files written and the exit code; errors always print what failed and `next:` what to try; `ExitCode` 100/101/102 (#13).
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

[Unreleased]: https://github.com/rj-karan/coldrun/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/rj-karan/coldrun/compare/v0.4.0...v1.0.0
[0.4.0]: https://github.com/rj-karan/coldrun/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/rj-karan/coldrun/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/rj-karan/coldrun/compare/v0.1.1...v0.2.0
[0.1.1]: https://github.com/rj-karan/coldrun/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/rj-karan/coldrun/compare/v0.0.1...v0.1.0
[0.0.1]: https://github.com/rj-karan/coldrun/releases/tag/v0.0.1
