# runsafe — Claude Code build spec

Nov 12, 2026 · @kk

> **Naming note.** This document was written under the working name `saferun`.
> That name is taken on PyPI (an unrelated Python sandbox, last released March
> 2025), so the project was renamed to **runsafe** before the first commit.
> `runsafe` was verified free on PyPI and the AUR on 2026-11-12. The text below
> uses the new name throughout.

## What we're building

runsafe is a CLI that takes any script you downloaded, works out what it
needs, checks it for malicious behaviour, and runs it in a sandbox. One command
replaces the usual loop of reading the script, making a venv, installing
modules and hoping it is safe.

```
runsafe run https://github.com/someone/tool/blob/main/script.py -- --target 10.10.11.5
```

### In scope

- Any script type, through pluggable runners: Python 3 and 2, Bash, Node, Go,
  Ruby, Perl, PHP, PowerShell, C/C++, prebuilt binaries.
- Any source: local file, raw URL, GitHub repo or gist, exploit-db ID.
- Automatic dependency resolution, installed inside the sandbox and never on
  the host.
- Vetting of the script and its dependencies before anything executes.
- Linux hosts first (Arch, Omarchy, Kali, Debian, Ubuntu).

### Not in scope

- GUI programs and Windows or macOS hosts.
- A guarantee that a script is safe. The scan warns; the sandbox protects.
- Replacing a VM for analysing known live malware.

## Architecture

The core is language-agnostic and each language is a plugin. Fetching,
vetting, sandboxing and reporting are written once; only dependency resolution
and the run command differ per language.

### Pipeline, in order

1. Fetch the source into a quarantine directory. Nothing in it is executed or
   imported by the host.
2. Detect the type from shebang, extension and file magic, then pick a runner.
3. Resolve dependencies through the runner: a manifest if one exists,
   otherwise inferred from the code.
4. Vet the script and every dependency. Produce a risk score with reasons.
5. Decide: low risk runs, medium asks for confirmation, high refuses unless
   `--force`.
6. Build the sandbox, install dependencies inside it, and cache the result by
   content hash.
7. Run inside the sandbox with the chosen network and filesystem policy.
8. Report what ran, what was blocked and the exit code.

### Runner interface

Every language implements the same small contract. Runners are discovered
through Python entry points so third parties can ship their own.

```python
class Runner(Protocol):
    name: str

    def detect(self, path: Path) -> float: ...                 # confidence 0.0 to 1.0
    def resolve_deps(self, path: Path) -> DepSet: ...          # packages, system binaries, interpreter version
    def install_cmd(self, deps: DepSet) -> list[str]: ...      # runs inside the sandbox
    def run_cmd(self, path: Path, args: list[str]) -> list[str]: ...
    def vet(self, path: Path, deps: DepSet) -> list[Finding]: ...  # language-specific checks
```

### Runners and how each resolves dependencies

| Runner | Dependency source | Phase |
|---|---|---|
| Python 3 | PEP 723 block, requirements.txt, else imports via AST; installed with uv | 1 |
| Bash / sh | Commands used in the script mapped to packages | 1 |
| Python 2 | Same as Python 3, run in a Python 2.7 image | 2 |
| Node | package.json, else require and import statements | 2 |
| Go | go.mod, else `go run` module resolution | 2 |
| Ruby | Gemfile, else require statements | 2 |
| Perl / PHP | cpanfile and use statements / composer.json | 3 |
| PowerShell | Import-Module statements, run with pwsh | 3 |
| C / C++ | #include headers mapped to dev packages, compiled with gcc | 3 |
| Binary | None; vet and sandbox only | 3 |

### Stack

- Python 3.10+, packaged with uv and `pyproject.toml`, CLI built on Typer,
  output with Rich.
- Sandbox backends behind one interface: bubblewrap by default (light, no
  daemon), Podman for runners that need a full image.
- Config in `~/.config/runsafe/config.toml`, cache in `~/.cache/runsafe/`.

## CLI

Five commands cover the whole workflow. Everything after `--` is passed to the
script untouched.

```
runsafe run   <source> [flags] [-- script args]   # fetch, vet, sandbox, run
runsafe scan  <source>                            # vet only, never executes
runsafe deps  <source>                            # print resolved dependencies
runsafe doctor                                    # check bwrap, podman, uv, kernel support
runsafe cache list | clean                        # manage cached environments
```

| Flag | Default | Meaning |
|---|---|---|
| `--net none\|allow\|full` | none | Network policy inside the sandbox |
| `--allow-host HOST[:PORT]` | none | Permit one destination; repeatable; implies `--net allow` |
| `--listen PORT` | none | Forward an inbound port into the sandbox (for callbacks and reverse shells) |
| `--rw PATH` | none | Mount one host path read-write; everything else is hidden or read-only |
| `--out DIR` | `./runsafe-out` | Where files the script writes are copied on exit |
| `--backend bwrap\|podman` | auto | Force a sandbox backend |
| `--lang NAME` | auto | Override type detection |
| `--yes` | off | Skip the confirmation on medium risk |
| `--force` | off | Run despite a high-risk verdict; prints a warning |
| `--json` | off | Machine-readable report on stdout |

### Behaviour rules

- Default is deny: no network, no home directory, no write access outside the
  sandbox.
- Interactive scripts work: stdin, stdout and the TTY pass through.
- Exit code is the script's own, except 100 (refused by vetting), 101 (sandbox
  setup failed), 102 (dependency resolution failed).
- Every error says what failed and the next command to try.

## Security model

The sandbox is the protection and the scan is the warning. Static scanning
misses obfuscated and compiled payloads, so the design must stay safe even when
the scan says clean.

### Sandbox rules (must hold for every runner)

- No access to `$HOME`, SSH keys, browser profiles, cloud credentials, the
  Docker socket or the D-Bus session.
- New PID, mount, IPC and user namespaces; no new privileges; all capabilities
  dropped.
- Root filesystem read-only; a private tmpfs for `/tmp` and the working
  directory.
- Network off by default. With `--allow-host`, only those destinations are
  reachable.
- Dependency installation also runs inside the sandbox, with network limited to
  the package registries.
- Environment variables are scrubbed to an allowlist.

### Vetting layers

| Layer | What it checks | Tooling |
|---|---|---|
| Dependencies | Known-malicious packages, typosquats, packages published days ago, install hooks | GuardDog for PyPI, npm, Go, RubyGems; registry metadata |
| Script | Obfuscation, encoded payloads passed to exec / eval, download-and-execute, reads of credential paths, persistence (cron, shell rc, systemd) | Semgrep and YARA rules in `rules/` |
| Source | Repo age, author account age, recent force-pushes | GitHub API, optional |
| Binaries | Packing, suspicious strings, known signatures | YARA, optional ClamAV |

### Rules for the rules

- Security tools legitimately open sockets and spawn shells. Flag behaviour
  aimed at the host, not network activity towards a target the user named.
- Every finding carries a rule ID, severity, file, line and a one-line
  explanation.
- A hardcoded IP or domain that is not in `--allow-host` is always shown to the
  user.

### Threats the tests must cover

- Malicious dependency that runs code at install time.
- Script that reads `~/.ssh` or browser cookies and posts them out.
- Script that writes to shell rc files or cron for persistence.
- Path traversal or symlink tricks in a fetched archive.
- Planted files that shadow imports in the quarantine directory.

### Hard rules for the codebase

- The host never imports, sources or executes fetched content. Parsing only.
- Subprocess calls use argument lists, never `shell=True`.
- Archives are extracted with path and symlink checks.
- No real malware in the repo. Test fixtures are harmless synthetic samples
  that only match the rules.

## Repo standards

Nothing lands on main without an issue, a branch, a pull request and green CI.
Claude Code follows this for every change, including its own.

### Layout

```
runsafe/
  src/runsafe/
    cli.py              # Typer app, no logic
    pipeline.py         # the eight steps
    fetch/              # url, github, gist, exploitdb
    detect.py
    runners/            # one module per language + base.py
    vet/                # engine, findings, scoring
    sandbox/            # base.py, bwrap.py, podman.py
    report.py
    config.py
  rules/                # semgrep and yara rules, versioned
  tests/
    unit/
    integration/
    fixtures/           # synthetic sample scripts per language
  docs/                 # mkdocs: usage, threat model, writing a runner
  packaging/            # aur/PKGBUILD, debian/
  .github/
    workflows/
    ISSUE_TEMPLATE/
    PULL_REQUEST_TEMPLATE.md
    CODEOWNERS
    dependabot.yml
  pyproject.toml
  README.md  CONTRIBUTING.md  SECURITY.md  CODE_OF_CONDUCT.md
  CHANGELOG.md  LICENSE  CLAUDE.md
```

### Workflow for every change

1. Open an issue with the right template and labels, and attach it to a
   milestone.
2. Branch from main as `feat/12-bash-runner`, `fix/31-symlink-check`,
   `docs/…`, `chore/…`.
3. Commit in small steps using Conventional Commits: `feat(runners): add bash
   runner`.
4. Open a pull request that fills the template and says `Closes #12`.
5. Wait for CI. Fix failures on the branch; never disable a check to get green.
6. Squash-merge, delete the branch, confirm the issue closed.

### Branch protection on main

- Pull request required; direct pushes and force pushes blocked.
- Required checks: lint, types, tests, CodeQL.
- Linear history, squash merges only.

### Templates and files to create

| File | Contents |
|---|---|
| Issue: bug | Version, distro, command run, expected, actual, `runsafe doctor` output |
| Issue: feature | Problem, proposal, alternatives |
| Issue: new runner | Language, how dependencies are declared, sample scripts |
| Issue: false positive / missed detection | Rule ID, sample, why it is wrong |
| PR template | What and why, linked issue, how it was tested, checklist (tests, docs, changelog) |
| SECURITY.md | Private reporting through GitHub security advisories; sandbox escapes are the top severity |
| CONTRIBUTING.md | Dev setup with uv, running tests, adding a runner, commit style |
| CLAUDE.md | The rules in this section plus the hard rules from the security model |

Labels: `type:bug`, `type:feature`, `type:docs`, `type:chore`, `area:core`,
`area:sandbox`, `area:vet`, `area:runner-<lang>`, `area:packaging`,
`security`, `good first issue`, `priority:high`.

### Code quality

- Ruff for lint and format, mypy in strict mode, full type hints, docstrings on
  public functions.
- pre-commit runs ruff, mypy, a secrets scan and a check for Conventional
  Commit messages.
- Keep a Changelog format, Semantic Versioning, MIT licence.

## Testing and CI/CD

Every pull request must pass lint, types, tests and security scans before
merge. Coverage must stay at or above 85%, and 100% of sandbox policy code must
be covered.

### Test levels

| Level | What it proves | Where |
|---|---|---|
| Unit | Detection, dependency inference, scoring, config, archive checks | `tests/unit`, no sandbox needed |
| Runner contract | Every runner passes the same suite against its fixtures | `tests/unit/runners`, parametrised |
| Sandbox escape | A script trying to read `~/.ssh`, write outside the sandbox, or reach a blocked host fails | `tests/integration`, marked `sandbox` |
| End to end | `runsafe run` on a fixture per language installs dependencies and returns the right output | `tests/integration`, marked `e2e` |
| Rules | Each Semgrep and YARA rule has one sample that must match and one that must not | `tests/unit/vet` |

A bug fix always adds a test that fails before the fix.

### GitHub Actions workflows

| Workflow | Trigger | Does |
|---|---|---|
| `ci.yml` | Pull request, push to main | Ruff, mypy, pytest on Python 3.10 to 3.13, coverage upload, build the wheel |
| `integration.yml` | Pull request, push to main | Sandbox and end-to-end tests with bubblewrap and Podman installed |
| `codeql.yml` | Pull request, weekly | CodeQL analysis for Python |
| `security.yml` | Pull request, weekly | pip-audit on dependencies, secrets scan, Semgrep on our own code |
| `pr-lint.yml` | Pull request | Title follows Conventional Commits, an issue is linked |
| `release.yml` | Tag `v*` | Build, publish to PyPI with trusted publishing, create the GitHub release with notes and checksums |
| `docs.yml` | Push to main | Build and publish the docs site |

Dependabot opens weekly update pull requests for Python packages and for the
Actions themselves.

### CI rules

- Pin third-party Actions to a commit SHA and give each workflow the minimum
  `permissions`.
- Cache uv downloads so a run stays under five minutes.
- Hosted runners may restrict unprivileged user namespaces, which bubblewrap
  needs. `integration.yml` must check this and enable it, or fail with a clear
  message. Verify on the current runner image before relying on it.
- A flaky test is fixed or removed, never retried into passing.
- README badges: CI status, coverage, PyPI version, licence.

## Milestones

Six milestones, worked in order; each one ends with a tagged release. Claude
Code creates the milestones and their issues first, then works them one pull
request at a time.

| Milestone | Issues to open | Done when |
|---|---|---|
| M0 Foundation (v0.0.1) | Repo scaffold; pyproject and uv; ruff, mypy, pre-commit; all templates and community files; CI, CodeQL, Dependabot; branch protection; labels; CLAUDE.md | An empty `runsafe --version` passes every check on a pull request |
| M1 Core pipeline (v0.1.0) | Fetch from file and URL; type detection; runner base class and registry; bubblewrap backend; report output; doctor | A local hello-world script runs sandboxed with no network and no home access |
| M2 First runners (v0.2.0) | Python 3 runner with uv and import inference; Bash runner with command-to-package mapping; environment cache; `deps` command | A Python script with three third-party imports and a Bash script using jq and curl both run with zero manual setup |
| M3 Vetting (v0.3.0) | Finding and score model; GuardDog integration; Semgrep and YARA rule sets; decision gate; `scan` command; `--json` | Synthetic exfiltration, persistence and obfuscation samples are refused; benign network tools are not |
| M4 Network and sources (v0.4.0) | `--allow-host` filtering; `--listen` port forward; GitHub repo, gist and exploit-db fetchers; archive safety checks | A script reaches only the allowed host, and a callback arrives on the forwarded port |
| M5 More runners and packaging (v1.0.0) | Podman backend; Python 2, Node, Go, Ruby runners; docs site; PyPI release; AUR package; man page and shell completions | `uvx runsafe` and the AUR package both install and pass doctor on a clean Arch and Kali machine |

After v1.0.0: Perl, PHP, PowerShell, C/C++ compile-and-serve mode, binary
scanning, Debian packaging for the Kali request.

## Packaging and release

PyPI and the AUR ship at v1.0.0; the Kali request waits until the project has
users and a few months of steady releases.

| Channel | How | When |
|---|---|---|
| GitHub Releases | `release.yml` on a `v*` tag, with changelog notes and checksums | Every milestone |
| PyPI | Trusted publishing from `release.yml`; users run `uvx runsafe` or `pipx install runsafe` | v0.1.0 onwards |
| AUR | `packaging/aur/PKGBUILD` for `runsafe` (tagged) and `runsafe-git`; covers Arch and Omarchy | v1.0.0 |
| Kali | Debian packaging in `packaging/debian/`, then a New Tool Request on bugs.kali.org | After v1.0.0, with traction |

### Release steps

1. Move the Unreleased entries in `CHANGELOG.md` under the new version.
2. Bump the version in `pyproject.toml` through a pull request.
3. Tag `vX.Y.Z` on main; the workflow does the rest.
4. Update the AUR PKGBUILD checksum and push it.

### Kali request checklist

Kali asks for the licence, dependencies, similar tools, development activity
and install steps, and wants a real case made for the tool (submitting tools,
tools policy). Have these ready first:

- MIT licence and tagged, signed releases
- Runtime dependencies limited to packages already in Debian (bubblewrap,
  python3, uv or pip)
- A comparison with the closest tools and what runsafe adds
- Regular commits and closed issues over at least two to three months
- Working Debian package built from `packaging/debian/`
- A short demo and docs site
- A statement that you will maintain the package

## Kickoff prompt for Claude Code

Save this document as `docs/SPEC.md` in an empty folder, make sure `gh auth
status` works, then paste the prompt below.

```
You are building `runsafe`, an open-source CLI. The full specification is in
docs/SPEC.md. Read it completely before doing anything.

Work like a professional maintainer:

1. Create the GitHub repo with `gh` (public, MIT), then do milestone M0 only:
   scaffold, tooling, templates, community files, CI workflows, labels,
   milestones M0 to M5, and CLAUDE.md containing the repo standards and the
   hard security rules from the spec.
2. Open one GitHub issue per item listed under each milestone, with labels
   and the milestone set. Do not write feature code before the issues exist.
3. For every issue: create a branch named for it, write tests first where
   practical, implement, run ruff, mypy and pytest locally, commit with
   Conventional Commits, open a pull request that fills the template and
   says "Closes #N", wait for CI to pass, then squash-merge.
4. Never push to main directly. Never skip, disable or weaken a check to get
   green. If CI fails, fix the cause on the branch.
5. Keep CHANGELOG.md and the docs updated in the same pull request as the
   change.
6. Follow the security model exactly. The host must never execute or import
   fetched content. Do not add real malware as test data; write harmless
   synthetic fixtures.
7. Work one milestone at a time. At the end of each milestone, tag the
   release, then stop and give me a short summary: what shipped, what is
   open, and any decision you need from me.

Before creating the repo, check that the name is free on PyPI, the AUR and
GitHub. If it is taken, propose three alternatives and wait.

If the spec is unclear or two parts conflict, open an issue labelled
`question` and ask me instead of guessing.

Start with M0 now.
```

## Before you start

- Decide whether the repo lives under your personal account or your
  organisation
- Install `gh`, `uv`, bubblewrap and podman locally
- Turn on branch protection after M0 if Claude Code cannot set it through the
  API
- Review and merge the first few pull requests yourself to check the standard
  is being met
