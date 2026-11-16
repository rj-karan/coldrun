<p align="center">
  <img src="docs/assets/logo.svg" width="112" alt="">
</p>

<h1 align="center">coldrun</h1>

<p align="center">Fetch, vet and sandbox any downloaded script in one command.</p>

<p align="center">
  <a href="https://github.com/rj-karan/coldrun/actions/workflows/ci.yml"><img src="https://github.com/rj-karan/coldrun/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="https://codecov.io/gh/rj-karan/coldrun"><img src="https://codecov.io/gh/rj-karan/coldrun/graph/badge.svg" alt="Coverage"></a>
  <a href="https://pypi.org/project/coldrun/"><img src="https://img.shields.io/pypi/v/coldrun?label=pypi" alt="PyPI"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/licence-MIT-blue.svg" alt="Licence: MIT"></a>
</p>

```
coldrun run https://github.com/someone/tool/blob/main/script.py -- --target 10.10.11.5
```

You found a script on GitHub, exploit-db or a CTF write-up. The usual loop is:
read it, make a venv, guess the packages, install them on your machine, and
hope it does not read `~/.ssh` on the way. coldrun replaces that loop. It
fetches the script into quarantine, works out what it needs, installs that
inside a bubblewrap sandbox, and runs it there: no network unless you say so,
no home directory, no credentials, nothing written outside `/work`.

## What a run looks like

```
$ coldrun run ./imports.py
imports ok requests yaml BeautifulSoup
source        ./imports.py  (file)
sha256        a785b1f5b2d77f22c365e3c0090002d2daa76451a79fa987a1c62c3d100c0eac
runner        python  (100%: shebang /usr/bin/env python3, extension .py)
dependencies  python3; pypi: PyYAML, beautifulsoup4, requests  (from inferred)
verdict       low
environment   fca453c8009e3f3b (installed)
sandbox       bwrap, network none
blocked       all network access
              home directory, SSH keys, browser profiles, cloud credentials
              Docker socket and D-Bus session
              writes outside /work and /tmp
              capabilities and privilege escalation
exit code     0
```

The script had three third-party imports and no manifest. coldrun inferred
them, installed them with uv inside the sandbox, ran the script, and the next
run reuses that environment.

## Why not just a venv, Docker or firejail

| | venv | Docker | firejail | coldrun |
|---|---|---|---|---|
| Finds and installs the dependencies for you | no | no | no | yes |
| Script cannot read your home directory | no | yes | yes | yes |
| Network off by default | no | no | no | yes |
| No daemon, no image to build, no root | yes | no | yes | yes |
| Works on a script you have not read yet | no | no | no | yes |

## Install

```
uv tool install 'coldrun[vet]'   # with the script vetting rules (Semgrep and YARA)
pipx install 'coldrun[vet]'      # or with pipx
uvx coldrun --version            # or run without installing (no vetting)
```

Needs Linux, Python 3.10+ and [bubblewrap](https://github.com/containers/bubblewrap)
(`pacman -S bubblewrap` on Arch and Omarchy, `apt install bubblewrap` on Debian, Kali
and Ubuntu). `coldrun doctor` checks the rest.

## Usage

```
coldrun run SOURCE [flags] [-- script args]   # fetch, detect, vet, sandbox, run
coldrun deps SOURCE                           # print resolved dependencies, run nothing
coldrun doctor                                # check bwrap, user namespaces, uv, podman
coldrun cache list | clean                    # cached dependency environments
```

`SOURCE` is a local path, an `http(s)` URL or a GitHub `blob` URL. Everything
after `--` is passed to the script untouched.

| Flag | Default | Meaning |
|---|---|---|
| `--net none\|full` | `none` | Network policy inside the sandbox (`allow` with `--allow-host` arrives in v0.4.0) |
| `--rw PATH` | none | Mount one host path read-write; repeatable. `/`, `$HOME` and credential directories are refused |
| `--out DIR` | `./coldrun-out` | Where files the script writes in `/work` are copied on exit |
| `--backend bwrap` | auto | Force a sandbox backend (Podman arrives in v1.0.0) |
| `--lang NAME` | auto | Override type detection |
| `--yes` | off | Skip the confirmation on medium risk |
| `--force` | off | Run despite a high-risk verdict; prints a warning |

### What the sandbox guarantees

No `$HOME`, SSH keys, browser profiles, cloud credentials, Docker socket or D-Bus
session. New user, PID, mount, IPC, UTS and network namespaces; no capabilities;
`no_new_privs`. Read-only root, private `/tmp`, the script read-only in `/work`.
Network off unless you ask. Environment scrubbed to an allowlist.

### Exit codes

The script's own exit code, except `100` (refused by vetting), `101` (sandbox could
not be set up; run `coldrun doctor`) and `102` (dependency resolution failed).

### Runners

| Runner | Dependencies from | Installed with |
|---|---|---|
| Python 3 | PEP 723 block, `requirements.txt` beside the script, else imports parsed with `ast` | uv, once per dependency set, cached under `~/.cache/coldrun/envs` |
| Bash / sh | Commands the script invokes | Nothing; missing tools are reported with the `pacman` or `apt` line |

## Status

v0.2.0 completes milestone M2 of the [spec](docs/SPEC.md): Python and Bash
scripts run sandboxed with their dependencies resolved. Vetting with Semgrep,
YARA and GuardDog (M3), `--allow-host` and GitHub/gist/exploit-db sources
(M4), and Podman plus more runners (M5) follow.

## Contributing

Issues and pull requests are welcome; see [CONTRIBUTING.md](CONTRIBUTING.md).
If coldrun saves you a venv-and-pray cycle, a star helps the next person find it.

## Licence

MIT. See [LICENSE](LICENSE).
