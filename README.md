# coldrun

[![CI](https://github.com/rj-karan/coldrun/actions/workflows/ci.yml/badge.svg)](https://github.com/rj-karan/coldrun/actions/workflows/ci.yml)
[![Coverage](https://codecov.io/gh/rj-karan/coldrun/graph/badge.svg)](https://codecov.io/gh/rj-karan/coldrun)
[![PyPI](https://img.shields.io/pypi/v/coldrun?label=pypi)](https://pypi.org/project/coldrun/)
[![Licence: MIT](https://img.shields.io/badge/licence-MIT-blue.svg)](LICENSE)

Fetch, vet and sandbox any downloaded script in one command.

```
coldrun run https://github.com/someone/tool/blob/main/script.py -- --target 10.10.11.5
```

coldrun takes a script from a file, URL, GitHub repo, gist or exploit-db ID,
works out what it needs, checks it for behaviour aimed at your machine, and runs
it inside a sandbox with no network and no access to your home directory.

## Install

```
uvx coldrun --version          # run without installing
pipx install coldrun           # or install for good
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

## Licence

MIT. See [LICENSE](LICENSE).
