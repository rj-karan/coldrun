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
uv tool install 'coldrun[vet]'   # coldrun with the YARA script rules
uv tool install semgrep guarddog # Python script rules and dependency vetting
uvx coldrun --version            # or run without installing (no vetting)
```

Needs Linux, Python 3.10+ and [bubblewrap](https://github.com/containers/bubblewrap)
(`pacman -S bubblewrap` on Arch and Omarchy, `apt install bubblewrap` on Debian, Kali
and Ubuntu). `coldrun doctor` checks the rest.

## Usage

```
coldrun run SOURCE [flags] [-- script args]   # fetch, detect, vet, sandbox, run
coldrun scan SOURCE                           # vet only: findings and verdict, exit 100 on high
coldrun deps SOURCE                           # print resolved dependencies, run nothing
coldrun doctor                                # check bwrap, user namespaces, uv, vetting tools
coldrun cache list | clean                    # cached dependency environments
```

`SOURCE` is a local path, an `http(s)` URL, a GitHub repo, `tree` or `blob` URL, a
gist URL, or `edb:ID` for exploit-db. A tar or zip
is extracted with traversal and link checks and the one script at its top runs with
its siblings visible read-only under `/work/src`. Everything after `--` is passed to
the script untouched.

| Flag | Default | Meaning |
|---|---|---|
| `--net none\|allow\|full` | `none` | Network policy inside the sandbox |
| `--allow-host HOST[:PORT]` | none | Permit one destination; repeatable; implies `--net allow`. The sandbox keeps an empty network namespace and reaches the host through a proxy that connects only to the list, so there is no DNS for anything else. Clients must honour `https_proxy` (curl, wget, requests, uv do; raw sockets need `--net full`) |
| `--listen PORT` | none | Forward one host port into the sandbox for callbacks and reverse shells; repeatable. The script listens on `127.0.0.1:PORT` inside; the rest of the network stays closed |
| `--rw PATH` | none | Mount one host path read-write; repeatable. `/`, `$HOME` and credential directories are refused |
| `--out DIR` | `./coldrun-out` | Where files the script writes in `/work` are copied on exit |
| `--backend bwrap` | auto | Force a sandbox backend (Podman arrives in v1.0.0) |
| `--lang NAME` | auto | Override type detection |
| `--yes` | off | Skip the confirmation on medium risk |
| `--force` | off | Run despite a high-risk verdict; prints a warning |
| `--json` | off | One JSON document on stdout; human output and the script's stdout go to stderr |

### What the sandbox guarantees

No `$HOME`, SSH keys, browser profiles, cloud credentials, Docker socket or D-Bus
session. New user, PID, mount, IPC, UTS and network namespaces; no capabilities;
`no_new_privs`. Read-only root, private `/tmp`, the script read-only in `/work`.
Network off unless you ask. Environment scrubbed to an allowlist.

### JSON output

`--json` on `run`, `scan` and `deps` prints one document on stdout and moves the
human report, and the script's own output, to stderr. The fields are described in
[docs/report.schema.json](docs/report.schema.json); `schema_version` is 1.

```
coldrun scan tool.py --json | jq '.verdict, [.findings[].rule_id]'
```

### Exit codes

The script's own exit code, except `100` (refused by vetting), `101` (sandbox could
not be set up; run `coldrun doctor`) and `102` (dependency resolution failed).

### Runners

| Runner | Dependencies from | Installed with |
|---|---|---|
| Python 3 | PEP 723 block, `requirements.txt` beside the script, else imports parsed with `ast` | uv, once per dependency set, cached under `~/.cache/coldrun/envs` |
| Bash / sh | Commands the script invokes | Nothing; missing tools are reported with the `pacman` or `apt` line |
| Node | `package.json` beside the script, else `require` and `import` statements | The system `npm` with `--ignore-scripts`, registry-only network |
| Go | `go.mod` beside the script, else third-party imports | The system `go get` through `proxy.golang.org` only; built offline |
| Ruby | `Gemfile` beside the script, else `require` lines that are not the standard library | The system `gem install` from rubygems.org only |

## Status

v0.4.0 completes milestone M4 of the [spec](docs/SPEC.md). Python and Bash
scripts run sandboxed with their dependencies resolved. The script and its
dependencies are vetted first. Network access can be limited to named hosts
with `--allow-host`, callbacks arrive through `--listen`, and scripts can come
from archives, GitHub repositories, gists and exploit-db. Podman and more
runners (M5) follow.

## Contributing

Issues and pull requests are welcome; see [CONTRIBUTING.md](CONTRIBUTING.md).
If coldrun saves you a venv-and-pray cycle, a star helps the next person find it.

## Licence

MIT. See [LICENSE](LICENSE).
