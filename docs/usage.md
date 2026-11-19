# Usage

```sh
coldrun run SOURCE [flags] [-- script args]   # fetch, detect, vet, sandbox, run
coldrun scan SOURCE                           # vet only: findings and verdict
coldrun deps SOURCE                           # print resolved dependencies, run nothing
coldrun doctor                                # check bubblewrap, podman and the vetting tools
coldrun cache list | clean                    # cached dependency environments
```

Everything after `--` goes to the script untouched. `man coldrun` has the same
reference once the package is installed.

## Sources

| Source | Example |
|---|---|
| Local file | `coldrun run ./poc.py` |
| Raw or plain URL | `coldrun run https://example.com/tool.sh` |
| GitHub file | `coldrun run https://github.com/OWNER/REPO/blob/main/poc.py` |
| GitHub repository | `coldrun run https://github.com/OWNER/REPO` |
| GitHub folder or file at a ref | `coldrun run https://github.com/OWNER/REPO/tree/v1.2/tools/scan.py` |
| Gist | `coldrun run https://gist.github.com/USER/ID` |
| exploit-db | `coldrun run edb:50383` |
| Archive | `coldrun run ./tool.tar.gz` |

A repository, gist or archive is unpacked into quarantine with checks for path
traversal, absolute paths, links that point outside, device entries, size and
member count. The one script at its top (after single top-level folders)
becomes the entry. A file beside it that would shadow a common module, such as
a planted `requests.py`, is refused. The whole tree is visible read-only under
`/work/src`, so the script can reach its sibling files.

## Flags for `run`

| Flag | Default | Meaning |
|---|---|---|
| `--net none\|allow\|full` | `none` | Network policy inside the sandbox |
| `--allow-host HOST[:PORT]` | none | Permit one destination; repeatable; implies `--net allow` |
| `--listen [ADDR:]PORT` | none | Forward a port into the sandbox for callbacks; repeatable |
| `--rw PATH` | none | Mount one host path read-write; repeatable. `/`, `$HOME` and credential directories are refused |
| `--out DIR` | `./coldrun-out` | Where files the script writes in `/work` are copied on exit |
| `--backend bwrap\|podman` | auto | Force a sandbox backend |
| `--lang NAME` | auto | Override type detection |
| `--yes` | off | Skip the confirmation on medium risk |
| `--force` | off | Run despite a high-risk verdict; prints a warning |
| `--json` | off | One JSON document on stdout; see [JSON report](json.md) |

## Network: `--allow-host`

```sh
coldrun run ./scan.py --allow-host target.example:443 --allow-host 10.10.11.42
```

The sandbox keeps an empty network namespace. A proxy on the host connects only
to the listed hosts and resolves names on the host, so the script gets no DNS
for anything else. Inside, the proxy is reachable through the standard
`http_proxy` and `https_proxy` variables. curl, wget, Python `requests` and
package managers honour them; a tool that opens raw sockets needs `--net full`.

## Callbacks: `--listen`

```sh
coldrun run ./exploit.py --listen 10.10.14.5:4444 -- --lhost 10.10.14.5 --lport 4444
```

The host opens the port and hands it to the sandbox; the script listens on
`127.0.0.1:4444` inside. Without an address the host side binds `127.0.0.1`
only, so nothing else on your network can reach it. Give your VPN address, or
`0.0.0.0` if you really mean every interface, so the target can connect back.

## Exit codes

The script's own exit code, except:

| Code | Meaning |
|---|---|
| 2 | Usage error, or the source could not be fetched or recognised |
| 100 | Refused by vetting: high risk without `--force`, or medium risk declined |
| 101 | The sandbox could not be set up; run `coldrun doctor` |
| 102 | Dependencies could not be resolved or installed |

`coldrun scan` exits 100 on a high verdict and 0 otherwise, so
`coldrun scan x && coldrun run x` works in scripts.

## Shell completions

The packages install bash, zsh and fish completions. From a source checkout
they are in `packaging/completions/`.
