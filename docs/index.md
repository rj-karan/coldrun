# coldrun

Fetch, vet and sandbox any downloaded script in one command.

You found a proof of concept on GitHub, a tool in a gist, or an exploit on
exploit-db. Running it means reading it, making a venv, guessing the packages,
installing them on your machine, and hoping. coldrun fetches the script into
quarantine, works out what it needs, vets the script and its dependencies, and
runs it in a sandbox with no network, no home directory and a read-only root
unless you allow more.

**The sandbox is the protection; the scan is the warning.** coldrun stays safe
even when the scan says clean.

## Install

```sh
uv tool install 'coldrun[vet]'   # coldrun with the YARA script rules
uv tool install semgrep guarddog # Python script rules and dependency vetting
coldrun doctor                   # checks bubblewrap, user namespaces and the rest
```

Linux only. Needs Python 3.10 or newer and
[bubblewrap](https://github.com/containers/bubblewrap): `pacman -S bubblewrap`
on Arch and Omarchy, `apt install bubblewrap` on Debian, Kali and Ubuntu.
Podman is needed only for Python 2 scripts.

## A first run

```text
$ coldrun run ./imports.py
imports ok requests yaml BeautifulSoup
source        ./imports.py  (file)
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
them, installed them inside the sandbox, ran the script, and the next run
reuses that environment.

## Where to go next

- [Usage](usage.md): every command, flag and source form, with examples.
- [Threat model](threat-model.md): what the sandbox guarantees and what it does not.
- [Runners](runners.md): the languages coldrun runs and how to add one.
- [JSON report](json.md): the `--json` document for scripts and CI.
