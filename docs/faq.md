# FAQ

## Why not a venv, Docker or firejail?

| | venv | Docker | firejail | coldrun |
|---|---|---|---|---|
| Finds and installs the dependencies for you | no | no | no | yes |
| Script cannot read your home directory | no | yes | yes | yes |
| Network off by default | no | no | no | yes |
| No daemon, no image to build, no root | yes | no | yes | yes |

## The scan said low. Is the script safe?

No. Low means the rules found nothing worth stopping for. The sandbox is what
keeps you safe; the scan only decides whether to ask first.

## My script needs the internet.

Name the hosts with `--allow-host`. Use `--net full` only when the script
opens raw sockets or must reach hosts you cannot list.

## coldrun says node is not installed, but it is.

Your node probably comes from mise, nvm or asdf in your home directory, which
the sandbox hides. Install the distribution package (`pacman -S nodejs npm` or
`apt install nodejs npm`).

## Where do files the script writes go?

The script runs in `/work`. Anything it writes there is copied to
`./coldrun-out` (or `--out DIR`) when it exits.

## How do I clear the dependency cache?

`coldrun cache clean`. Quarantined sources and environments live under
`~/.cache/coldrun/`.

## Which Linux distributions work?

Any with Python 3.10 or newer, bubblewrap and unprivileged user namespaces. CI
runs the real sandbox on Arch, Fedora, Debian, Ubuntu, Rocky 8 and 9, openSUSE
and Alpine. NixOS is not supported yet.

## Does it run on macOS or Windows?

No. The sandbox is built on Linux namespaces through bubblewrap and Podman.
