# Threat model

coldrun assumes the script is hostile and that the scan can miss it. Static
analysis does not see through every obfuscation or a compiled payload, so the
design must stay safe when the verdict is "low".

## What the sandbox guarantees

These hold for every runner and both backends.

- No access to `$HOME`, SSH keys, browser profiles, cloud credentials, the
  Docker socket or the D-Bus session.
- New user, PID, mount, IPC, UTS and network namespaces; all capabilities
  dropped; no new privileges.
- Read-only root filesystem; private tmpfs for `/tmp` and `/run`; the script
  read-only in `/work`; only `/work` and paths you pass with `--rw` are writable.
- Network off by default. With `--allow-host`, only those destinations, through
  a host-side proxy, with no DNS for anything else.
- Dependencies install inside the sandbox with network limited to the package
  registry, and npm runs with `--ignore-scripts`.
- The environment is scrubbed to an allowlist; your tokens and keys in
  environment variables never reach the script.

The **bubblewrap** backend runs everything that uses host toolchains: Python 3,
Bash, Node, Go and Ruby. The **Podman** backend runs runners that ship an image
(Python 2), rootless, with `--cap-drop=all`, `--read-only`, `--userns=keep-id`
and a pid limit. The same escape tests run against both in CI.

## What vetting adds

Vetting decides whether to run, ask, or refuse. It is a warning layer on top
of the sandbox, not a replacement for it.

| Layer | Checks | Tooling |
|---|---|---|
| Script | Decoded or rebuilt code passed to exec, download and execute, reads of credential paths, persistence through cron, shell rc files, systemd or autostart, obfuscated shell, large encoded blobs | YARA rules for any language, Semgrep rules for Python |
| Dependencies | Known-malicious packages, install hooks, suspicious code in the package | GuardDog, with the package's own risk label |
| Source | GitHub repository or owner account younger than 30 days, recent force-pushes to the fetched branch | GitHub API |

Low runs, medium asks (or refuses without a terminal unless `--yes`), and high
refuses unless `--force`. A hardcoded host that is not in `--allow-host` is
always shown.

## What coldrun does not protect against

- **What you let out.** `--net full`, `--rw` and `--listen ADDR:PORT` widen the
  sandbox on purpose. A script with full network can talk to anything.
- **The kernel.** A kernel exploit that escapes user namespaces escapes
  bubblewrap and rootless Podman alike. Keep the kernel patched.
- **Outputs.** Files the script writes are copied to `--out`. Treat them as
  untrusted.
- **TIOCSTI on old kernels.** When the kernel still allows terminal injection,
  interactive scripts run in a new session without job control.
  `coldrun doctor` reports it.

Report a sandbox escape privately through
[GitHub security advisories](https://github.com/rj-karan/coldrun/security/advisories/new).
