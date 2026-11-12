# Security policy

coldrun exists to run untrusted scripts. A flaw in the sandbox is the most
serious bug the project can have, and it is treated that way.

## Reporting a vulnerability

Report privately through a GitHub security advisory:
<https://github.com/rj-karan/coldrun/security/advisories/new>

Do not open a public issue, pull request or discussion for anything that could
let a script reach the host. You will get an acknowledgement within 72 hours
and a fix or a mitigation plan within 14 days for high and critical reports.
Credit is given in the advisory and the changelog unless you ask otherwise.

## Severity

| Severity | Examples |
|---|---|
| Critical | Sandbox escape: a script reads or writes outside the sandbox, reaches the network when the policy says none, gains capabilities, or touches `$HOME`, SSH keys, credentials, the Docker socket or the D-Bus session |
| High | The host imports, sources or executes fetched content; dependency installation runs outside the sandbox; archive extraction writes outside the quarantine directory |
| Medium | A vetting bypass that hides a finding the rules should have produced; environment scrubbing lets a secret through |
| Low | Information disclosure about the host inside the sandbox; denial of service against coldrun itself |

A vetting false negative on its own is **not** a vulnerability. The scan is a
warning; the sandbox is the protection. If a malicious script runs but stays
contained, report it as a missed detection through the issue template.

## Supported versions

Only the latest minor release gets security fixes. Pre-1.0 releases may ship
breaking changes to close a hole.

## Scope notes

- coldrun is not a VM. It is not designed to analyse live malware that targets
  the kernel or the container runtime; kernel and bubblewrap or Podman
  vulnerabilities belong upstream.
- GUI programs and non-Linux hosts are out of scope.
