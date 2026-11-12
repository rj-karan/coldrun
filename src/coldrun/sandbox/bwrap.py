"""Bubblewrap backend: light, no daemon, the default.

The sandbox gets new user, PID, mount, IPC, UTS and (unless ``--net full``)
network namespaces; bubblewrap always sets ``no_new_privs`` and leaves the
sandbox with no capabilities. The root is a read-only view of ``/usr`` and a
handful of ``/etc`` files, with private tmpfs for ``/tmp`` and the work
directory. ``$HOME`` and everything else on the host simply do not exist
inside.
"""

from __future__ import annotations

import os
import shutil
import subprocess  # nosemgrep: gitlab.bandit.B404 -- spawning bwrap is the point; argv lists only
from pathlib import Path
from typing import TYPE_CHECKING

from coldrun.sandbox.base import (
    WORKDIR,
    Availability,
    NetPolicy,
    Policy,
    SandboxError,
    scrub_env,
)

if TYPE_CHECKING:
    from collections.abc import Mapping, Sequence

#: Read-only /etc files every script may need. Missing ones are skipped.
_ETC_RO = ("/etc/ld.so.cache", "/etc/alternatives", "/etc/localtime", "/etc/nsswitch.conf")
#: Added only when the network policy allows traffic.
_ETC_NET = ("/etc/resolv.conf", "/etc/hosts", "/etc/ssl", "/etc/ca-certificates", "/etc/pki")
_USR_SYMLINKS = (
    ("usr/bin", "/bin"),
    ("usr/sbin", "/sbin"),
    ("usr/lib", "/lib"),
    ("usr/lib64", "/lib64"),
)
_TIOCSTI_SYSCTL = Path("/proc/sys/dev/tty/legacy_tiocsti")
_USERNS_CLONE = Path("/proc/sys/kernel/unprivileged_userns_clone")
_APPARMOR_USERNS = Path("/proc/sys/kernel/apparmor_restrict_unprivileged_userns")
_MAX_USERNS = Path("/proc/sys/user/max_user_namespaces")
_DOCTOR = "Run `coldrun doctor` for the fix."


def _read_int(path: Path) -> int | None:
    try:
        return int(path.read_text().strip())
    except (OSError, ValueError):
        return None


def tiocsti_is_blocked() -> bool:
    """True when the kernel refuses TIOCSTI from unprivileged processes.

    Kernels from 6.2 expose ``dev.tty.legacy_tiocsti`` and default it to 0.
    Older kernels always allow the ioctl, which would let a sandboxed script
    type into the user's terminal; then the sandbox gets its own session.
    """
    return _read_int(_TIOCSTI_SYSCTL) == 0


def userns_problem() -> tuple[str, str] | None:
    """Return (reason, hint) when unprivileged user namespaces look disabled."""
    if _read_int(_USERNS_CLONE) == 0:
        return (
            "unprivileged user namespaces are disabled (kernel.unprivileged_userns_clone=0).",
            "Run `sudo sysctl -w kernel.unprivileged_userns_clone=1` or use --backend podman.",
        )
    if _read_int(_APPARMOR_USERNS) == 1:
        return (
            (
                "AppArmor blocks unprivileged user namespaces "
                "(kernel.apparmor_restrict_unprivileged_userns=1)."
            ),
            (
                "Run `sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=0` "
                "or install the bubblewrap AppArmor profile."
            ),
        )
    if _read_int(_MAX_USERNS) == 0:
        return (
            "user namespaces are disabled (user.max_user_namespaces=0).",
            "Run `sudo sysctl -w user.max_user_namespaces=15000`.",
        )
    return None


def _passwd_files(scratch: Path, uid: int, gid: int) -> tuple[Path, Path]:
    """Write minimal passwd and group files so the host's users stay hidden."""
    meta = scratch / ".coldrun"
    meta.mkdir(mode=0o700, exist_ok=True)
    passwd = meta / "passwd"
    group = meta / "group"
    passwd.write_text(
        f"root:x:0:0:root:/root:/bin/sh\ncoldrun:x:{uid}:{gid}:coldrun:{WORKDIR}:/bin/sh\n"
    )
    group.write_text(f"root:x:0:\ncoldrun:x:{gid}:\n")
    return passwd, group


class BwrapBackend:
    """Build and run sandboxes with ``bwrap``."""

    name = "bwrap"

    def __init__(
        self,
        bwrap: str | None = None,
        environ: Mapping[str, str] | None = None,
        uid: int | None = None,
        gid: int | None = None,
    ) -> None:
        """Create a backend; the arguments exist so tests can pin the host state."""
        self._bwrap = bwrap
        self._environ = environ if environ is not None else os.environ
        self._uid = os.getuid() if uid is None else uid
        self._gid = os.getgid() if gid is None else gid

    @property
    def executable(self) -> str | None:
        """Path to ``bwrap`` or ``None`` when it is not installed."""
        return self._bwrap or shutil.which("bwrap")

    def available(self) -> Availability:
        """Check for the binary and for user namespace support."""
        if self.executable is None:
            return Availability(
                False,
                "bubblewrap is not installed.",
                "Install it: `sudo pacman -S bubblewrap` or `sudo apt install bubblewrap`.",
            )
        problem = userns_problem()
        if problem is not None:
            return Availability(False, *problem)
        return Availability(True)

    def command(
        self, policy: Policy, argv: Sequence[str], *, tiocsti_blocked: bool | None = None
    ) -> list[str]:
        """Translate ``policy`` into a ``bwrap`` argument list.

        Args:
            policy: What the script may access.
            argv: The script command, produced by a runner.
            tiocsti_blocked: Override the kernel probe; tests use it.
        """
        bwrap = self.executable or "bwrap"
        blocked = tiocsti_is_blocked() if tiocsti_blocked is None else tiocsti_blocked
        cmd: list[str] = [bwrap, "--unshare-all", "--die-with-parent"]
        if policy.net == NetPolicy.FULL:
            cmd.append("--share-net")
        if not (policy.tty and blocked):
            # Without a fresh session a script on an old kernel could inject
            # keystrokes into the user's terminal through TIOCSTI.
            cmd.append("--new-session")
        cmd += ["--hostname", policy.hostname, "--uid", str(self._uid), "--gid", str(self._gid)]

        # Read-only base system.
        cmd += ["--ro-bind", "/usr", "/usr"]
        for target, link in _USR_SYMLINKS:
            cmd += ["--symlink", target, link]
        for etc in _ETC_RO:
            cmd += ["--ro-bind-try", etc, etc]
        if policy.net != NetPolicy.NONE:
            for etc in _ETC_NET:
                cmd += ["--ro-bind-try", etc, etc]
        passwd, group = _passwd_files(policy.scratch, self._uid, self._gid)
        cmd += ["--ro-bind", str(passwd), "/etc/passwd", "--ro-bind", str(group), "/etc/group"]

        # Kernel interfaces and private writable space.
        cmd += ["--proc", "/proc", "--dev", "/dev"]
        cmd += ["--tmpfs", "/tmp", "--tmpfs", "/run"]  # noqa: S108 - guest paths
        cmd += ["--bind", str(policy.scratch), WORKDIR]
        cmd += ["--ro-bind", str(policy.script), policy.guest_script]
        for p in policy.ro_paths:
            cmd += ["--ro-bind", str(p), str(p)]
        for p in policy.rw_paths:
            cmd += ["--bind", str(p), str(p)]
        # Everything not bound above lives on bwrap's root tmpfs; freeze it.
        cmd += ["--remount-ro", "/", "--chdir", WORKDIR]

        # Scrubbed environment.
        cmd.append("--clearenv")
        for name, value in scrub_env(self._environ, policy.env).items():
            cmd += ["--setenv", name, value]

        cmd.append("--")
        cmd.extend(argv)
        return cmd

    def probe(self) -> None:
        """Start an empty sandbox once to surface setup errors before the real run.

        Raises:
            SandboxError: With bubblewrap's own message and a hint.
        """
        avail = self.available()
        if not avail.ok:
            raise SandboxError(avail.reason, avail.hint)
        bwrap = self.executable
        if bwrap is None:  # pragma: no cover - available() already failed in that case
            raise SandboxError("bubblewrap is not installed.", _DOCTOR)
        cmd = [
            bwrap, "--unshare-all", "--die-with-parent", "--new-session",
            "--ro-bind", "/usr", "/usr", "--symlink", "usr/bin", "/bin",
            "--symlink", "usr/lib", "/lib", "--symlink", "usr/lib64", "/lib64",
            "--proc", "/proc", "--dev", "/dev", "--", "/bin/true",
        ]  # fmt: skip
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, check=False, timeout=30)  # noqa: S603 - fixed argv
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise SandboxError(f"bubblewrap could not start: {exc}.", _DOCTOR) from exc
        if result.returncode != 0:
            detail = result.stderr.strip().splitlines()[-1:] or [f"exit {result.returncode}"]
            raise SandboxError(f"bubblewrap failed to create a sandbox: {detail[0]}.", _DOCTOR)

    def run(self, policy: Policy, argv: Sequence[str]) -> int:
        """Probe, then run with stdin, stdout and stderr inherited."""
        self.probe()
        cmd = self.command(policy, argv)
        try:
            return subprocess.run(cmd, check=False).returncode  # noqa: S603 - argv built by command()
        except OSError as exc:
            raise SandboxError(f"could not start bubblewrap: {exc}.", _DOCTOR) from exc
