"""Bubblewrap backend: light, no daemon, the default.

The sandbox gets new user, PID, mount, IPC, UTS and (unless ``--net full``)
network namespaces; bubblewrap always sets ``no_new_privs`` and leaves the
sandbox with no capabilities. The root is a read-only view of ``/usr`` and a
handful of ``/etc`` files, with private tmpfs for ``/tmp`` and the work
directory. ``$HOME`` and everything else on the host simply do not exist
inside.
"""

from __future__ import annotations

import contextlib
import os
import shutil
import socket
import subprocess  # nosemgrep: gitlab.bandit.B404 -- spawning bwrap is the point; argv lists only
import tempfile
from pathlib import Path
from typing import TYPE_CHECKING

from coldrun.config import cache_dir
from coldrun.safefs import write_nofollow
from coldrun.sandbox import bridge, seccomp
from coldrun.sandbox.base import (
    DEPS_DIR,
    WORKDIR,
    Availability,
    NetPolicy,
    Policy,
    SandboxError,
    scrub_env,
)
from coldrun.sandbox.netproxy import GUEST_PORT, AllowProxy

if TYPE_CHECKING:
    from collections.abc import Mapping, Sequence

#: Read-only /etc files every script may need. Missing ones are skipped.
_ETC_RO = ("/etc/ld.so.cache", "/etc/alternatives", "/etc/localtime", "/etc/nsswitch.conf")
#: Added only when the network policy allows traffic.
_ETC_NET = ("/etc/ssl", "/etc/ca-certificates", "/etc/pki")
#: Only with full network: with --allow-host, names resolve on the host side of the proxy.
_ETC_DNS = ("/etc/resolv.conf", "/etc/hosts")
#: Guest paths for --net allow: the bridge script and the proxy socket directory.
_GUEST_BRIDGE = "/run/coldrun/bridge.py"
_GUEST_SOCK_DIR = "/run/coldrun/net"
_GUEST_PYTHON = "/usr/bin/python3"
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


def _script_bind(policy: Policy) -> list[str]:
    """The script alone, or the whole extracted tree it sits in, read-only under /work."""
    if policy.tree is not None:
        return ["--ro-bind", str(policy.tree), f"{WORKDIR}/{policy.tree.name}"]
    return ["--ro-bind", str(policy.script), policy.guest_script]


def _etc_files(net: NetPolicy) -> tuple[str, ...]:
    """Host ``/etc`` files the sandbox may read: certificates need a network, DNS a full one."""
    files: tuple[str, ...] = _ETC_RO
    if net != NetPolicy.NONE:
        files += _ETC_NET
    if net == NetPolicy.FULL:
        files += _ETC_DNS
    return files


def _host_listener(addr: str, port: int) -> socket.socket:
    """A listening socket on the address the user named, handed into the sandbox."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        sock.bind((addr, port))
        sock.listen(16)
    except OSError as exc:
        sock.close()
        raise SandboxError(
            f"cannot listen on {addr}:{port}: {exc.strerror}.",
            "Pick another --listen port, or an address this machine has.",
        ) from exc
    return sock


def _bridge(
    policy: Policy, proxy_sock: Path | None, listen_fds: Mapping[int, int], argv: Sequence[str]
) -> tuple[list[str], dict[str, str], list[str]]:
    """Mounts, proxy variables and the bridge-wrapped argv for allow-net and listen."""
    cmd = ["--ro-bind", str(Path(bridge.__file__).resolve()), _GUEST_BRIDGE]
    env: dict[str, str] = {}
    opts: list[str] = []
    if policy.net == NetPolicy.ALLOW:
        if proxy_sock is None:
            msg = "NetPolicy.ALLOW needs the proxy socket"
            raise SandboxError(msg, "This is a coldrun bug; please open an issue.")
        # The socket needs a writable mount to connect(); the bridge is our own code.
        cmd += ["--bind", str(proxy_sock.parent), _GUEST_SOCK_DIR]
        url = f"http://127.0.0.1:{GUEST_PORT}"
        env = dict.fromkeys(("http_proxy", "https_proxy", "HTTP_PROXY", "HTTPS_PROXY"), url)
        opts += ["--proxy", f"{GUEST_PORT}:{_GUEST_SOCK_DIR}/{proxy_sock.name}"]
    for _, port in policy.listen:
        if port not in listen_fds:
            msg = f"listen port {port} has no host socket"
            raise SandboxError(msg, "This is a coldrun bug; please open an issue.")
        opts += ["--listen", f"{listen_fds[port]}:{port}"]
    return cmd, env, [_GUEST_PYTHON, _GUEST_BRIDGE, *opts, "--", *argv]


DISABLE_USERNS = "--disable-userns"
#: Per run: plenty for builds and package managers, far short of a fork bomb.
TASKS_MAX = 2048
#: Per run, of physical memory: the rest of the machine stays usable.
MEMORY_MAX = "75%"


def resource_scope(tasks_max: int = TASKS_MAX, memory_max: str = MEMORY_MAX) -> list[str]:
    """``systemd-run`` prefix that runs the sandbox in a limited user scope, or ``[]``.

    Needs systemd and a user session (most desktop Linux). Without one the sandbox
    still runs, without limits, and ``coldrun doctor`` says so.
    """
    exe = shutil.which("systemd-run")
    if exe is None:
        return []
    base = [exe, "--user", "--scope", "--quiet", "--collect"]
    try:
        ok = subprocess.run(  # noqa: S603 - fixed argv
            [*base, "--", "true"], capture_output=True, check=False, timeout=15
        )
    except (OSError, subprocess.TimeoutExpired):
        return []
    if ok.returncode != 0:
        return []
    return [*base, "-p", f"TasksMax={tasks_max}", "-p", f"MemoryMax={memory_max}", "--"]


def bwrap_features(executable: str | None) -> frozenset[str]:
    """Optional flags this bubblewrap supports; ``--disable-userns`` needs 0.8 or newer."""
    if executable is None:
        return frozenset()
    try:
        out = subprocess.run(  # noqa: S603 - fixed argv
            [executable, "--help"], capture_output=True, text=True, check=False, timeout=10
        )
    except (OSError, subprocess.TimeoutExpired):
        return frozenset()
    return frozenset(f for f in (DISABLE_USERNS,) if f in out.stdout + out.stderr)


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


def _passwd_files(etc_dir: Path, uid: int, gid: int) -> tuple[Path, Path]:
    """Minimal passwd and group files so the host's users stay hidden.

    They live in coldrun's cache, which no sandbox mounts: anything written
    into a directory the sandbox can write (such as the scratch directory an
    install step already ran in) could be a symlink planted to redirect it.
    """
    etc_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    texts = {
        "passwd": (
            f"root:x:0:0:root:/root:/bin/sh\ncoldrun:x:{uid}:{gid}:coldrun:{WORKDIR}:/bin/sh\n"
        ),
        "group": f"root:x:0:\ncoldrun:x:{gid}:\n",
    }
    for name, text in texts.items():
        path = etc_dir / name
        if path.is_symlink() or not path.is_file() or path.read_text() != text:
            write_nofollow(path, text)
    return etc_dir / "passwd", etc_dir / "group"


class BwrapBackend:
    """Build and run sandboxes with ``bwrap``."""

    name = "bwrap"

    def __init__(
        self,
        bwrap: str | None = None,
        *,
        environ: Mapping[str, str] | None = None,
        uid: int | None = None,
        gid: int | None = None,
        features: frozenset[str] | None = None,
        scope: list[str] | None = None,
    ) -> None:
        """Create a backend; the arguments exist so tests can pin the host state."""
        self._bwrap = bwrap
        self._environ = environ if environ is not None else os.environ
        self._uid = os.getuid() if uid is None else uid
        self._gid = os.getgid() if gid is None else gid
        self._features = features
        self._scope = scope

    @property
    def features(self) -> frozenset[str]:
        """Optional bubblewrap flags this installation supports, asked once."""
        if self._features is None:
            self._features = bwrap_features(self.executable)
        return self._features

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
        self,
        policy: Policy,
        argv: Sequence[str],
        *,
        tiocsti_blocked: bool | None = None,
        proxy_sock: Path | None = None,
        listen_fds: Mapping[int, int] | None = None,
        seccomp_fd: int | None = None,
    ) -> list[str]:
        """Translate ``policy`` into a ``bwrap`` argument list.

        Args:
            policy: What the script may access.
            argv: The script command, produced by a runner.
            tiocsti_blocked: Override the kernel probe; tests use it.
            proxy_sock: The host-side allowlist proxy socket; required for
                ``NetPolicy.ALLOW``. The sandbox reaches it through the
                bridge on ``127.0.0.1`` and the usual proxy variables.
            listen_fds: ``{port: fd}`` of the listening sockets the host opened
                for ``policy.listen``; the bridge accepts on them inside.
            seccomp_fd: A file descriptor holding :func:`seccomp.program`.
        """
        if policy.image is not None:
            raise SandboxError(
                f"This runner runs in the container image {policy.image}.",
                "Use --backend podman, or leave --backend out.",
            )
        bwrap = self.executable or "bwrap"
        blocked = tiocsti_is_blocked() if tiocsti_blocked is None else tiocsti_blocked
        cmd: list[str] = [bwrap, "--unshare-all", "--die-with-parent", *self._hardening(seccomp_fd)]
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
        for etc in _etc_files(policy.net):
            cmd += ["--ro-bind-try", etc, etc]
        passwd, group = _passwd_files(cache_dir() / "sandbox-etc", self._uid, self._gid)
        cmd += ["--ro-bind", str(passwd), "/etc/passwd", "--ro-bind", str(group), "/etc/group"]

        # Kernel interfaces and private writable space.
        cmd += ["--proc", "/proc", "--dev", "/dev"]
        cmd += ["--tmpfs", "/tmp", "--tmpfs", "/run"]  # noqa: S108 - guest paths
        cmd += ["--bind", str(policy.scratch), WORKDIR, *_script_bind(policy)]
        for p in policy.ro_paths:
            cmd += ["--ro-bind", str(p), str(p)]
        if policy.binaries:
            # /usr is read-only, so give /usr/local/bin a tmpfs to hold the mount points.
            cmd += ["--tmpfs", "/usr/local/bin"]
        for p in policy.binaries:
            cmd += ["--ro-bind", str(p), f"/usr/local/bin/{p.name}"]
        for p in policy.rw_paths:
            cmd += ["--bind", str(p), str(p)]
        if policy.deps_dir is not None:
            mode = "--bind" if policy.deps_writable else "--ro-bind"
            cmd += [mode, str(policy.deps_dir), DEPS_DIR]
        extra_env = dict(policy.env)
        if policy.net == NetPolicy.ALLOW or policy.listen:
            net_cmd, net_env, argv = _bridge(policy, proxy_sock, listen_fds or {}, argv)
            cmd += net_cmd
            extra_env |= net_env
        # Everything not bound above lives on bwrap's root tmpfs; freeze it.
        cmd += ["--remount-ro", "/", "--chdir", WORKDIR]

        # Scrubbed environment.
        cmd.append("--clearenv")
        for name, value in scrub_env(self._environ, extra_env).items():
            cmd += ["--setenv", name, value]

        cmd.append("--")
        cmd.extend(argv)
        return cmd

    @property
    def scope(self) -> list[str]:
        """The systemd scope prefix that limits tasks and memory, or ``[]``, decided once."""
        if self._scope is None:
            self._scope = resource_scope()
        return self._scope

    def _hardening(self, seccomp_fd: int | None) -> list[str]:
        flags: list[str] = []
        if DISABLE_USERNS in self.features:
            # no nested user namespaces: they are how most kernel exploits reach root
            flags += ["--unshare-user", DISABLE_USERNS, "--assert-userns-disabled"]
        if seccomp_fd is not None:
            flags += ["--seccomp", str(seccomp_fd)]
        return flags

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
        bridged = policy.net == NetPolicy.ALLOW or bool(policy.listen)
        if bridged and not Path(_GUEST_PYTHON).exists():
            raise SandboxError(
                f"--allow-host and --listen need {_GUEST_PYTHON} on the host for the bridge.",
                "Install python3 from your distribution, or use --net full.",
            )
        with contextlib.ExitStack() as stack:
            filter_fd = seccomp.memfd()
            stack.callback(os.close, filter_fd)
            proxy = None
            if policy.net == NetPolicy.ALLOW:
                sock_dir = stack.enter_context(tempfile.TemporaryDirectory(prefix="coldrun-net-"))
                proxy = AllowProxy(policy.allow_hosts, Path(sock_dir)).start()
                stack.callback(proxy.stop)
            listeners = [_host_listener(addr, port) for addr, port in policy.listen]
            for sock in listeners:
                stack.callback(sock.close)
            ports = [port for _, port in policy.listen]
            fds = {port: sock.fileno() for port, sock in zip(ports, listeners, strict=True)}
            cmd = self.command(
                policy,
                argv,
                proxy_sock=proxy.path if proxy else None,
                listen_fds=fds,
                seccomp_fd=filter_fd,
            )
            return self._exec(cmd, pass_fds=(*fds.values(), filter_fd))

    def _exec(self, cmd: list[str], pass_fds: tuple[int, ...] = ()) -> int:
        try:
            return subprocess.run(  # noqa: S603 - argv built by command()
                [*self.scope, *cmd], check=False, pass_fds=pass_fds
            ).returncode
        except OSError as exc:
            raise SandboxError(f"could not start bubblewrap: {exc}.", _DOCTOR) from exc
