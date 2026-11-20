"""Podman backend: the policy model in a rootless container, for runners that ship an image.

Same guarantees as bubblewrap where Podman can give them: all capabilities
dropped, no new privileges, read-only root, private ``/tmp`` and ``/run``,
the host user mapped in (``--userns=keep-id``), a pid limit, network off
unless asked, and the scrubbed environment. ``--allow-host`` uses the same
host-side proxy and bridge as bubblewrap, run with the image's Python.
"""

from __future__ import annotations

import os
import shutil
import subprocess  # nosemgrep: gitlab.bandit.B404 -- spawning podman is the point; argv lists only
import tempfile
from pathlib import Path
from typing import TYPE_CHECKING

from coldrun.distro import install_command
from coldrun.sandbox import bridge
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

PIDS_LIMIT = 1024
#: Podman's own failures (bad image, pull error) exit with this code.
PODMAN_FAILED = 125
_GUEST_BRIDGE = "/run/coldrun/bridge.py"
_GUEST_SOCK_DIR = "/run/coldrun/net"


def _install_hint() -> str:
    return f"Install it: `{install_command(['podman'])}`, then run it rootless."


class PodmanBackend:
    """Build and run ``podman run`` command lines from a :class:`Policy`."""

    name = "podman"

    def __init__(self, podman: str | None = None, environ: Mapping[str, str] | None = None) -> None:
        self.executable = podman or shutil.which("podman")
        self._environ = os.environ if environ is None else environ

    def available(self) -> Availability:
        """Podman must be installed; it decides rootless support itself at run time."""
        if self.executable is None:
            return Availability(False, "podman is not installed.", _install_hint())
        return Availability(True)

    def command(
        self, policy: Policy, argv: Sequence[str], *, proxy_sock: Path | None = None
    ) -> list[str]:
        """Translate ``policy`` into a ``podman run`` argument list."""
        if policy.image is None:
            raise SandboxError(
                "The podman backend runs runners that ship an image.",
                "This runner uses the host toolchain; use --backend bwrap.",
            )
        if policy.listen:
            raise SandboxError(
                "--listen needs the bwrap backend.", "Drop --listen for this runner."
            )
        cmd = [
            self.executable or "podman", "run", "--rm", "--interactive", "--pull=missing",
            "--cap-drop=all", "--security-opt=no-new-privileges", "--read-only",
            "--userns=keep-id", f"--pids-limit={PIDS_LIMIT}", "--hostname", policy.hostname,
            "--tmpfs", "/tmp", "--tmpfs", "/run", "--workdir", WORKDIR,  # noqa: S108 - guest paths
        ]  # fmt: skip
        if policy.net != NetPolicy.FULL:
            cmd.append("--network=none")
        if policy.tty:
            cmd.append("--tty")
        mounts = [(policy.scratch, WORKDIR, "rw")]
        if policy.tree is not None:
            mounts.append((policy.tree, f"{WORKDIR}/{policy.tree.name}", "ro"))
        else:
            mounts.append((policy.script, policy.guest_script, "ro"))
        mounts += [(p, str(p), "ro") for p in policy.ro_paths]
        mounts += [(p, str(p), "rw") for p in policy.rw_paths]
        mounts += [(p, f"/usr/local/bin/{p.name}", "ro") for p in policy.binaries]
        if policy.deps_dir is not None:
            mounts.append((policy.deps_dir, DEPS_DIR, "rw" if policy.deps_writable else "ro"))
        extra_env = dict(policy.env)
        if policy.net == NetPolicy.ALLOW:
            if proxy_sock is None:
                msg = "NetPolicy.ALLOW needs the proxy socket"
                raise SandboxError(msg, "This is a coldrun bug; please open an issue.")
            mounts.append((proxy_sock.parent, _GUEST_SOCK_DIR, "rw"))
            mounts.append((Path(bridge.__file__).resolve(), _GUEST_BRIDGE, "ro"))
            url = f"http://127.0.0.1:{GUEST_PORT}"
            extra_env |= dict.fromkeys(
                ("http_proxy", "https_proxy", "HTTP_PROXY", "HTTPS_PROXY"), url
            )
            guest_sock = f"{_GUEST_SOCK_DIR}/{proxy_sock.name}"
            argv = ["python", _GUEST_BRIDGE, "--proxy", f"{GUEST_PORT}:{guest_sock}", "--", *argv]
        for host, guest, mode in mounts:
            if ":" in str(host) or "," in str(host):
                raise SandboxError(
                    f"podman cannot mount a path with ':' or ',' in it: {host}.",
                    "Rename or move it, or use --backend bwrap.",
                )
            cmd += ["--volume", f"{host}:{guest}:{mode}"]
        for name, value in scrub_env(self._environ, extra_env).items():
            cmd += ["--env", f"{name}={value}"]
        return [*cmd, policy.image, *argv]

    def run(self, policy: Policy, argv: Sequence[str]) -> int:
        """Run the container with stdio passed through; Podman's own failures are errors."""
        avail = self.available()
        if not avail.ok:
            raise SandboxError(avail.reason, avail.hint)
        if policy.net != NetPolicy.ALLOW:
            return self._exec(self.command(policy, argv))
        with tempfile.TemporaryDirectory(prefix="coldrun-net-") as sock_dir:
            proxy = AllowProxy(policy.allow_hosts, Path(sock_dir)).start()
            try:
                return self._exec(self.command(policy, argv, proxy_sock=proxy.path))
            finally:
                proxy.stop()

    def _exec(self, cmd: list[str]) -> int:
        try:
            code = subprocess.run(cmd, check=False).returncode  # noqa: S603 - argv built by command()
        except OSError as exc:
            raise SandboxError(f"could not start podman: {exc}.", _install_hint()) from exc
        if code == PODMAN_FAILED:
            # shortcut: a script that itself exits 125 is reported as a podman failure
            raise SandboxError(
                "podman could not start the container (exit 125).",
                "Read podman's message above; `podman info` checks the rootless setup.",
            )
        return code
