"""Prove bubblewrap can build the namespaces the sandbox relies on.

This is the probe the spec asks for before trusting a runner image. It runs
only with ``-m sandbox`` and fails, never skips, when bubblewrap is missing
or cannot create user namespaces.
"""

from __future__ import annotations

import shutil
import subprocess

import pytest

pytestmark = pytest.mark.sandbox

_MINIMAL_ROOT = [
    "--unshare-all",
    "--die-with-parent",
    "--new-session",
    "--ro-bind",
    "/usr",
    "/usr",
    "--symlink",
    "usr/bin",
    "/bin",
    "--symlink",
    "usr/lib",
    "/lib",
    "--symlink",
    "usr/lib64",
    "/lib64",
    "--proc",
    "/proc",
    "--dev",
    "/dev",
    "--tmpfs",
    "/tmp",  # noqa: S108 - mount target inside the sandbox, not a host temp file
    "--clearenv",
    "--setenv",
    "PATH",
    "/usr/bin:/bin",
]


def _bwrap() -> str:
    path = shutil.which("bwrap")
    assert path, "bubblewrap is not installed; install the bubblewrap package"
    return path


def _run_in_bwrap(script: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(  # noqa: S603 - fixed argv, no user input
        [_bwrap(), *_MINIMAL_ROOT, "--", "/bin/sh", "-c", script],
        capture_output=True,
        text=True,
        check=False,
        timeout=30,
    )


def test_bwrap_creates_namespaces_unprivileged() -> None:
    result = _run_in_bwrap("true")
    assert result.returncode == 0, result.stderr


def test_home_is_absent_and_env_is_scrubbed() -> None:
    result = _run_in_bwrap('test ! -e /home && test ! -e /root && test -z "$HOME"')
    assert result.returncode == 0, result.stderr


def test_root_is_read_only_and_tmp_is_private() -> None:
    result = _run_in_bwrap("! touch /usr/muzzle-probe 2>/dev/null && touch /tmp/ok")
    assert result.returncode == 0, result.stderr


def test_network_namespace_has_no_routes() -> None:
    # /proc/net/route holds only its header line when no interface is up.
    result = _run_in_bwrap('[ "$(wc -l < /proc/net/route)" -eq 1 ]')
    assert result.returncode == 0, result.stderr
