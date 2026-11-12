"""``coldrun doctor``: check bwrap, podman, uv and kernel support.

Each check is a small function that returns a :class:`CheckResult` with the
fix for its failure, so the output tells the user exactly what to run next.
The probes are injectable for tests.
"""

from __future__ import annotations

import platform
import shutil
import subprocess  # nosemgrep: gitlab.bandit.B404 -- version probes with fixed argv lists
import sys
from dataclasses import dataclass
from enum import Enum
from typing import TYPE_CHECKING

from rich.table import Table
from rich.text import Text

from coldrun.config import cache_dir
from coldrun.sandbox import bwrap as bw

if TYPE_CHECKING:
    from collections.abc import Callable
    from pathlib import Path

    from rich.console import Console

MIN_PYTHON = (3, 10)


class Status(str, Enum):
    """Outcome of one check."""

    PASS = "pass"  # noqa: S105 - a status, not a password
    WARN = "warn"
    FAIL = "fail"


@dataclass(frozen=True, slots=True)
class CheckResult:
    """One line of doctor output."""

    name: str
    status: Status
    detail: str
    fix: str = ""


def _run_version(argv: list[str]) -> str | None:
    try:
        out = subprocess.run(  # noqa: S603 - fixed argv of a known tool
            argv, capture_output=True, text=True, check=False, timeout=10
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    line = (out.stdout or out.stderr).strip().splitlines()
    return line[0] if line else None


@dataclass(frozen=True, slots=True)
class Probes:
    """Host lookups the checks depend on; tests replace them."""

    which: Callable[[str], str | None] = shutil.which
    version_of: Callable[[list[str]], str | None] = _run_version
    userns_problem: Callable[[], tuple[str, str] | None] = bw.userns_problem
    tiocsti_blocked: Callable[[], bool] = bw.tiocsti_is_blocked
    python_version: tuple[int, int] = sys.version_info[:2]
    kernel: str = platform.release()
    cache: Path | None = None


def check_bwrap(p: Probes) -> CheckResult:
    """Bubblewrap is installed."""
    path = p.which("bwrap")
    if path is None:
        return CheckResult(
            "bubblewrap",
            Status.FAIL,
            "not installed",
            "sudo pacman -S bubblewrap  (Arch)  or  sudo apt install bubblewrap  (Debian, Kali)",
        )
    ver = p.version_of([path, "--version"]) or "version unknown"
    return CheckResult("bubblewrap", Status.PASS, f"{path} ({ver})")


def check_userns(p: Probes) -> CheckResult:
    """Unprivileged user namespaces are allowed."""
    problem = p.userns_problem()
    if problem is None:
        return CheckResult("user namespaces", Status.PASS, "unprivileged user namespaces allowed")
    return CheckResult("user namespaces", Status.FAIL, problem[0], problem[1])


def check_tiocsti(p: Probes) -> CheckResult:
    """The kernel blocks TIOCSTI so interactive scripts can keep the terminal."""
    if p.tiocsti_blocked():
        return CheckResult("TIOCSTI", Status.PASS, "blocked by the kernel; TTY passthrough is safe")
    return CheckResult(
        "TIOCSTI",
        Status.WARN,
        "legacy TIOCSTI allowed; interactive scripts run in a new session (no job control)",
        "sudo sysctl -w dev.tty.legacy_tiocsti=0  (kernel 6.2 or newer)",
    )


def check_podman(p: Probes) -> CheckResult:
    """Podman is optional until a runner needs a full image."""
    path = p.which("podman")
    if path is None:
        return CheckResult(
            "podman",
            Status.WARN,
            "not installed; only needed for Python 2, Node, Go and Ruby runners (M5)",
            "sudo pacman -S podman  or  sudo apt install podman",
        )
    ver = p.version_of([path, "--version"]) or "version unknown"
    return CheckResult("podman", Status.PASS, f"{path} ({ver})")


def check_uv(p: Probes) -> CheckResult:
    """Uv installs Python dependencies inside the sandbox."""
    path = p.which("uv")
    if path is None:
        return CheckResult(
            "uv",
            Status.WARN,
            "not installed; needed by the Python runner (M2)",
            "curl -LsSf https://astral.sh/uv/install.sh | sh   or   sudo pacman -S uv",
        )
    ver = p.version_of([path, "--version"]) or "version unknown"
    return CheckResult("uv", Status.PASS, f"{path} ({ver})")


def check_python(p: Probes) -> CheckResult:
    """Python is new enough for coldrun itself."""
    ver = ".".join(map(str, p.python_version))
    if p.python_version < MIN_PYTHON:
        return CheckResult(
            "python", Status.FAIL, f"{ver} is too old", "coldrun needs Python 3.10 or newer"
        )
    return CheckResult("python", Status.PASS, f"{ver} ({p.kernel})")


def check_cache(p: Probes) -> CheckResult:
    """The cache directory can be created and written."""
    path = p.cache if p.cache is not None else cache_dir()
    try:
        path.mkdir(parents=True, exist_ok=True)
        probe = path / ".doctor-write-test"
        probe.write_text("ok")
        probe.unlink()
    except OSError as exc:
        return CheckResult(
            "cache", Status.FAIL, f"{path}: {exc.strerror}", f"chown or chmod {path}"
        )
    return CheckResult("cache", Status.PASS, str(path))


CHECKS: tuple[Callable[[Probes], CheckResult], ...] = (
    check_python,
    check_bwrap,
    check_userns,
    check_tiocsti,
    check_podman,
    check_uv,
    check_cache,
)


def run_checks(probes: Probes | None = None) -> list[CheckResult]:
    """Run every check and return the results in display order."""
    p = probes or Probes()
    return [check(p) for check in CHECKS]


def has_failures(results: list[CheckResult]) -> bool:
    """True when at least one check failed outright."""
    return any(r.status is Status.FAIL for r in results)


_STYLE = {Status.PASS: "green", Status.WARN: "yellow", Status.FAIL: "bold red"}


def render(results: list[CheckResult], console: Console) -> None:
    """Print the doctor table."""
    table = Table(show_header=True, header_style="bold", box=None, pad_edge=False, padding=(0, 1))
    table.add_column("check", no_wrap=True)
    table.add_column("status", no_wrap=True)
    table.add_column("detail")
    for r in results:
        detail = Text(r.detail)
        if r.fix:
            detail.append("\nfix: ", style="bold")
            detail.append(r.fix)
        table.add_row(r.name, Text(r.status.value, style=_STYLE[r.status]), detail)
    console.print(table)
    if has_failures(results):
        console.print(
            Text(
                "coldrun cannot sandbox scripts until the failures above are fixed.",
                style="bold red",
            )
        )
    else:
        console.print(Text("ready to run.", style="green"))
