"""Render what ran, what was blocked and the exit code.

Human output goes through Rich to stderr-safe consoles; the JSON form
arrives with the vetting milestone. Errors from any pipeline step are shown
the same way: what failed, then the next command to try.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import IntEnum
from typing import TYPE_CHECKING, Protocol, runtime_checkable

from rich.console import Console
from rich.table import Table
from rich.text import Text

from coldrun.vet.findings import Severity

if TYPE_CHECKING:
    from collections.abc import Sequence

    from coldrun.detect import Detection
    from coldrun.fetch.base import Fetched
    from coldrun.runners.base import DepSet
    from coldrun.vet.findings import Finding


class ExitCode(IntEnum):
    """Exit codes coldrun uses for its own failures.

    Anything else is the script's own exit code, passed through.
    """

    OK = 0
    REFUSED = 100
    SANDBOX_FAILED = 101
    DEPS_FAILED = 102
    USAGE = 2


@runtime_checkable
class UserFacingError(Protocol):
    """Errors that carry a one-sentence cause and a next step."""

    what: str
    hint: str


@dataclass(slots=True)
class Report:
    """Everything the user should know about one run.

    Fields are filled in as the pipeline advances, so a report rendered after
    a failure shows how far it got.
    """

    source: Fetched | None = None
    detection: Detection | None = None
    deps: DepSet | None = None
    findings: list[Finding] = field(default_factory=list)
    verdict: str | None = None
    backend: str | None = None
    net: str = "none"
    blocked: list[str] = field(default_factory=list)
    exit_code: int | None = None
    out_dir: str | None = None
    wrote: list[str] = field(default_factory=list)

    @property
    def max_severity(self) -> Severity | None:
        """Highest severity among the findings, or ``None``."""
        if not self.findings:
            return None
        return max((f.severity for f in self.findings), key=lambda s: s.rank)


_SEVERITY_STYLE = {
    Severity.INFO: "dim",
    Severity.LOW: "green",
    Severity.MEDIUM: "yellow",
    Severity.HIGH: "bold red",
}


def default_blocked(net: str) -> list[str]:
    """The protections every run gets, phrased for the report."""
    blocked = [
        "home directory, SSH keys, browser profiles, cloud credentials",
        "Docker socket and D-Bus session",
        "writes outside /work and /tmp",
        "capabilities and privilege escalation",
    ]
    if net == "none":
        blocked.insert(0, "all network access")
    elif net == "allow":
        blocked.insert(0, "network except --allow-host destinations")
    return blocked


def make_console(*, stderr: bool = False, force_plain: bool = False) -> Console:
    """A console for reports; ``force_plain`` disables colour and width tricks for tests."""
    if force_plain:
        return Console(stderr=stderr, color_system=None, width=100, highlight=False)
    return Console(stderr=stderr, highlight=False)


def render(report: Report, console: Console) -> None:
    """Print the run summary."""
    table = Table(show_header=False, box=None, pad_edge=False, padding=(0, 1))
    table.add_column("key", style="bold", no_wrap=True)
    table.add_column("value")

    if report.source is not None:
        table.add_row("source", f"{report.source.origin}  ({report.source.kind})")
        table.add_row("sha256", report.source.sha256)
    if report.detection is not None:
        det = report.detection
        why = ", ".join(det.reasons) or "runner score"
        table.add_row("runner", f"{det.runner.name}  ({det.confidence:.0%}: {why})")
    if report.deps is not None:
        table.add_row("dependencies", _format_deps(report.deps))
    if report.findings:
        table.add_row("findings", _format_findings(report.findings))
    if report.verdict is not None:
        table.add_row("verdict", report.verdict)
    if report.backend is not None:
        table.add_row("sandbox", f"{report.backend}, network {report.net}")
    if report.blocked:
        table.add_row("blocked", "\n".join(report.blocked))
    if report.wrote:
        where = f" -> {report.out_dir}" if report.out_dir else ""
        table.add_row("wrote", "\n".join(report.wrote) + where)
    if report.exit_code is not None:
        table.add_row("exit code", _format_exit(report.exit_code))
    console.print(table)


def render_error(err: BaseException, console: Console) -> None:
    """Print a failure as *what failed* then *next: what to try*."""
    if isinstance(err, UserFacingError):
        console.print(Text(err.what, style="bold red"))
        console.print(Text(f"next: {err.hint}", style="yellow"))
    else:
        console.print(Text(f"{type(err).__name__}: {err}", style="bold red"))
        console.print(Text("next: rerun with COLDRUN_DEBUG=1 and open an issue.", style="yellow"))


def exit_code_for(err: BaseException) -> int:
    """Map a pipeline error to the exit code the CLI should use."""
    code = getattr(err, "exit_code", None)
    if isinstance(code, int):
        return code
    by_name = {
        "FetchError": ExitCode.USAGE,
        "DetectError": ExitCode.USAGE,
        "SandboxError": ExitCode.SANDBOX_FAILED,
        "DepsError": ExitCode.DEPS_FAILED,
        "RefusedError": ExitCode.REFUSED,
    }
    return int(by_name.get(type(err).__name__, 1))


def _format_deps(deps: DepSet) -> str:
    parts: list[str] = []
    if deps.interpreter:
        parts.append(deps.interpreter)
    if deps.packages:
        eco = f"{deps.ecosystem}: " if deps.ecosystem else ""
        parts.append(eco + ", ".join(deps.packages))
    if deps.system_binaries:
        parts.append("binaries: " + ", ".join(deps.system_binaries))
    if not parts:
        return "none"
    return "; ".join(parts) + f"  (from {deps.source})"


def _format_findings(findings: Sequence[Finding]) -> Text:
    text = Text()
    for i, f in enumerate(sorted(findings, key=lambda x: -x.severity.rank)):
        if i:
            text.append("\n")
        text.append(f"{f.severity.value:<6}", style=_SEVERITY_STYLE[f.severity])
        text.append(f" {f.rule_id}  {f.location()}: {f.message}")
    return text


def _format_exit(code: int) -> Text:
    if code == 0:
        return Text("0", style="green")
    try:
        label = ExitCode(code).name.lower().replace("_", " ")
    except ValueError:
        return Text(str(code), style="red")
    return Text(f"{code} ({label})", style="red")
