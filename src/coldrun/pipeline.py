"""The eight pipeline steps: fetch, detect, resolve, vet, decide, build, run, report.

Everything the ``run`` command does lives here so the CLI stays logic-free
and the steps can be tested with fake backends and registries.
"""

from __future__ import annotations

import re
import shutil
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING

from coldrun import cache
from coldrun.detect import detect
from coldrun.fetch import fetch
from coldrun.report import ExitCode, Report, default_blocked, exit_code_for, render, render_error
from coldrun.runners.registry import Registry, default_registry
from coldrun.runners.shell import package_for
from coldrun.sandbox import BwrapBackend, NetPolicy, Policy, SandboxError
from coldrun.sandbox.base import WORKDIR
from coldrun.vet.findings import Severity

if TYPE_CHECKING:
    from collections.abc import Sequence

    from rich.console import Console

    from coldrun.detect import Detection
    from coldrun.fetch.base import Fetched
    from coldrun.runners.base import DepSet, Runner
    from coldrun.sandbox.base import Backend
    from coldrun.vet.findings import Finding

#: Files the pipeline itself keeps in the scratch directory.
_SCRATCH_META = ".coldrun"
_OS_RELEASE = Path("/etc/os-release")


class DepsError(Exception):
    """Dependency resolution or installation failed. Exit 102."""

    exit_code = int(ExitCode.DEPS_FAILED)

    def __init__(self, what: str, hint: str) -> None:
        """Keep the halves separate for the report."""
        super().__init__(f"{what} {hint}")
        self.what = what
        self.hint = hint


class RefusedError(Exception):
    """Vetting refused to run the script. Exit 100."""

    exit_code = int(ExitCode.REFUSED)

    def __init__(self, what: str, hint: str) -> None:
        """Keep the halves separate for the report."""
        super().__init__(f"{what} {hint}")
        self.what = what
        self.hint = hint


@dataclass(slots=True)
class RunOptions:
    """Everything the ``run`` command accepts."""

    source: str
    args: list[str] = field(default_factory=list)
    net: NetPolicy = NetPolicy.NONE
    rw: list[Path] = field(default_factory=list)
    out: Path = Path("./coldrun-out")
    backend: str | None = None
    lang: str | None = None
    yes: bool = False
    force: bool = False
    tty: bool | None = None

    def is_tty(self) -> bool:
        """Whether stdin is a terminal, unless overridden."""
        return sys.stdin.isatty() if self.tty is None else self.tty


@dataclass(slots=True)
class Services:
    """Injection points for tests: registry, backends and the confirm prompt."""

    registry: Registry = field(default_factory=default_registry)
    backends: dict[str, Backend] = field(default_factory=lambda: {"bwrap": BwrapBackend()})
    confirm: object = None  # Callable[[str], bool]; None means ask on the terminal


def choose_backend(name: str | None, backends: dict[str, Backend]) -> Backend:
    """``--backend`` or the first available one."""
    if name is not None:
        if name not in backends:
            known = ", ".join(sorted(backends)) or "none"
            raise SandboxError(
                f"backend {name!r} is not available in this version.",
                f"Use one of: {known}. Podman arrives in v1.0.0 (#30).",
            )
        backend = backends[name]
        avail = backend.available()
        if not avail.ok:
            raise SandboxError(avail.reason, avail.hint)
        return backend
    reasons: list[str] = []
    for backend in backends.values():
        avail = backend.available()
        if avail.ok:
            return backend
        reasons.append(f"{backend.name}: {avail.reason} {avail.hint}")
    raise SandboxError(
        "No sandbox backend is usable. " + " ".join(reasons), "Run `coldrun doctor`."
    )


def decide(
    findings: Sequence[Finding], opts: RunOptions, services: Services, console: Console
) -> str:
    """Step 5: low runs, medium asks, high refuses unless ``--force``.

    Returns the verdict label. The full score model lands in #20 and #23;
    until then the verdict is the highest severity among the findings.
    """
    top = max((f.severity for f in findings), key=lambda s: s.rank, default=Severity.LOW)
    verdict = {Severity.INFO: "low"}.get(top, top.value)
    if top is Severity.HIGH:
        if not opts.force:
            raise RefusedError(
                "Vetting found high-risk behaviour; refusing to run.",
                "Review the findings above, then rerun with --force if you accept the risk.",
            )
        console.print("[bold red]warning:[/] running despite a high-risk verdict (--force)")
    elif top is Severity.MEDIUM and not opts.yes:
        if services.confirm is not None:
            ok = bool(services.confirm("Medium risk. Run anyway?"))  # type: ignore[operator]
        elif opts.is_tty():
            ok = console.input("Medium risk. Run anyway? [y/N] ").strip().lower() in {"y", "yes"}
        else:
            raise RefusedError(
                "Vetting found medium-risk behaviour and no terminal is attached to confirm.",
                "Rerun with --yes to accept, or run interactively.",
            )
        if not ok:
            raise RefusedError("Not running.", "Rerun with --yes to skip this prompt.")
    return verdict


def _resolve(runner: Runner, path: Path) -> DepSet:
    try:
        deps = runner.resolve_deps(path)
    except Exception as exc:
        raise DepsError(
            f"The {runner.name} runner could not work out dependencies: {exc}.",
            "Run `coldrun deps SOURCE` for details, or pass --lang to pick another runner.",
        ) from exc
    missing = sorted(b for b in deps.system_binaries if shutil.which(b) is None)
    if missing:
        raise DepsError(
            f"The script needs commands not installed here: {', '.join(missing)}.",
            install_hint(missing),
        )
    return deps


def host_distro() -> str:
    """``arch`` or ``debian`` from /etc/os-release; debian when unsure."""
    try:
        text = _OS_RELEASE.read_text()
    except OSError:
        return "debian"
    ids = " ".join(re.findall(r'^ID(?:_LIKE)?=["\']?([^"\'\n]*)', text, flags=re.MULTILINE))
    return "arch" if "arch" in ids.split() else "debian"


def install_hint(missing: Sequence[str]) -> str:
    """The package manager command that provides ``missing``."""
    distro = host_distro()
    known = [p for p in (package_for(m, distro) for m in missing) if p]
    unknown = [m for m in missing if package_for(m, distro) is None]
    tool = "sudo pacman -S" if distro == "arch" else "sudo apt install"
    parts = [f"{tool} {' '.join(dict.fromkeys(known))}"] if known else []
    if unknown:
        parts.append(f"no known package for: {', '.join(unknown)}")
    return "; ".join(parts) + "."


def _host_binaries(*cmds: Sequence[str]) -> tuple[Path, ...]:
    """Executables a command needs that live outside ``/usr`` on the host."""
    found: list[Path] = []
    for cmd in cmds:
        # Look past `env` and its VAR=value prefixes to the real program.
        rest = [a for a in cmd if "=" not in a]
        if rest and Path(rest[0]).name == "env":
            rest = rest[1:]
        head = rest[0] if rest else ""
        where = shutil.which(head) if head and "/" not in head else None
        if where and not where.startswith("/usr/"):
            found.append(Path(where))
    return tuple(dict.fromkeys(found))


def _scratch_for(fetched: Fetched) -> Path:
    scratch = fetched.quarantine / "scratch"
    scratch.mkdir(mode=0o700, exist_ok=True)
    return scratch


def _install(backend: Backend, policy: Policy, runner: Runner, deps: DepSet) -> str | None:
    """Install into the cached environment unless it is already there.

    Returns the environment key, or ``None`` when nothing had to be installed.
    """
    cmd = runner.install_cmd(deps)
    if not cmd or policy.deps_dir is None:
        return None
    key = policy.deps_dir.name
    if cache.is_ready(policy.deps_dir):
        return f"{key} (cached)"
    # Until --allow-host filtering lands (#26) installs get full network.
    install_policy = Policy(
        script=policy.script,
        scratch=policy.scratch,
        net=NetPolicy.FULL,
        ro_paths=policy.ro_paths,
        binaries=policy.binaries,
        deps_dir=policy.deps_dir,
        deps_writable=True,
        env=policy.env,
        hostname=policy.hostname,
    )
    code = backend.run(install_policy, cmd)
    if code != 0:
        cache.discard(policy.deps_dir)
        raise DepsError(
            f"Installing dependencies failed inside the sandbox (exit {code}).",
            "Check the install output above; `coldrun deps SOURCE` shows what was requested.",
        )
    cache.mark_ready(policy.deps_dir, runner.name, deps)
    return f"{key} (installed)"


def _collect_outputs(scratch: Path, out: Path, script_name: str) -> list[str]:
    """Copy what the script wrote in ``/work`` to ``--out``; return relative names.

    The script itself is bind-mounted read-only into ``/work``, which leaves
    an empty placeholder with its name in the scratch directory; that and the
    pipeline's own metadata are not outputs.
    """

    def is_output(item: Path) -> bool:
        if item.name == _SCRATCH_META:
            return False
        return not (item.name == script_name and item.is_file() and item.stat().st_size == 0)

    wrote = [
        i.name + ("/" if i.is_dir() else "") for i in sorted(scratch.iterdir()) if is_output(i)
    ]
    if not wrote:
        return wrote
    out.mkdir(parents=True, exist_ok=True)
    for item in scratch.iterdir():
        if not is_output(item):
            continue
        target = out / item.name
        if item.is_dir():
            shutil.copytree(item, target, dirs_exist_ok=True, symlinks=True)
        else:
            shutil.copy2(item, target, follow_symlinks=False)
    return wrote


def run(opts: RunOptions, console: Console, services: Services | None = None) -> int:
    """Run the whole pipeline and return the process exit code.

    Errors are rendered as *what failed* and *next* and mapped to the exit
    codes from the spec; the script's own exit code passes through.
    """
    services = services or Services()
    report = Report(net=opts.net.value)
    try:
        code = _run(opts, console, services, report)
    except Exception as exc:
        report.exit_code = exit_code_for(exc)
        render(report, console)
        render_error(exc, console)
        return report.exit_code
    render(report, console)
    return code


def deps(source: str, lang: str | None, console: Console, services: Services | None = None) -> int:
    """``coldrun deps``: fetch, detect and resolve, then report. Never installs or runs."""
    services = services or Services()
    report = Report()
    try:
        fetched = fetch(source)
        report.source = fetched
        report.detection = detect(fetched.path, services.registry, lang)
        report.deps = _resolve(report.detection.runner, fetched.path)
    except Exception as exc:
        report.exit_code = exit_code_for(exc)
        render(report, console)
        render_error(exc, console)
        return report.exit_code
    render(report, console)
    return 0


def _run(opts: RunOptions, console: Console, services: Services, report: Report) -> int:
    fetched = fetch(opts.source)  # 1 fetch
    report.source = fetched
    detection: Detection = detect(fetched.path, services.registry, opts.lang)  # 2 detect
    report.detection = detection
    runner = detection.runner
    deps = _resolve(runner, fetched.path)  # 3 resolve
    report.deps = deps
    findings = list(runner.vet(fetched.path, deps))  # 4 vet (engine lands in M3)
    report.findings = findings
    report.verdict = decide(findings, opts, services, console)  # 5 decide

    backend = choose_backend(opts.backend, services.backends)  # 6 build
    report.backend = backend.name
    scratch = _scratch_for(fetched)
    guest_script = Path(f"{WORKDIR}/{fetched.path.name}")
    argv = runner.run_cmd(guest_script, list(opts.args))
    policy = Policy(
        script=fetched.path,
        scratch=scratch,
        net=opts.net,
        rw_paths=tuple(p.resolve() for p in opts.rw),
        binaries=_host_binaries(runner.install_cmd(deps), argv),
        deps_dir=cache.env_dir(runner.name, deps) if runner.install_cmd(deps) else None,
        tty=opts.is_tty(),
    )
    report.env = _install(backend, policy, runner, deps)
    # 7 run
    code = backend.run(policy, argv)

    report.blocked = default_blocked(opts.net.value)  # 8 report
    report.wrote = _collect_outputs(scratch, opts.out, fetched.path.name)
    report.out_dir = str(opts.out) if report.wrote else None
    report.exit_code = code
    return code
