"""The eight pipeline steps: fetch, detect, resolve, vet, decide, build, run, report.

Everything the ``run`` command does lives here so the CLI stays logic-free
and the steps can be tested with fake backends and registries.
"""

from __future__ import annotations

import contextlib
import os
import re
import shutil
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING

from coldrun import cache
from coldrun.detect import detect
from coldrun.fetch import fetch
from coldrun.report import (
    ExitCode,
    Report,
    default_blocked,
    emit_json,
    exit_code_for,
    render,
    render_error,
)
from coldrun.runners.registry import Registry, default_registry
from coldrun.runners.shell import package_for
from coldrun.safefs import copy_nofollow
from coldrun.sandbox import BwrapBackend, NetPolicy, PodmanBackend, Policy, SandboxError
from coldrun.vet import engine, guarddog
from coldrun.vet.scoring import score
from coldrun.vet.source import scan_source

if TYPE_CHECKING:
    from collections.abc import Callable, Iterator, Sequence

    from rich.console import Console

    from coldrun.detect import Detection
    from coldrun.fetch.base import Fetched
    from coldrun.runners.base import DepSet, Runner
    from coldrun.sandbox.base import Backend
    from coldrun.vet.findings import Finding

#: Files the pipeline itself keeps in the scratch directory.
_SCRATCH_META = ".coldrun"
#: Where installs may connect. shortcut: an ecosystem missing here gets full network
REGISTRY_HOSTS: dict[str, tuple[str, ...]] = {
    "pypi": ("pypi.org", "files.pythonhosted.org"),
    "npm": ("registry.npmjs.org",),
    "go": ("proxy.golang.org", "sum.golang.org"),
    "rubygems": ("rubygems.org", "index.rubygems.org"),
}
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
    allow_hosts: list[str] = field(default_factory=list)
    listen: list[tuple[str, int]] = field(default_factory=list)
    rw: list[Path] = field(default_factory=list)
    out: Path = Path("./coldrun-out")
    backend: str | None = None
    lang: str | None = None
    yes: bool = False
    force: bool = False
    tty: bool | None = None
    json: bool = False

    def is_tty(self) -> bool:
        """Whether stdin is a terminal, unless overridden."""
        return sys.stdin.isatty() if self.tty is None else self.tty


@dataclass(slots=True)
class Services:
    """Injection points for tests: registry, backends and the confirm prompt."""

    registry: Registry = field(default_factory=default_registry)
    backends: dict[str, Backend] = field(
        default_factory=lambda: {"bwrap": BwrapBackend(), "podman": PodmanBackend()}
    )
    confirm: object = None  # Callable[[str], bool]; None means ask on the terminal
    scan_deps: Callable[[DepSet], list[Finding]] = guarddog.scan_deps
    scan_script: Callable[[Path], list[Finding]] = engine.scan_yara
    scan_source: Callable[[str], list[Finding]] = scan_source


def choose_backend(
    name: str | None, backends: dict[str, Backend], image: str | None = None
) -> Backend:
    """``--backend`` or the first available one that fits: Podman for image runners only."""
    if name is not None:
        if name not in backends:
            known = ", ".join(sorted(backends)) or "none"
            raise SandboxError(
                f"backend {name!r} is not available in this version.", f"Use one of: {known}."
            )
        if image is not None and name != "podman":
            raise SandboxError(
                f"This runner runs in a container image; --backend {name} cannot run it.",
                "Use --backend podman, or leave --backend out.",
            )
        if image is None and name == "podman":
            raise SandboxError(
                "Podman runs the runners that ship an image (Python 2); this one uses the host"
                " toolchain.",
                "Use --backend bwrap, or leave --backend out.",
            )
        backend = backends[name]
        avail = backend.available()
        if not avail.ok:
            raise SandboxError(avail.reason, avail.hint)
        return backend
    reasons: list[str] = []
    for key, backend in backends.items():
        if (key == "podman") != (image is not None):
            continue
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

    Returns the verdict level from :func:`coldrun.vet.scoring.score`.
    """
    verdict = score(findings, opts.allow_hosts).level
    if verdict == "high":
        if not opts.force:
            raise RefusedError(
                "Vetting found high-risk behaviour; refusing to run.",
                "Review the findings above, then rerun with --force if you accept the risk.",
            )
        console.print("[bold red]warning:[/] running despite a high-risk verdict (--force)")
    elif verdict == "medium" and not opts.yes:
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
    absent = [b for b in deps.system_binaries if shutil.which(b) is None]
    missing = sorted({Path(b).name for b in absent})
    if missing:
        hint = install_hint(missing)
        elsewhere = [
            n for n in missing if any(b.startswith("/") for b in absent) and shutil.which(n)
        ]
        if elsewhere:
            hint += (
                f" Your {', '.join(elsewhere)} comes from a version manager in your home"
                " directory, which the sandbox hides; coldrun uses the system one in /usr/bin."
            )
        raise DepsError(
            f"The script needs commands not installed here: {', '.join(missing)}.", hint
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


def _install(
    backend: Backend,
    policy: Policy,
    runner: Runner,
    deps: DepSet,
    dep_findings: Sequence[Finding] = (),
) -> str | None:
    """Install into the cached environment unless it is already there.

    Returns the environment key, or ``None`` when nothing had to be installed.
    """
    cmd = runner.install_cmd(deps)
    if not cmd or policy.deps_dir is None:
        return None
    key = policy.deps_dir.name
    if cache.is_ready(policy.deps_dir):
        return f"{key} (cached)"
    registry_hosts = REGISTRY_HOSTS.get(deps.ecosystem, ())
    # its own /work: install-time code must not leave anything where the script will run
    install_scratch = policy.scratch.parent / "install"
    install_scratch.mkdir(mode=0o700, exist_ok=True)
    install_policy = Policy(
        script=policy.script,
        scratch=install_scratch,
        image=policy.image,
        net=NetPolicy.ALLOW if registry_hosts else NetPolicy.FULL,
        allow_hosts=registry_hosts,
        ro_paths=policy.ro_paths,
        binaries=policy.binaries,
        deps_dir=policy.deps_dir,
        deps_writable=True,
        env=policy.env,
        hostname=policy.hostname,
    )
    with _stdout_to_stderr():  # installer chatter is not the script's output
        code = backend.run(install_policy, cmd)
    if code != 0:
        cache.discard(policy.deps_dir)
        raise DepsError(
            f"Installing dependencies failed inside the sandbox (exit {code}).",
            "Check the install output above; `coldrun deps SOURCE` shows what was requested.",
        )
    cache.mark_ready(policy.deps_dir, runner.name, deps, dep_findings)
    return f"{key} (installed)"


def _collect_outputs(scratch: Path, out: Path, script_name: str) -> list[str]:
    """Copy what the script wrote in ``/work`` to ``--out``; return relative names.

    Only regular files and directories are copied. A symlink is never followed
    or copied, at any depth: a script could leave ``loot -> ../../../../.ssh``
    for the host to copy out. Special files are skipped, and nothing is ever
    written through a symlink already in ``--out``. The script's read-only
    placeholder and the pipeline's own metadata are not outputs.
    """

    def is_output(item: Path) -> bool:
        if item.name == _SCRATCH_META or item.is_symlink():
            return False
        if not (item.is_dir() or item.is_file()):
            return False  # fifos, sockets, devices
        if item.name != script_name:
            return True
        return not ((item.is_file() and item.stat().st_size == 0) or not any(item.iterdir()))

    items = [i for i in sorted(scratch.iterdir()) if is_output(i)]
    links = [i for i in sorted(scratch.iterdir()) if i.is_symlink()]
    wrote = [i.name + ("/" if i.is_dir() else "") for i in items]
    wrote += [f"{i.name} (symlink, not copied)" for i in links]
    if not items:
        return wrote
    out.mkdir(parents=True, exist_ok=True)
    for item in items:
        _copy_out(item, out / item.name)
    return wrote


def _copy_out(src: Path, dst: Path) -> None:
    """Copy a regular file or a directory tree without following any symlink."""
    if src.is_symlink():
        return
    if src.is_file():
        copy_nofollow(src, dst)
        return
    if not src.is_dir():
        return
    if dst.is_symlink() or (dst.exists() and not dst.is_dir()):
        dst.unlink()
    dst.mkdir(exist_ok=True)
    for child in sorted(src.iterdir()):
        _copy_out(child, dst / child.name)


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
        return _finish(report, console, exc, opts.json)
    return _finish(report, console, None, opts.json, code)


def _finish(
    report: Report,
    console: Console,
    error: BaseException | None,
    as_json: bool,
    code: int = 0,
) -> int:
    """Render the report (and the error), emit JSON when asked, return the exit code."""
    if error is not None:
        report.exit_code = code = exit_code_for(error)
    render(report, console)
    if error is not None:
        render_error(error, console)
    if as_json:
        report.exit_code = code  # scan and deps keep the row out of the human report
        emit_json(report, error)
    return code


@contextlib.contextmanager
def _stdout_to_stderr() -> Iterator[None]:
    """Send the script's stdout to stderr so ``--json`` owns stdout."""
    # shortcut: output is not captured into the document; add a "stdout" field if asked
    saved = os.dup(1)
    sys.stdout.flush()
    os.dup2(2, 1)
    try:
        yield
    finally:
        os.dup2(saved, 1)
        os.close(saved)


def deps(
    source: str,
    lang: str | None,
    console: Console,
    services: Services | None = None,
    *,
    as_json: bool = False,
) -> int:
    """``coldrun deps``: fetch, detect and resolve, then report. Never installs or runs."""
    services = services or Services()
    report = Report()
    try:
        fetched = fetch(source)
        report.source = fetched
        report.detection = detect(fetched.path, services.registry, lang)
        report.deps = _resolve(report.detection.runner, fetched.path)
    except Exception as exc:
        return _finish(report, console, exc, as_json)
    return _finish(report, console, None, as_json)


def _vet(
    fetched: Fetched, runner: Runner, deps: DepSet, services: Services, *, deps_too: bool
) -> list[Finding]:
    path = fetched.path
    findings = services.scan_source(fetched.origin) + services.scan_script(path)
    findings += runner.vet(path, deps)
    return findings + services.scan_deps(deps) if deps_too else findings


def scan(
    source: str,
    lang: str | None,
    console: Console,
    services: Services | None = None,
    *,
    as_json: bool = False,
) -> int:
    """``coldrun scan``: fetch, detect, resolve and vet, then report. Never builds or runs.

    Exits 100 when the verdict is high, so ``coldrun scan x && coldrun run x`` works.
    """
    services = services or Services()
    report = Report()
    try:
        fetched = fetch(source)
        report.source = fetched
        report.detection = detect(fetched.path, services.registry, lang)
        runner = report.detection.runner
        report.deps = _resolve(runner, fetched.path)
        report.findings = _vet(fetched, runner, report.deps, services, deps_too=True)
    except Exception as exc:
        return _finish(report, console, exc, as_json)
    report.verdict = score(report.findings).level
    code = ExitCode.REFUSED if report.verdict == "high" else 0
    return _finish(report, console, None, as_json, code)


def _run(opts: RunOptions, console: Console, services: Services, report: Report) -> int:
    fetched = fetch(opts.source)  # 1 fetch
    report.source = fetched
    detection: Detection = detect(fetched.path, services.registry, opts.lang)  # 2 detect
    report.detection = detection
    runner = detection.runner
    deps = _resolve(runner, fetched.path)  # 3 resolve
    report.deps = deps
    deps_dir = cache.env_dir(runner.name, deps) if runner.install_cmd(deps) else None
    # 4 vet: a cached environment replays the dependency findings recorded at install
    if deps_dir is not None and cache.is_ready(deps_dir):
        dep_findings = cache.recorded_findings(deps_dir)
    else:
        dep_findings = services.scan_deps(deps)
    findings = _vet(fetched, runner, deps, services, deps_too=False) + dep_findings
    report.findings = findings
    report.verdict = decide(findings, opts, services, console)  # 5 decide

    image: str | None = getattr(runner, "image", None)
    backend = choose_backend(opts.backend, services.backends, image)  # 6 build
    report.backend = backend.name
    scratch = _scratch_for(fetched)
    policy = Policy(
        script=fetched.path,
        scratch=scratch,
        tree=fetched.tree,
        net=opts.net,
        allow_hosts=tuple(opts.allow_hosts),
        listen=tuple(opts.listen),
        rw_paths=tuple(p.resolve() for p in opts.rw),
        image=image,
        # an image brings its own tools; a host binary would shadow them
        binaries=()
        if image
        else _host_binaries(runner.install_cmd(deps), runner.run_cmd(fetched.path, [])),
        deps_dir=deps_dir,
        tty=opts.is_tty(),
    )
    argv = runner.run_cmd(Path(policy.guest_script), list(opts.args))
    report.env = _install(backend, policy, runner, deps, dep_findings)
    # 7 run
    with _stdout_to_stderr() if opts.json else contextlib.nullcontext():
        code = backend.run(policy, argv)

    report.blocked = default_blocked(opts.net.value, opts.listen)  # 8 report
    mounted = fetched.tree.name if fetched.tree is not None else fetched.path.name
    report.wrote = _collect_outputs(scratch, opts.out, mounted)
    report.out_dir = str(opts.out) if report.wrote else None
    report.exit_code = code
    return code
