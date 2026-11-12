from __future__ import annotations

import io
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path

import pytest
from rich.console import Console

from coldrun import pipeline
from coldrun.pipeline import DepsError, RefusedError, RunOptions, Services, choose_backend, decide
from coldrun.runners.base import DepSet, Runner, RunnerInfo
from coldrun.runners.registry import Registry
from coldrun.runners.shell import ShellRunner
from coldrun.sandbox import NetPolicy, Policy, SandboxError
from coldrun.sandbox.base import Availability
from coldrun.vet.findings import Finding, Severity


@dataclass
class FakeBackend:
    name: str = "fake"
    ok: bool = True
    codes: list[int] = field(default_factory=lambda: [0])
    runs: list[tuple[Policy, list[str]]] = field(default_factory=list)
    reason: str = "fake is off"
    hint: str = "turn it on"

    def available(self) -> Availability:
        return Availability(self.ok, self.reason, self.hint)

    def command(self, policy: Policy, argv: Sequence[str]) -> list[str]:
        return list(argv)

    def run(self, policy: Policy, argv: Sequence[str]) -> int:
        self.runs.append((policy, list(argv)))
        (policy.scratch / "out.txt").write_text("made by script\n")
        return self.codes.pop(0) if self.codes else 0


class VettingRunner(ShellRunner):
    """A shell runner whose vet() returns whatever the test wants."""

    name = "vetsh"

    def __init__(
        self, findings: list[Finding] | None = None, install: list[str] | None = None
    ) -> None:
        self.findings = findings or []
        self.install = install or []

    def vet(self, path: Path, deps: DepSet) -> list[Finding]:
        return list(self.findings)

    def install_cmd(self, deps: DepSet) -> list[str]:
        return list(self.install)


def registry(*runners: Runner) -> Registry:
    reg = Registry([])
    reg._loaded = {r.name: RunnerInfo(r, "test") for r in runners}
    return reg


def console() -> tuple[Console, io.StringIO]:
    buf = io.StringIO()
    return Console(file=buf, color_system=None, width=120, highlight=False), buf


@pytest.fixture
def script(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path / "cache"))
    s = tmp_path / "hello.sh"
    s.write_text("#!/bin/sh\necho hi\n")
    return s


def finding(sev: Severity) -> Finding:
    return Finding("T-1", sev, Path("hello.sh"), f"{sev.value} thing")


def test_happy_path_runs_and_collects_outputs(script: Path, tmp_path: Path) -> None:
    backend = FakeBackend(codes=[5])
    con, buf = console()
    opts = RunOptions(source=str(script), args=["--a", "1"], out=tmp_path / "out", tty=False)
    code = pipeline.run(opts, con, Services(registry(ShellRunner()), {"fake": backend}))

    assert code == 5
    policy, argv = backend.runs[0]
    assert argv == ["/bin/sh", "/work/hello.sh", "--a", "1"]
    assert policy.net is NetPolicy.NONE
    assert policy.script.name == "hello.sh"
    assert policy.script.parent.parent == tmp_path / "cache" / "coldrun" / "quarantine"
    assert policy.scratch == policy.script.parent / "scratch"
    assert (tmp_path / "out" / "out.txt").read_text() == "made by script\n"
    out = buf.getvalue()
    assert "runner sh" in " ".join(out.split())
    assert "out.txt -> " in out
    assert "all network access" in out
    assert "exit code 5" in " ".join(out.split())


def test_fetch_error_exit_2_and_partial_report() -> None:
    con, buf = console()
    code = pipeline.run(RunOptions(source="/nope/x.sh", tty=False), con, Services(registry(), {}))
    assert code == 2
    assert "does not exist" in buf.getvalue()
    assert "next:" in buf.getvalue()


def test_detect_error_when_no_runner_claims_it(script: Path) -> None:
    con, buf = console()
    code = pipeline.run(RunOptions(source=str(script), tty=False), con, Services(registry(), {}))
    assert code == 2
    assert "--lang" in buf.getvalue()


def test_resolve_failure_is_exit_102(script: Path) -> None:
    class Broken(ShellRunner):
        name = "broken"

        def resolve_deps(self, path: Path) -> DepSet:
            msg = "manifest unreadable"
            raise ValueError(msg)

    con, buf = console()
    svc = Services(registry(Broken()), {"fake": FakeBackend()})
    code = pipeline.run(RunOptions(source=str(script), lang="broken", tty=False), con, svc)
    assert code == 102
    assert "manifest unreadable" in buf.getvalue()


def test_install_runs_with_network_and_failure_is_102(script: Path, tmp_path: Path) -> None:
    runner = VettingRunner(install=["pip", "install", "x"])
    backend = FakeBackend(codes=[0, 0])
    con, _ = console()
    svc = Services(registry(runner), {"fake": backend})
    code = pipeline.run(RunOptions(source=str(script), out=tmp_path / "o", tty=False), con, svc)
    assert code == 0
    install_policy, install_argv = backend.runs[0]
    assert install_argv == ["pip", "install", "x"]
    assert install_policy.net is NetPolicy.FULL
    assert backend.runs[1][0].net is NetPolicy.NONE

    backend = FakeBackend(codes=[1])
    con, buf = console()
    svc = Services(registry(runner), {"fake": backend})
    code = pipeline.run(RunOptions(source=str(script), tty=False), con, svc)
    assert code == 102
    assert "Installing dependencies failed" in buf.getvalue()
    assert len(backend.runs) == 1


def test_high_refuses_unless_force(script: Path, tmp_path: Path) -> None:
    runner = VettingRunner([finding(Severity.HIGH)])
    con, buf = console()
    svc = Services(registry(runner), {"fake": FakeBackend()})
    code = pipeline.run(RunOptions(source=str(script), tty=False), con, svc)
    assert code == 100
    assert "refusing to run" in buf.getvalue()
    assert "--force" in buf.getvalue()

    backend = FakeBackend()
    con, buf = console()
    svc = Services(registry(runner), {"fake": backend})
    opts = RunOptions(source=str(script), force=True, out=tmp_path / "o", tty=False)
    assert pipeline.run(opts, con, svc) == 0
    assert "warning:" in buf.getvalue()
    assert len(backend.runs) == 1


def test_medium_asks_confirms_or_refuses(script: Path, tmp_path: Path) -> None:
    runner = VettingRunner([finding(Severity.MEDIUM), finding(Severity.INFO)])
    con, buf = console()
    svc = Services(registry(runner), {"fake": FakeBackend()})
    # non-interactive, no --yes
    assert pipeline.run(RunOptions(source=str(script), tty=False), con, svc) == 100
    assert "--yes" in buf.getvalue()
    # --yes
    svc = Services(registry(runner), {"fake": FakeBackend()})
    assert (
        pipeline.run(
            RunOptions(source=str(script), yes=True, out=tmp_path / "o", tty=False), con, svc
        )
        == 0
    )
    # injected prompt says no
    svc = Services(registry(runner), {"fake": FakeBackend()}, confirm=lambda q: False)
    assert pipeline.run(RunOptions(source=str(script), tty=True), con, svc) == 100
    # injected prompt says yes
    svc = Services(registry(runner), {"fake": FakeBackend()}, confirm=lambda q: True)
    assert pipeline.run(RunOptions(source=str(script), tty=True, out=tmp_path / "o"), con, svc) == 0


def test_decide_terminal_prompt(monkeypatch: pytest.MonkeyPatch) -> None:
    con, _ = console()
    opts = RunOptions(source="x", tty=True)
    monkeypatch.setattr(Console, "input", lambda self, prompt: "y")
    assert decide([finding(Severity.MEDIUM)], opts, Services(registry(), {}), con) == "medium"
    monkeypatch.setattr(Console, "input", lambda self, prompt: "")
    with pytest.raises(RefusedError, match="Not running"):
        decide([finding(Severity.MEDIUM)], opts, Services(registry(), {}), con)
    assert decide([], opts, Services(registry(), {}), con) == "low"
    assert decide([finding(Severity.INFO)], opts, Services(registry(), {}), con) == "low"
    assert decide([finding(Severity.LOW)], opts, Services(registry(), {}), con) == "low"


def test_choose_backend() -> None:
    good, bad = FakeBackend(name="good"), FakeBackend(name="bad", ok=False)
    assert choose_backend(None, {"bad": bad, "good": good}) is good
    assert choose_backend("good", {"good": good}) is good
    with pytest.raises(SandboxError, match="fake is off"):
        choose_backend("bad", {"bad": bad})
    with pytest.raises(SandboxError, match="not available in this version") as exc:
        choose_backend("podman", {"good": good})
    assert "Use one of: good" in exc.value.hint
    with pytest.raises(
        SandboxError, match=r"No sandbox backend is usable\. bad: fake is off turn it on"
    ):
        choose_backend(None, {"bad": bad})


def test_sandbox_error_is_101(script: Path) -> None:
    con, buf = console()
    svc = Services(registry(ShellRunner()), {"off": FakeBackend(ok=False)})
    assert pipeline.run(RunOptions(source=str(script), tty=False), con, svc) == 101
    assert "coldrun doctor" in buf.getvalue()


def test_unexpected_exception_is_exit_1(script: Path) -> None:
    class Weird(ShellRunner):
        name = "weird"

        def run_cmd(self, path: Path, args: list[str]) -> list[str]:
            msg = "surprise"
            raise RuntimeError(msg)

    con, buf = console()
    svc = Services(registry(Weird()), {"fake": FakeBackend()})
    assert pipeline.run(RunOptions(source=str(script), lang="weird", tty=False), con, svc) == 1
    assert "RuntimeError: surprise" in buf.getvalue()


def test_rw_paths_are_resolved_and_outputs_copy_dirs(script: Path, tmp_path: Path) -> None:
    class DirBackend(FakeBackend):
        def run(self, policy: Policy, argv: Sequence[str]) -> int:
            (policy.scratch / "sub").mkdir()
            (policy.scratch / "sub" / "a.txt").write_text("a")
            (policy.scratch / ".coldrun").mkdir(exist_ok=True)
            (policy.scratch / ".coldrun" / "passwd").write_text("x")
            (policy.scratch / policy.script.name).touch()  # bwrap's ro-bind placeholder
            self.runs.append((policy, list(argv)))
            return 0

    rw = tmp_path / "rw"
    rw.mkdir()
    backend = DirBackend()
    con, _ = console()
    svc = Services(registry(ShellRunner()), {"d": backend})
    opts = RunOptions(source=str(script), rw=[rw], out=tmp_path / "out", tty=False)
    assert pipeline.run(opts, con, svc) == 0
    assert backend.runs[0][0].rw_paths == (rw.resolve(),)
    assert (tmp_path / "out" / "sub" / "a.txt").read_text() == "a"
    assert not (tmp_path / "out" / ".coldrun").exists()
    assert not (tmp_path / "out" / "hello.sh").exists()
    assert sorted(p.name for p in (tmp_path / "out").iterdir()) == ["sub"]


def test_no_outputs_means_no_out_dir(script: Path, tmp_path: Path) -> None:
    class Quiet(FakeBackend):
        def run(self, policy: Policy, argv: Sequence[str]) -> int:
            return 0

    con, buf = console()
    svc = Services(registry(ShellRunner()), {"q": Quiet()})
    assert (
        pipeline.run(RunOptions(source=str(script), out=tmp_path / "out", tty=False), con, svc) == 0
    )
    assert not (tmp_path / "out").exists()
    assert "wrote" not in buf.getvalue()


def test_run_options_tty_default(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("sys.stdin", io.StringIO())
    assert RunOptions(source="x").is_tty() is False
    assert RunOptions(source="x", tty=True).is_tty() is True


def test_error_classes_carry_exit_codes() -> None:
    assert DepsError("a", "b").exit_code == 102
    assert RefusedError("a", "b").exit_code == 100
