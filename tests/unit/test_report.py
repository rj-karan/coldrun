from __future__ import annotations

import io
from pathlib import Path

import pytest
from rich.console import Console

from coldrun.detect import Detection, FileKind, Signals
from coldrun.fetch.base import Fetched, FetchError
from coldrun.report import (
    ExitCode,
    Report,
    default_blocked,
    exit_code_for,
    make_console,
    render,
    render_error,
)
from coldrun.runners.base import DepSet
from coldrun.sandbox.base import SandboxError
from coldrun.vet.findings import Finding, Severity
from tests.unit.runners.fake_runner import FakeRunner


def console() -> tuple[Console, io.StringIO]:
    buf = io.StringIO()
    return Console(file=buf, color_system=None, width=100, highlight=False), buf


def fetched(tmp_path: Path) -> Fetched:
    return Fetched(
        "url", "https://x/y.py", tmp_path / "y.py", "ab" * 32, 12, "2026-11-12T00:00:00+00:00"
    )


def detection() -> Detection:
    sig = Signals(FileKind.SCRIPT, "/usr/bin/env python3", "python3", ".py")
    return Detection(FakeRunner(), 0.9, sig, candidates=[("fake", 0.9)])


def test_render_full_report(tmp_path: Path) -> None:
    con, buf = console()
    rep = Report(
        source=fetched(tmp_path),
        detection=detection(),
        deps=DepSet("pypi", ("requests", "rich"), ("curl",), "python>=3.10", "requirements.txt"),
        findings=[
            Finding("CR-1", Severity.LOW, Path("y.py"), "low thing", 3),
            Finding("CR-2", Severity.HIGH, Path("y.py"), "high thing"),
        ],
        verdict="high",
        backend="bwrap",
        net="none",
        blocked=default_blocked("none"),
        exit_code=0,
        out_dir="./coldrun-out",
        wrote=["result.txt"],
    )
    render(rep, con)
    out = buf.getvalue()
    assert "https://x/y.py  (url)" in out
    assert "ab" * 32 in out
    assert "fake  (90%: shebang /usr/bin/env python3, extension .py)" in out
    assert "python>=3.10; pypi: requests, rich; binaries: curl  (from requirements.txt)" in out
    assert out.index("CR-2") < out.index("CR-1")  # high first
    assert "high   CR-2  y.py: high thing" in out
    assert "low    CR-1  y.py:3: low thing" in out
    assert "verdict" in out and "high" in out
    assert "bwrap, network none" in out
    assert "all network access" in out
    assert "result.txt -> ./coldrun-out" in out
    assert "exit code" in out


def test_render_partial_report_after_early_failure(tmp_path: Path) -> None:
    con, buf = console()
    render(Report(source=fetched(tmp_path), exit_code=101), con)
    out = buf.getvalue()
    assert "source" in out
    assert "runner" not in out
    assert "101 (sandbox failed)" in out


def test_render_empty_deps_and_unknown_exit() -> None:
    con, buf = console()
    render(Report(deps=DepSet(), exit_code=7), con)
    out = buf.getvalue()
    assert "dependencies none" in " ".join(out.split())
    assert "exit code 7" in " ".join(out.split())


def test_render_detection_without_reasons() -> None:
    con, buf = console()
    sig = Signals(FileKind.TEXT, None, None, "")
    render(Report(detection=Detection(FakeRunner(), 0.6, sig)), con)
    assert "fake  (60%: runner score)" in buf.getvalue()


def test_max_severity() -> None:
    assert Report().max_severity is None
    rep = Report(
        findings=[
            Finding("a", Severity.LOW, Path("f"), "m"),
            Finding("b", Severity.MEDIUM, Path("f"), "m"),
        ]
    )
    assert rep.max_severity is Severity.MEDIUM


def test_default_blocked_varies_with_network() -> None:
    assert default_blocked("none")[0] == "all network access"
    assert default_blocked("allow")[0].startswith("network except")
    assert (
        not default_blocked("full")[0].startswith("network")
        and "home directory" in default_blocked("full")[0]
    )


def test_render_error_user_facing_and_generic() -> None:
    con, buf = console()
    render_error(FetchError("Thing broke.", "Try this."), con)
    assert buf.getvalue() == "Thing broke.\nnext: Try this.\n"
    con, buf = console()
    render_error(RuntimeError("boom"), con)
    assert "RuntimeError: boom" in buf.getvalue()
    assert "COLDRUN_DEBUG=1" in buf.getvalue()


class DepsError(Exception):
    pass


class RefusedError(Exception):
    pass


@pytest.mark.parametrize(
    ("err", "code"),
    [
        (FetchError("a", "b"), 2),
        (SandboxError("a", "b"), 101),
        (DepsError(), 102),
        (RefusedError(), 100),
        (RuntimeError(), 1),
    ],
)
def test_exit_code_for(err: BaseException, code: int) -> None:
    assert exit_code_for(err) == code


def test_exit_code_enum_values() -> None:
    assert (ExitCode.REFUSED, ExitCode.SANDBOX_FAILED, ExitCode.DEPS_FAILED) == (100, 101, 102)


def test_make_console_variants() -> None:
    plain = make_console(force_plain=True)
    assert plain.color_system is None and plain.width == 100
    rich = make_console(stderr=True)
    assert rich.stderr is True
