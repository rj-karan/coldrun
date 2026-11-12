from __future__ import annotations

import io
from pathlib import Path

import pytest
from rich.console import Console
from typer.testing import CliRunner

from coldrun import doctor
from coldrun.cli import app
from coldrun.doctor import Probes, Status


def probes(tmp_path: Path, **kw: object) -> Probes:
    base: dict[str, object] = {
        "which": lambda name: f"/usr/bin/{name}",
        "version_of": lambda argv: f"{Path(argv[0]).name} 9.9",
        "userns_problem": lambda: None,
        "tiocsti_blocked": lambda: True,
        "python_version": (3, 12),
        "kernel": "7.1.9-arch1-2",
        "cache": tmp_path / "cache",
    }
    base.update(kw)
    return Probes(**base)  # type: ignore[arg-type]


def test_all_green(tmp_path: Path) -> None:
    results = doctor.run_checks(probes(tmp_path))
    assert [r.name for r in results] == [
        "python", "bubblewrap", "user namespaces", "TIOCSTI", "podman", "uv", "cache",
    ]  # fmt: skip
    assert all(r.status is Status.PASS for r in results)
    assert "bwrap 9.9" in results[1].detail
    assert not doctor.has_failures(results)
    assert (tmp_path / "cache").is_dir()


def test_missing_tools_and_broken_userns(tmp_path: Path) -> None:
    missing = {"bwrap", "podman", "uv"}
    results = doctor.run_checks(
        probes(
            tmp_path,
            which=lambda name: None if name in missing else f"/usr/bin/{name}",
            userns_problem=lambda: ("userns off", "sysctl it on"),
            tiocsti_blocked=lambda: False,
            python_version=(3, 9),
        )
    )
    by = {r.name: r for r in results}
    assert by["bubblewrap"].status is Status.FAIL and "pacman" in by["bubblewrap"].fix
    assert (
        by["user namespaces"].status is Status.FAIL and by["user namespaces"].fix == "sysctl it on"
    )
    assert by["TIOCSTI"].status is Status.WARN and "legacy_tiocsti" in by["TIOCSTI"].fix
    assert by["podman"].status is Status.WARN
    assert by["uv"].status is Status.WARN and "astral.sh" in by["uv"].fix
    assert by["python"].status is Status.FAIL and "3.9" in by["python"].detail
    assert doctor.has_failures(results)


def test_version_unknown_when_tool_prints_nothing(tmp_path: Path) -> None:
    results = doctor.run_checks(probes(tmp_path, version_of=lambda argv: None))
    assert "version unknown" in results[1].detail


def test_cache_not_writable(tmp_path: Path) -> None:
    blocker = tmp_path / "file"
    blocker.write_text("x")
    results = doctor.run_checks(probes(tmp_path, cache=blocker / "sub"))
    cache = next(r for r in results if r.name == "cache")
    assert cache.status is Status.FAIL
    assert "chmod" in cache.fix


def test_run_version_probe_handles_missing_and_real_tools() -> None:
    assert doctor._run_version(["/definitely/not/here", "--version"]) is None
    assert doctor._run_version(["true"]) is None  # prints nothing
    out = doctor._run_version(["sh", "-c", "echo tool 1.2"])
    assert out == "tool 1.2"


def test_render_and_exit_status(tmp_path: Path) -> None:
    buf = io.StringIO()
    con = Console(file=buf, color_system=None, width=120, highlight=False)
    results = doctor.run_checks(probes(tmp_path))
    doctor.render(results, con)
    out = buf.getvalue()
    assert "ready to run." in out
    assert "fix:" not in out

    buf = io.StringIO()
    con = Console(file=buf, color_system=None, width=120, highlight=False)
    results = doctor.run_checks(probes(tmp_path, which=lambda name: None))
    doctor.render(results, con)
    out = buf.getvalue()
    assert "fix: sudo pacman -S bubblewrap" in out
    assert "cannot sandbox scripts" in out


def test_cli_doctor_exit_codes(monkeypatch: pytest.MonkeyPatch) -> None:
    mp = monkeypatch
    good = [doctor.CheckResult("x", Status.PASS, "ok")]
    bad = [doctor.CheckResult("x", Status.FAIL, "no", "do this")]
    mp.setattr(doctor, "run_checks", lambda probes=None: good)
    result = CliRunner().invoke(app, ["doctor"])
    assert result.exit_code == 0, result.output
    assert "ready to run" in result.output
    mp.setattr(doctor, "run_checks", lambda probes=None: bad)
    result = CliRunner().invoke(app, ["doctor"])
    assert result.exit_code == 1
    assert "do this" in result.output
