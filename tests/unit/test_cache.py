from __future__ import annotations

from pathlib import Path

import pytest
from typer.testing import CliRunner

from coldrun import cache
from coldrun.cli import app
from coldrun.runners.base import DepSet
from coldrun.vet.findings import Finding, Severity


@pytest.fixture(autouse=True)
def _xdg(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path))


def test_key_depends_on_runner_interpreter_and_packages() -> None:
    a = DepSet("pypi", ("requests", "rich"), (), "python3")
    b = DepSet("pypi", ("rich", "requests"), ("jq",), "python3")  # order and binaries irrelevant
    assert cache.env_key("python", a) == cache.env_key("python", b)
    assert len(cache.env_key("python", a)) == 16
    assert cache.env_key("python", a) != cache.env_key("python2", a)
    assert cache.env_key("python", a) != cache.env_key("python", DepSet("pypi", ("requests",)))


def test_lifecycle_list_and_clean(tmp_path: Path) -> None:
    deps = DepSet("pypi", ("requests",), (), "python3")
    d = cache.env_dir("python", deps)
    assert d.parent == tmp_path / "coldrun" / "envs"
    assert not cache.is_ready(d)
    assert cache.list_envs() == []
    (d / "pkg.py").write_text("x" * 2048)
    cache.mark_ready(d, "python", deps)
    assert cache.is_ready(d)
    [env] = cache.list_envs()
    assert env["key"] == d.name and env["runner"] == "python" and env["packages"] == ["requests"]
    assert env["bytes"] >= 2048
    half = cache.env_dir("python", DepSet("pypi", ("other",)))  # never marked ready
    assert [e["key"] for e in cache.list_envs()] == [d.name]
    cache.discard(half)
    assert not half.exists()
    assert cache.clean() == 1
    assert cache.list_envs() == []
    assert cache.clean() == 0


def test_cli_cache_commands(tmp_path: Path) -> None:
    runner = CliRunner()
    res = runner.invoke(app, ["cache", "list"])
    assert res.exit_code == 0 and "no cached environments" in res.output
    deps = DepSet("pypi", ("requests", "rich"), (), "python3")
    cache.mark_ready(cache.env_dir("python", deps), "python", deps)
    res = runner.invoke(app, ["cache", "list"])
    assert res.exit_code == 0 and "python" in res.output and "requests, rich" in res.output
    res = runner.invoke(app, ["cache", "clean"])
    assert res.exit_code == 0 and "removed 1" in res.output


def test_install_hooks_cannot_steer_metadata_writes(tmp_path: Path) -> None:
    # an install hook runs inside the sandbox with the environment directory writable;
    # these symlinks are what it could plant there to make the host write elsewhere
    deps = DepSet("pypi", ('requests; platform_release != "$(touch pwned)"',), (), "python3")
    d = cache.env_dir("python", deps)
    victim = tmp_path / "bashrc"
    victim.write_text("original\n")
    (d / "meta.json").symlink_to(victim)
    (d / ".ready").symlink_to(victim)
    (d / f"{d.name}.json").symlink_to(victim)  # even the new name, should it ever live inside
    assert not cache.is_ready(d)  # a marker planted inside the environment means nothing
    cache.mark_ready(d, "python", deps)
    assert victim.read_text() == "original\n"
    assert cache.is_ready(d)
    [env] = cache.list_envs()
    assert env["packages"] == list(deps.packages)
    assert env["bytes"] < 1024  # symlinks are not followed when sizing


def test_metadata_is_never_written_through_a_symlink(tmp_path: Path) -> None:
    deps = DepSet("pypi", ("rich",), (), "python3")
    d = cache.env_dir("python", deps)
    victim = tmp_path / "profile"
    victim.write_text("original\n")
    (d.parent / f"{d.name}.json").symlink_to(victim)
    cache.mark_ready(d, "python", deps)
    assert victim.read_text() == "original\n"
    assert not (d.parent / f"{d.name}.json").is_symlink()
    cache.discard(d)
    assert not d.exists() and not (d.parent / f"{d.name}.json").exists()


def test_dependency_findings_round_trip() -> None:
    deps = DepSet("pypi", ("requests",), (), "python3")
    d = cache.env_dir("python", deps)
    found = [
        Finding(
            "guarddog.hook", Severity.MEDIUM, Path("requests/setup.py"), "install hook", line=3
        ),
        Finding("source.ip", Severity.LOW, Path("x"), "hardcoded host", host="10.0.0.1"),
    ]
    cache.mark_ready(d, "python", deps, found)
    assert cache.recorded_findings(d) == found
    other = cache.env_dir("python", DepSet("pypi", ("rich",)))
    meta = other.parent / f"{other.name}.json"
    meta.write_text('{"runner": "python", "packages": ["rich"]}')  # written before 1.1
    assert cache.recorded_findings(other) == []
