from __future__ import annotations

from pathlib import Path

import pytest
from typer.testing import CliRunner

from coldrun import cache
from coldrun.cli import app
from coldrun.runners.base import DepSet


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
