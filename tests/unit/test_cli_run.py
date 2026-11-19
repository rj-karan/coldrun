from __future__ import annotations

from pathlib import Path

import pytest
from typer.testing import CliRunner

from coldrun import cli, pipeline
from coldrun.sandbox import NetPolicy


def test_run_builds_options_and_passes_script_args(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    captured: dict[str, object] = {}

    def fake_run(opts: pipeline.RunOptions, console: object, services: object = None) -> int:
        captured["opts"] = opts
        return 42

    monkeypatch.setattr(pipeline, "run", fake_run)
    rw = tmp_path / "rw"
    rw.mkdir()
    result = CliRunner().invoke(
        cli.app,
        ["run", "tool.sh", "--net", "full", "--rw", str(rw), "--out", "o", "--lang", "sh",
         "--backend", "bwrap", "--yes", "--force", "--", "--target", "1.2.3.4", "-v"],
    )  # fmt: skip
    assert result.exit_code == 42, result.output
    opts = captured["opts"]
    assert isinstance(opts, pipeline.RunOptions)
    assert opts.source == "tool.sh"
    assert opts.args == ["--target", "1.2.3.4", "-v"]
    assert opts.net is NetPolicy.FULL
    assert opts.rw == [rw]
    assert opts.out == Path("o")
    assert (opts.lang, opts.backend, opts.yes, opts.force) == ("sh", "bwrap", True, True)


def test_deps_command_passes_through(monkeypatch: pytest.MonkeyPatch) -> None:
    seen: dict[str, object] = {}

    def fake(
        source: str,
        lang: str | None,
        console: object,
        services: object = None,
        *,
        as_json: bool = False,
    ) -> int:
        seen.update(source=source, lang=lang)
        return 7

    monkeypatch.setattr(pipeline, "deps", fake)
    result = CliRunner().invoke(cli.app, ["deps", "x.py", "--lang", "python"])
    assert result.exit_code == 7
    assert seen == {"source": "x.py", "lang": "python"}


def test_scan_command_passes_through(monkeypatch: pytest.MonkeyPatch) -> None:
    seen: dict[str, object] = {}

    def fake(
        source: str,
        lang: str | None,
        console: object,
        services: object = None,
        *,
        as_json: bool = False,
    ) -> int:
        seen.update(source=source, lang=lang)
        return 7

    monkeypatch.setattr(pipeline, "scan", fake)
    result = CliRunner().invoke(cli.app, ["scan", "x.py", "--lang", "python"])
    assert result.exit_code == 7
    assert seen == {"source": "x.py", "lang": "python"}


def test_allow_host_implies_net_allow_and_mismatches_are_usage_errors(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    seen: list[pipeline.RunOptions] = []

    def fake_run(opts: pipeline.RunOptions, console: object, services: object = None) -> int:
        seen.append(opts)
        return 0

    monkeypatch.setattr(pipeline, "run", fake_run)
    ok = CliRunner().invoke(
        cli.app, ["run", "t.sh", "--allow-host", "a.b:443", "--allow-host", "c"]
    )
    assert ok.exit_code == 0 and seen[0].net is NetPolicy.ALLOW
    assert seen[0].allow_hosts == ["a.b:443", "c"]
    for args in (["--net", "allow"], ["--net", "full", "--allow-host", "a"]):
        result = CliRunner().invoke(cli.app, ["run", "t.sh", *args])
        assert result.exit_code == 2 and "go together" in result.output


def test_run_help_lists_flags() -> None:
    # CI sets a colour-capable terminal; keep help plain and wide so flags are not wrapped.
    env = {"NO_COLOR": "1", "TERM": "dumb", "COLUMNS": "200"}
    result = CliRunner(env=env).invoke(cli.app, ["run", "--help"])
    assert result.exit_code == 0
    for flag in ("--net", "--rw", "--out", "--backend", "--lang", "--yes", "--force"):
        assert flag in result.output


def test_listen_is_passed_and_refused_with_full_network(monkeypatch: pytest.MonkeyPatch) -> None:
    seen: list[pipeline.RunOptions] = []

    def fake_run(opts: pipeline.RunOptions, console: object, services: object = None) -> int:
        seen.append(opts)
        return 0

    monkeypatch.setattr(pipeline, "run", fake_run)
    assert (
        CliRunner()
        .invoke(cli.app, ["run", "t.sh", "--listen", "4444", "--listen", "10.10.14.5:80"])
        .exit_code
        == 0
    )
    assert seen[0].listen == [("127.0.0.1", 4444), ("10.10.14.5", 80)]
    bad = CliRunner().invoke(cli.app, ["run", "t.sh", "--listen", "target.example:80"])
    assert bad.exit_code == 2 and "IPv4 address" in bad.output
    result = CliRunner().invoke(cli.app, ["run", "t.sh", "--net", "full", "--listen", "1"])
    assert result.exit_code == 2 and "not needed" in result.output
