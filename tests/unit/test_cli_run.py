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


def test_run_rejects_net_allow_for_now() -> None:
    result = CliRunner().invoke(cli.app, ["run", "tool.sh", "--net", "allow"])
    assert result.exit_code == 2
    assert "#26" in result.output


def test_run_help_lists_flags() -> None:
    # CI sets a colour-capable terminal; keep help plain and wide so flags are not wrapped.
    env = {"NO_COLOR": "1", "TERM": "dumb", "COLUMNS": "200"}
    result = CliRunner(env=env).invoke(cli.app, ["run", "--help"])
    assert result.exit_code == 0
    for flag in ("--net", "--rw", "--out", "--backend", "--lang", "--yes", "--force"):
        assert flag in result.output
