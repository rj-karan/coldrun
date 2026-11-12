"""Tests for the top-level CLI."""

from __future__ import annotations

from typer.testing import CliRunner

from muzzle import __version__
from muzzle.cli import app

runner = CliRunner()


def test_version_flag_prints_package_version() -> None:
    result = runner.invoke(app, ["--version"])
    assert result.exit_code == 0
    assert result.output.strip() == f"muzzle {__version__}"


def test_short_version_flag() -> None:
    result = runner.invoke(app, ["-V"])
    assert result.exit_code == 0
    assert __version__ in result.output


def test_no_args_shows_help() -> None:
    result = runner.invoke(app, [])
    assert "Fetch, vet and sandbox" in result.output
