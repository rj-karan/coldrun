"""The man page and completions in packaging/ match the CLI, and completions answer."""

from __future__ import annotations

import importlib.util
import os
import subprocess
import sys
from pathlib import Path
from types import ModuleType

import pytest

GEN = Path(__file__).resolve().parents[2] / "packaging" / "generate.py"


def generator() -> ModuleType:
    spec = importlib.util.spec_from_file_location("generate", GEN)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_committed_files_are_fresh() -> None:
    stale = [p.name for p, text in generator().outputs().items() if p.read_text() != text]
    assert not stale, f"run `uv run python packaging/generate.py`; stale: {stale}"


def test_man_page_covers_every_command_and_flag() -> None:
    page = generator().man_page()
    for command in ("run", "scan", "deps", "doctor", "cache"):
        assert f'.SS "coldrun {command}' in page
    for flag in ("allow\\-host", "listen", "backend", "json", "force", "yes"):
        assert f".B \\-\\-{flag}" in page, flag
    assert ".B coldrun cache clean" in page and ".B 101" in page


@pytest.mark.parametrize(
    ("shell", "env", "want"),
    [
        ("bash", {"COMP_WORDS": "coldrun sc", "COMP_CWORD": "1"}, "scan"),
        ("zsh", {"_TYPER_COMPLETE_ARGS": "coldrun sc"}, '"scan":'),
        (
            "fish",
            {"_TYPER_COMPLETE_ARGS": "coldrun sc", "_TYPER_COMPLETE_FISH_ACTION": "get-args"},
            "scan\t",
        ),
    ],
)
def test_completion_callback_answers(shell: str, env: dict[str, str], want: str) -> None:
    res = subprocess.run(
        [sys.executable, "-m", "coldrun"],
        env=dict(os.environ, _COLDRUN_COMPLETE=f"complete_{shell}", **env),
        capture_output=True,
        text=True,
        check=False,
        timeout=60,
    )
    assert want in res.stdout, res.stdout + res.stderr
