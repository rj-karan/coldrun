from __future__ import annotations

from pathlib import Path

import pytest

from coldrun.runners.base import GUEST_DEPS_DIR
from coldrun.runners.python import PythonRunner, _third_party_imports
from tests.unit.runners.contract import RunnerContract

FX = Path(__file__).resolve().parents[2] / "fixtures" / "python"


class TestPythonRunnerContract(RunnerContract):
    runner = PythonRunner()
    fixtures = sorted(FX.glob("*.py"))


@pytest.mark.parametrize(
    ("content", "suffix", "score"),
    [
        ("#!/usr/bin/env python3\n", ".py", 1.0),
        ("#!/usr/bin/python3.12\n", "", 1.0),
        ("#!/usr/bin/env python\n", ".txt", 0.9),  # bare python may be Python 2
        ("#!/bin/bash\n", ".py", 0.0),
        ("print(1)\n", ".py", 0.8),
        ("print(1)\n", ".sh", 0.0),
    ],
)
def test_detect(tmp_path: Path, content: str, suffix: str, score: float) -> None:
    f = tmp_path / f"s{suffix}"
    f.write_text(content)
    assert PythonRunner().detect(f) == score


def test_pep723_block_wins() -> None:
    deps = PythonRunner().resolve_deps(FX / "pep723.py")
    assert deps.packages == ("requests>=2.31", "rich")
    assert (deps.ecosystem, deps.interpreter, deps.source) == ("pypi", "python3", "PEP 723")


def test_requirements_txt_beside_script(tmp_path: Path) -> None:
    (tmp_path / "t.py").write_text("import requests\n")
    (tmp_path / "requirements.txt").write_text(
        "# comment\nhttpx==0.27\n-r other.txt\n\nrich  # inline\n"
    )
    deps = PythonRunner().resolve_deps(tmp_path / "t.py")
    assert deps.packages == ("httpx==0.27", "rich")
    assert deps.source == "requirements.txt"


def test_imports_are_inferred_and_mapped() -> None:
    deps = PythonRunner().resolve_deps(FX / "imports.py")
    assert deps.packages == ("PyYAML", "beautifulsoup4", "requests")
    assert deps.source == "inferred"


def test_inference_skips_stdlib_local_modules_and_syntax_errors(tmp_path: Path) -> None:
    (tmp_path / "helper.py").write_text("")
    (tmp_path / "pkg").mkdir()
    text = (
        "import os, sys\nimport helper\nfrom pkg import x\nfrom . import rel\n"
        "import google.protobuf\nimport Crypto.Cipher\n"
    )
    assert _third_party_imports(text, tmp_path) == ["protobuf", "pycryptodome"]
    assert _third_party_imports("def broken(:\n", tmp_path) == []
    assert PythonRunner().resolve_deps(FX / "hello.py").packages == ()


def test_install_and_run_commands() -> None:
    r = PythonRunner()
    assert r.install_cmd(r.resolve_deps(FX / "hello.py")) == []
    cmd = r.install_cmd(r.resolve_deps(FX / "pep723.py"))
    assert cmd[:3] == ["/usr/bin/env", "UV_CACHE_DIR=/tmp/uv-cache", "uv"]
    assert "--target" in cmd and GUEST_DEPS_DIR in cmd and cmd[-2:] == ["requests>=2.31", "rich"]
    run = r.run_cmd(Path("/work/x.py"), ["-v"])
    assert run == [
        "/usr/bin/env",
        f"PYTHONPATH={GUEST_DEPS_DIR}",
        "PYTHONDONTWRITEBYTECODE=1",
        "/usr/bin/python3",
        "/work/x.py",
        "-v",
    ]
