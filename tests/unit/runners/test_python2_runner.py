from __future__ import annotations

from pathlib import Path

import pytest

from coldrun.runners.base import GUEST_DEPS_DIR
from coldrun.runners.python import PythonRunner
from coldrun.runners.python2 import IMAGE, Python2Runner
from tests.unit.runners.contract import RunnerContract

FX = Path(__file__).resolve().parents[2] / "fixtures" / "python2"


class TestPython2RunnerContract(RunnerContract):
    runner = Python2Runner()
    fixtures = sorted(FX.glob("*.py"))


@pytest.mark.parametrize(
    ("content", "suffix", "score"),
    [
        ("#!/usr/bin/env python2\nprint(1)\n", "", 1.0),
        ("#!/usr/bin/python2.7\n", ".txt", 1.0),
        ("#!/usr/bin/env python\nprint 'x'\n", "", 0.95),
        ("print 'x'\n", ".py", 0.95),
        ("try:\n    pass\nexcept ValueError, e:\n    pass\n", ".py", 0.95),
        ("import sys\nprint >>sys.stderr, 'x'\n", ".py", 0.95),
        ("print('x')\n", ".py", 0.0),  # valid Python 3
        ("print 'x'\n", ".txt", 0.0),
        ("#!/usr/bin/env python3\nprint 'x'\n", "", 0.0),
        ("def f(:\n", ".py", 0.0),  # broken, but not Python 2
    ],
)
def test_detect(tmp_path: Path, content: str, suffix: str, score: float) -> None:
    f = tmp_path / f"s{suffix}"
    f.write_text(content)
    assert Python2Runner().detect(f) == score


def test_python2_code_beats_python3_and_python3_code_does_not(tmp_path: Path) -> None:
    old = tmp_path / "old.py"
    old.write_text("#!/usr/bin/env python\nprint 'x'\n")
    assert Python2Runner().detect(old) > PythonRunner().detect(old)
    new = tmp_path / "new.py"
    new.write_text("#!/usr/bin/env python\nprint('x')\n")
    assert PythonRunner().detect(new) > Python2Runner().detect(new)


def test_imports_skip_python2_stdlib_and_local_files(tmp_path: Path) -> None:
    (tmp_path / "helper.py").write_text("")
    src = (
        "import urllib2, sys\nimport requests as r, bs4\nfrom Crypto.Cipher import AES\n"
        "from . import sibling\nfrom __future__ import print_function\nimport helper\n"
        "import ConfigParser\nfrom scapy.all import *\n"
    )
    (tmp_path / "x.py").write_text(src)
    deps = Python2Runner().resolve_deps(tmp_path / "x.py")
    assert deps.packages == ("beautifulsoup4", "pycryptodome", "requests", "scapy")
    assert (deps.interpreter, deps.ecosystem, deps.source) == ("python2", "pypi", "inferred")


def test_requirements_and_commands(tmp_path: Path) -> None:
    (tmp_path / "requirements.txt").write_text("six==1.16.0\n")
    (tmp_path / "x.py").write_text("print 'x'\n")
    r = Python2Runner()
    deps = r.resolve_deps(tmp_path / "x.py")
    assert (deps.packages, deps.source, deps.system_binaries) == (
        ("six==1.16.0",),
        "requirements.txt",
        (),
    )
    cmd = r.install_cmd(deps)
    assert cmd[:4] == ["python", "-m", "pip", "install"] and cmd[-3:] == [
        "--target",
        GUEST_DEPS_DIR,
        "six==1.16.0",
    ]
    assert r.install_cmd(r.resolve_deps(FX / "hello.py")) == []
    assert r.run_cmd(Path("/work/x.py"), ["a"])[-3:] == ["python", "/work/x.py", "a"]
    assert r.image == IMAGE and "@sha256:" in IMAGE
