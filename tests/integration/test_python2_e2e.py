"""Python 2 scripts through the real CLI on rootless Podman (CI installs podman)."""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

pytestmark = [
    pytest.mark.e2e,
    pytest.mark.skipif(shutil.which("podman") is None, reason="podman not installed"),
]
FX = Path(__file__).resolve().parents[1] / "fixtures" / "python2"


def coldrun(*args: str, tmp_path: Path) -> subprocess.CompletedProcess[str]:
    env = dict(os.environ, XDG_CACHE_HOME=str(tmp_path / "cache"), NO_COLOR="1", COLUMNS="200")
    return subprocess.run(  # noqa: S603 - our own CLI
        [sys.executable, "-m", "coldrun", *args],
        capture_output=True,
        text=True,
        check=False,
        cwd=tmp_path,
        env=env,
        timeout=600,
    )


def test_python2_hello_runs_in_the_image(tmp_path: Path) -> None:
    res = coldrun("run", str(FX / "hello.py"), tmp_path=tmp_path)
    assert res.returncode == 0, res.stdout + res.stderr
    assert res.stdout == "hello from python 2 urllib2\n"
    assert "sandbox       podman, network none" in res.stderr


def test_python2_installs_through_the_bridge(tmp_path: Path) -> None:
    res = coldrun("run", str(FX / "deps.py"), tmp_path=tmp_path)
    assert res.returncode == 0, res.stdout + res.stderr
    assert res.stdout == "py2 deps ok True\n"
    assert "(installed)" in res.stderr
