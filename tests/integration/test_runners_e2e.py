"""Node, Go and Ruby fixtures through the real CLI and bubblewrap, with the system toolchains."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

pytestmark = pytest.mark.e2e
FX = Path(__file__).resolve().parents[1] / "fixtures"


def needs(*tools: str) -> pytest.MarkDecorator:
    missing = [t for t in tools if not Path(t).exists()]
    return pytest.mark.skipif(bool(missing), reason=f"system toolchain missing: {missing}")


def coldrun(*args: str, tmp_path: Path) -> subprocess.CompletedProcess[str]:
    env = dict(os.environ, XDG_CACHE_HOME=str(tmp_path / "cache"), NO_COLOR="1", COLUMNS="200")
    return subprocess.run(  # noqa: S603 - our own CLI
        [sys.executable, "-m", "coldrun", *args],
        capture_output=True,
        text=True,
        check=False,
        cwd=tmp_path,
        env=env,
        timeout=300,
    )


@needs("/usr/bin/node")
def test_node_hello(tmp_path: Path) -> None:
    res = coldrun("run", str(FX / "node" / "hello.js"), tmp_path=tmp_path)
    assert res.returncode == 0, res.stdout + res.stderr
    assert res.stdout == "hello from node function function\n"


@needs("/usr/bin/node", "/usr/bin/npm")
def test_node_installs_from_the_registry_only(tmp_path: Path) -> None:
    res = coldrun("run", str(FX / "node" / "deps.js"), tmp_path=tmp_path)
    assert res.returncode == 0, res.stdout + res.stderr
    assert res.stdout == "node deps ok 7200000\n"
    assert "(installed)" in res.stderr
