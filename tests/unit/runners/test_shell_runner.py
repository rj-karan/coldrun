from __future__ import annotations

from pathlib import Path

import pytest

from coldrun.runners.shell import ShellRunner
from tests.unit.runners.contract import RunnerContract

FX = Path(__file__).resolve().parents[2] / "fixtures" / "sh"


class TestShellRunnerContract(RunnerContract):
    runner = ShellRunner()
    fixtures = sorted(FX.glob("*.sh"))


@pytest.mark.parametrize(
    ("content", "suffix", "score"),
    [
        ("#!/bin/sh\necho\n", ".sh", 1.0),
        ("#!/usr/bin/env bash\necho\n", "", 1.0),
        ("#!/usr/bin/env python3\n", ".sh", 0.0),
        ("echo no shebang\n", ".sh", 0.8),
        ("echo no shebang\n", ".bash", 0.9),
        ("echo no shebang\n", ".txt", 0.0),
    ],
)
def test_detect(tmp_path: Path, content: str, suffix: str, score: float) -> None:
    f = tmp_path / f"s{suffix}"
    f.write_text(content)
    assert ShellRunner().detect(f) == score


def test_run_cmd_uses_shebang_shell_and_falls_back(tmp_path: Path) -> None:
    bash = tmp_path / "b.sh"
    bash.write_text("#!/bin/bash\n")
    assert ShellRunner().run_cmd(bash, ["x"]) == ["/bin/bash", str(bash), "x"]
    plain = tmp_path / "p.sh"
    plain.write_text("echo\n")
    assert ShellRunner().run_cmd(plain, []) == ["/bin/sh", str(plain)]
    assert ShellRunner().run_cmd(Path("/work/missing.sh"), []) == ["/bin/sh", "/work/missing.sh"]
    assert ShellRunner().resolve_deps(bash).interpreter == "bash"
    assert ShellRunner().install_cmd(ShellRunner().resolve_deps(bash)) == []
