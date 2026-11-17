from __future__ import annotations

from pathlib import Path

import pytest

from coldrun.runners.base import GUEST_DEPS_DIR
from coldrun.runners.go import GoRunner, _imports
from tests.unit.runners.contract import RunnerContract

FX = Path(__file__).resolve().parents[2] / "fixtures" / "go"


class TestGoRunnerContract(RunnerContract):
    runner = GoRunner()
    fixtures = sorted(FX.glob("*.go"))


@pytest.mark.parametrize(
    ("content", "suffix", "score"),
    [
        ("package main\nfunc main() {}\n", ".go", 0.9),
        ("// x\npackage main\n", ".go", 0.9),
        ("package util\n", ".go", 0.3),
        ("#!/bin/sh\n", ".go", 0.0),
        ("package main\n", ".c", 0.0),
    ],
)
def test_detect(tmp_path: Path, content: str, suffix: str, score: float) -> None:
    f = tmp_path / f"s{suffix}"
    f.write_text(content)
    assert GoRunner().detect(f) == score


def test_third_party_imports_only() -> None:
    src = """package main
import "fmt"
import u "github.com/google/uuid"
import (
\t"os"
\t"net/http"
\tyaml "gopkg.in/yaml.v3"
\t_ "golang.org/x/crypto/ssh"
)
"""
    assert _imports(src) == [
        "github.com/google/uuid",
        "golang.org/x/crypto/ssh",
        "gopkg.in/yaml.v3",
    ]


def test_resolve_install_and_run() -> None:
    r = GoRunner()
    hello = r.resolve_deps(FX / "hello.go")
    assert (hello.packages, hello.system_binaries, hello.ecosystem) == ((), ("/usr/bin/go",), "go")
    assert r.install_cmd(hello) == []
    deps = r.resolve_deps(FX / "deps.go")
    assert deps.packages == ("github.com/google/uuid",)
    cmd = r.install_cmd(deps)
    assert "GOPROXY=https://proxy.golang.org" in cmd
    assert cmd[-2:] == [GUEST_DEPS_DIR, "github.com/google/uuid"]
    run = r.run_cmd(Path("/work/deps.go"), ["-v"])
    assert "GOPROXY=off" in run and run[-2:] == ["/work/deps.go", "-v"]


def test_go_mod_wins(tmp_path: Path) -> None:
    (tmp_path / "go.mod").write_text(
        "module x\n\ngo 1.22\n\nrequire (\n\tgithub.com/a/b v1.2.3\n"
        "\tgolang.org/x/net v0.1.0 // indirect\n)\n"
        "require github.com/c/d v0.0.1\n"
    )
    (tmp_path / "main.go").write_text('package main\nimport "github.com/ignored/x"\n')
    deps = GoRunner().resolve_deps(tmp_path / "main.go")
    assert deps.source == "go.mod"
    assert deps.packages == (
        "github.com/a/b@v1.2.3",
        "github.com/c/d@v0.0.1",
        "golang.org/x/net@v0.1.0",
    )
