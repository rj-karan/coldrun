from __future__ import annotations

from pathlib import Path

import pytest

from coldrun.runners.base import GUEST_DEPS_DIR
from coldrun.runners.node import NodeRunner, _packages
from tests.unit.runners.contract import RunnerContract

FX = Path(__file__).resolve().parents[2] / "fixtures" / "node"


class TestNodeRunnerContract(RunnerContract):
    runner = NodeRunner()
    fixtures = sorted(p for p in FX.iterdir() if p.suffix in {".js", ".mjs"})


@pytest.mark.parametrize(
    ("content", "suffix", "score"),
    [
        ("#!/usr/bin/env node\n", "", 1.0),
        ("#!/usr/bin/nodejs\n", ".txt", 1.0),
        ("#!/bin/sh\n", ".js", 0.0),
        ("x\n", ".js", 0.8),
        ("x\n", ".mjs", 0.9),
        ("x\n", ".py", 0.0),
    ],
)
def test_detect(tmp_path: Path, content: str, suffix: str, score: float) -> None:
    f = tmp_path / f"s{suffix}"
    f.write_text(content)
    assert NodeRunner().detect(f) == score


def test_packages_from_require_and_import() -> None:
    src = """
    const a = require('axios'); const b = require("@scope/pkg/sub");
    import x from 'lodash/fp'; import "side-effect"; const y = await import('chalk');
    export { z } from "zod";
    const fs = require('fs'); const p = require('node:path'); import c from './local.js';
    const d = require('/abs/mod'); const e = require('child_process');
    """
    assert _packages(src) == ["@scope/pkg", "axios", "chalk", "lodash", "side-effect", "zod"]


def test_resolve_install_and_run() -> None:
    r = NodeRunner()
    hello = r.resolve_deps(FX / "hello.js")
    assert (hello.packages, hello.system_binaries, hello.source) == (
        (),
        ("/usr/bin/node",),
        "inferred",
    )
    assert r.install_cmd(hello) == []
    deps = r.resolve_deps(FX / "deps.js")
    assert deps.packages == ("ms",) and deps.ecosystem == "npm"
    assert set(deps.system_binaries) == {"/usr/bin/node", "/usr/bin/npm"}
    cmd = r.install_cmd(deps)
    assert "--ignore-scripts" in cmd and cmd[-3:] == ["--prefix", GUEST_DEPS_DIR, "ms"]
    run = r.run_cmd(Path("/work/deps.js"), ["a"])
    assert run == [
        "/usr/bin/env",
        f"NODE_PATH={GUEST_DEPS_DIR}/node_modules",
        "/usr/bin/node",
        "/work/deps.js",
        "a",
    ]


def test_package_json_wins(tmp_path: Path) -> None:
    (tmp_path / "package.json").write_text('{"dependencies": {"ms": "^2.1.3", "@a/b": "1.0.0"}}')
    (tmp_path / "x.js").write_text("require('ignored')")
    deps = NodeRunner().resolve_deps(tmp_path / "x.js")
    assert (deps.packages, deps.source) == (("@a/b@1.0.0", "ms@^2.1.3"), "package.json")
    (tmp_path / "package.json").write_text("{}")
    assert NodeRunner().resolve_deps(tmp_path / "x.js").packages == ()
