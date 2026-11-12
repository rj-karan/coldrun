"""The suite every runner must pass.

Subclass :class:`RunnerContract` in a test module, provide ``runner`` and
``fixtures``, and pytest collects the checks. Runner modules add their own
tests on top; this file holds only what is true for all of them.
"""

from __future__ import annotations

import re
import shlex
from pathlib import Path

import pytest

from coldrun.runners.base import DepSet, Runner
from coldrun.vet.findings import Finding

_SLUG = re.compile(r"^[a-z][a-z0-9-]*$")
_SHELL_META = set(";|&<>`$(){}*?!\n")


class RunnerContract:
    """Shared behaviour. Subclasses set ``runner`` and ``fixtures``."""

    runner: Runner
    fixtures: list[Path]
    unrelated: Path = Path(__file__)  # this .py file is never a runner's own type

    def test_satisfies_protocol(self) -> None:
        assert isinstance(self.runner, Runner)

    def test_name_is_a_slug(self) -> None:
        assert _SLUG.match(self.runner.name), self.runner.name

    def test_detect_is_a_confidence(self) -> None:
        for fx in self.fixtures:
            score = self.runner.detect(fx)
            assert isinstance(score, float)
            assert 0.0 <= score <= 1.0, (fx, score)

    def test_detect_claims_own_fixtures(self) -> None:
        for fx in self.fixtures:
            assert self.runner.detect(fx) > 0.5, fx

    def test_detect_declines_unrelated_file(self) -> None:
        assert self.runner.detect(self.unrelated) < 0.5

    def test_resolve_deps_returns_depset(self) -> None:
        for fx in self.fixtures:
            deps = self.runner.resolve_deps(fx)
            assert isinstance(deps, DepSet)

    def test_commands_are_argument_lists(self) -> None:
        for fx in self.fixtures:
            deps = self.runner.resolve_deps(fx)
            for cmd in (self.runner.install_cmd(deps), self.runner.run_cmd(fx, ["--x", "1"])):
                assert isinstance(cmd, list)
                assert all(isinstance(a, str) for a in cmd)
                # The first element is a program, not a shell one-liner.
                if cmd:
                    assert not (_SHELL_META & set(cmd[0])), cmd[0]
                    assert shlex.split(cmd[0]) == [cmd[0]], cmd[0]

    def test_run_cmd_passes_script_and_args_through(self) -> None:
        for fx in self.fixtures:
            cmd = self.runner.run_cmd(fx, ["--target", "10.0.0.1"])
            assert cmd, "run_cmd must not be empty"
            assert str(fx) in cmd
            assert cmd[-2:] == ["--target", "10.0.0.1"]

    def test_vet_returns_findings(self) -> None:
        for fx in self.fixtures:
            deps = self.runner.resolve_deps(fx)
            findings = self.runner.vet(fx, deps)
            assert isinstance(findings, list)
            assert all(isinstance(f, Finding) for f in findings)

    def test_methods_do_not_mutate_fixture(self) -> None:
        for fx in self.fixtures:
            before = fx.read_bytes()
            deps = self.runner.resolve_deps(fx)
            self.runner.detect(fx)
            self.runner.vet(fx, deps)
            assert fx.read_bytes() == before


@pytest.fixture
def tmp_fixture_copy(tmp_path: Path) -> Path:
    """A scratch directory for runners that need to write beside a fixture."""
    return tmp_path
