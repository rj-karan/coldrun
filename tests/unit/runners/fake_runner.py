"""A minimal runner used to exercise the registry and the contract suite.

It is also the shape a third-party plugin takes: a class with a no-argument
constructor exposed through the ``coldrun.runners`` entry-point group.
"""

from __future__ import annotations

from pathlib import Path

from coldrun.runners.base import DepSet
from coldrun.vet.findings import Finding, Severity


class FakeRunner:
    """Runs ``.fake`` files with ``/bin/sh`` and reports one info finding."""

    name = "fake"

    def detect(self, path: Path) -> float:
        return 1.0 if path.suffix == ".fake" else 0.0

    def resolve_deps(self, path: Path) -> DepSet:
        return DepSet(ecosystem="", packages=(), system_binaries=("sh",), interpreter="sh")

    def install_cmd(self, deps: DepSet) -> list[str]:
        return []

    def run_cmd(self, path: Path, args: list[str]) -> list[str]:
        return ["/bin/sh", str(path), *args]

    def vet(self, path: Path, deps: DepSet) -> list[Finding]:
        return [Finding("FAKE-001", Severity.INFO, path, "fake runner looked at the file")]


class NamelessRunner(FakeRunner):
    """Violates the contract: empty name."""

    name = ""


class NotARunner:
    """Has none of the methods."""


def factory() -> FakeRunner:
    """Zero-argument factory form of an entry point."""
    return FakeRunner()


def broken() -> FakeRunner:
    """Entry point whose factory raises."""
    msg = "plugin exploded on load"
    raise RuntimeError(msg)


FIXTURE = Path(__file__).resolve().parents[2] / "fixtures" / "sh" / "hello.sh"
