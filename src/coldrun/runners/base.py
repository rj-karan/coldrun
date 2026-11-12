"""The contract every language runner implements.

A runner knows how to recognise a script, work out what it needs, and produce
the commands that install those needs and run the script. The commands are
executed by the sandbox, never by the runner itself, and never on the host.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Protocol, runtime_checkable

if TYPE_CHECKING:
    from pathlib import Path

    from coldrun.vet.findings import Finding


@dataclass(frozen=True, slots=True)
class DepSet:
    """Everything a script needs before it can run.

    Attributes:
        ecosystem: Package registry the packages come from, such as ``pypi``
            or ``npm``. Empty when there are no packages.
        packages: Package requirement strings as the ecosystem spells them,
            for example ``requests>=2.31``. Sorted and de-duplicated.
        system_binaries: Command names the script expects on ``PATH``.
        interpreter: Interpreter requirement, such as ``python>=3.10`` or
            ``bash``. ``None`` for prebuilt binaries.
        source: Where the requirements came from, for the report: a manifest
            file name or ``inferred``.
    """

    ecosystem: str = ""
    packages: tuple[str, ...] = ()
    system_binaries: tuple[str, ...] = ()
    interpreter: str | None = None
    source: str = "inferred"

    def __post_init__(self) -> None:
        """Normalise ordering so equal needs compare and hash equal."""
        object.__setattr__(self, "packages", tuple(sorted(set(self.packages))))
        object.__setattr__(self, "system_binaries", tuple(sorted(set(self.system_binaries))))

    @property
    def is_empty(self) -> bool:
        """True when nothing has to be installed."""
        return not self.packages and not self.system_binaries


@runtime_checkable
class Runner(Protocol):
    """What a language plugin provides.

    Runners are discovered through the ``coldrun.runners`` entry-point group.
    Each entry point names a class with a no-argument constructor, or a
    zero-argument factory, that yields an object satisfying this protocol.
    """

    name: str

    def detect(self, path: Path) -> float:
        """Return confidence from 0.0 to 1.0 that this runner owns ``path``.

        Only inspect the bytes; never execute or import the file.
        """
        ...

    def resolve_deps(self, path: Path) -> DepSet:
        """Work out what ``path`` needs, from a manifest or from the code."""
        ...

    def install_cmd(self, deps: DepSet) -> list[str]:
        """Argument list that installs ``deps``. Runs inside the sandbox.

        Return an empty list when nothing has to be installed.
        """
        ...

    def run_cmd(self, path: Path, args: list[str]) -> list[str]:
        """Argument list that runs ``path`` with ``args``. Runs inside the sandbox."""
        ...

    def vet(self, path: Path, deps: DepSet) -> list[Finding]:
        """Language-specific checks on the script and its dependencies."""
        ...


@dataclass(frozen=True, slots=True)
class RunnerInfo:
    """A loaded runner together with where it came from."""

    runner: Runner
    entry_point: str
    distribution: str | None = None
    load_error: str | None = field(default=None, compare=False)
