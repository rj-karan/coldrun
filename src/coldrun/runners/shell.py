"""Minimal POSIX shell runner.

Enough to run a hello-world script inside the sandbox. Command-to-package
mapping and vetting for shell scripts arrive with the Bash runner (#17),
which extends this module.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from coldrun.detect import interpreter_from_shebang, read_shebang
from coldrun.runners.base import DepSet

if TYPE_CHECKING:
    from pathlib import Path

    from coldrun.vet.findings import Finding

_SHELLS = {
    "sh": "/bin/sh",
    "bash": "/bin/bash",
    "dash": "/bin/dash",
    "ksh": "/bin/ksh",
    "zsh": "/bin/zsh",
}
_EXTENSIONS = {".sh": 0.8, ".bash": 0.9}


class ShellRunner:
    """Run ``sh`` and ``bash`` scripts with the interpreter their shebang names."""

    name = "sh"

    def detect(self, path: Path) -> float:
        """A shell shebang is certain; a shell extension alone is likely."""
        shebang = read_shebang(path)
        interp = interpreter_from_shebang(shebang) if shebang else None
        if interp in _SHELLS:
            return 1.0
        if shebang is not None:
            return 0.0  # some other interpreter owns it
        return _EXTENSIONS.get(path.suffix.lower(), 0.0)

    def resolve_deps(self, path: Path) -> DepSet:
        """Only the interpreter for now; command mapping lands in #17."""
        return DepSet(interpreter=self._interpreter(path), source="shebang")

    def install_cmd(self, deps: DepSet) -> list[str]:
        """Nothing to install for plain shell scripts."""
        return []

    def run_cmd(self, path: Path, args: list[str]) -> list[str]:
        """Run with the shebang's shell, falling back to ``/bin/sh``."""
        return [_SHELLS[self._interpreter(path)], str(path), *args]

    def vet(self, path: Path, deps: DepSet) -> list[Finding]:
        """Shell-specific rules arrive with the vetting milestone."""
        return []

    @staticmethod
    def _interpreter(path: Path) -> str:
        shebang = read_shebang(path) if path.exists() else None
        interp = interpreter_from_shebang(shebang) if shebang else None
        return interp if interp in _SHELLS else "sh"
