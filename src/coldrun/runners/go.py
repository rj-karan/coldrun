"""Go runner: dependencies from go.mod or the script's imports; modules fetched with go get.

Uses the system Go in ``/usr/bin``. The cached environment holds a tiny module
(``go.mod``, ``go.sum``) and the module cache. To run, the script is copied
with that module into a temporary directory, built, and the binary runs from
``/work`` so its outputs land where coldrun collects them. No network at run
time: ``GOPROXY=off``.
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

from coldrun.runners.base import GUEST_DEPS_DIR, DepSet, detect_by

if TYPE_CHECKING:
    from pathlib import Path

    from coldrun.vet.findings import Finding

GO = "/usr/bin/go"
_ENV = [
    f"GOMODCACHE={GUEST_DEPS_DIR}/mod",
    f"GOPATH={GUEST_DEPS_DIR}/gopath",
    "GOCACHE=/tmp/gocache",
    "GOTOOLCHAIN=local",
    "GOFLAGS=-mod=mod -modcacherw",  # a read-only module cache could not be cleaned up
]
_IMPORT_BLOCK = re.compile(r"^import\s*\((.*?)^\)", re.MULTILINE | re.DOTALL)
_IMPORT_LINE = re.compile(r'^import\s+(?:[\w.]+\s+)?"([^"]+)"', re.MULTILINE)
_QUOTED = re.compile(r'"([^"]+)"')
_REQUIRE = re.compile(r"^\s*(?:require\s+)?([\w.-]+\.[\w.-]+/\S+)\s+(v\S+)", re.MULTILINE)
_INSTALL = (
    'set -e; cd "$1"; shift; '
    f"[ -f go.mod ] || {GO} mod init coldrun.local/script >/dev/null 2>&1; "
    f'{GO} get "$@"'
)
# $0 is the script, the rest are its arguments; build in a temp module, run from /work
_RUN = (
    "set -e; t=$(mktemp -d); d=" + GUEST_DEPS_DIR + "; "
    'if [ -f "$d/go.mod" ]; then cp "$d/go.mod" "$t/"; '
    '[ ! -f "$d/go.sum" ] || cp "$d/go.sum" "$t/"; '
    f'else (cd "$t" && {GO} mod init coldrun.local/script >/dev/null 2>&1); fi; '
    'cp "$0" "$t/main.go"; '
    f'(cd "$t" && {GO} build -o "$t/prog" .); '
    'exec "$t/prog" "$@"'
)


class GoRunner:
    """Detect, resolve, install and run single-file Go programs."""

    name = "go"

    def detect(self, path: Path) -> float:
        """A ``.go`` file with ``package main`` is a program; other Go files are libraries."""
        score = detect_by(path, frozenset({"go"}), {".go": 0.9})
        if score and path.suffix.lower() == ".go":
            head = path.read_text(encoding="utf-8", errors="replace")[:4096]
            return score if re.search(r"^package\s+main\b", head, re.MULTILINE) else 0.3
        return score

    def resolve_deps(self, path: Path) -> DepSet:
        """``go.mod`` beside the script, else every import whose first element has a dot."""
        manifest = path.parent / "go.mod"
        if manifest.is_file():
            pkgs = tuple(f"{mod}@{ver}" for mod, ver in _REQUIRE.findall(manifest.read_text()))
            source = "go.mod"
        else:
            pkgs = tuple(_imports(path.read_text(encoding="utf-8", errors="replace")))
            source = "inferred"
        return DepSet("go", pkgs, (GO,), "go", source)

    def install_cmd(self, deps: DepSet) -> list[str]:
        """``go get`` the modules into the cached environment over GOPROXY only."""
        if not deps.packages:
            return []
        proxy = ["GOPROXY=https://proxy.golang.org", "GOSUMDB=sum.golang.org"]
        return [
            "/usr/bin/env", *_ENV, *proxy,
            "/bin/sh", "-c", _INSTALL, "sh", GUEST_DEPS_DIR, *deps.packages,
        ]  # fmt: skip

    def run_cmd(self, path: Path, args: list[str]) -> list[str]:
        """Build the script against the cached modules, offline, and run it from /work."""
        return ["/usr/bin/env", *_ENV, "GOPROXY=off", "/bin/sh", "-c", _RUN, str(path), *args]

    def vet(self, path: Path, deps: DepSet) -> list[Finding]:
        """The YARA rules read Go source too; nothing Go-specific yet."""
        return []


def _imports(text: str) -> list[str]:
    """Third-party import paths: the first path element has a dot, as module hosts do."""
    paths = _IMPORT_LINE.findall(text)
    for block in _IMPORT_BLOCK.findall(text):
        paths += _QUOTED.findall(block)
    return sorted({p for p in paths if "." in p.split("/")[0]})
