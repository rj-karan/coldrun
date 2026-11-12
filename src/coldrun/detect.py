"""Pick a runner from shebang, extension and file magic.

The language knowledge lives in the runners: each one scores a file through
``Runner.detect``. This module supplies the cheap, shared signals runners
build on, asks every registered runner, and turns the scores into one choice
or one clear error. Only bytes are inspected; nothing is executed or imported.
"""

from __future__ import annotations

import shlex
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from coldrun.runners.base import Runner
    from coldrun.runners.registry import Registry

#: A runner must be at least this sure before coldrun runs anything.
THRESHOLD = 0.5
_SNIFF_BYTES = 512
_SHEBANG_MAX = 256


class FileKind(str, Enum):
    """Coarse shape of a file, from its first bytes."""

    SCRIPT = "script"  # has a shebang
    TEXT = "text"  # readable text without a shebang
    ELF = "elf"
    PE = "pe"
    MACHO = "macho"
    ZIP = "zip"
    GZIP = "gzip"
    XZ = "xz"
    BZIP2 = "bzip2"
    ZSTD = "zstd"
    BINARY = "binary"  # other non-text
    EMPTY = "empty"


_MAGIC: tuple[tuple[bytes, FileKind], ...] = (
    (b"\x7fELF", FileKind.ELF),
    (b"MZ", FileKind.PE),
    (b"\xcf\xfa\xed\xfe", FileKind.MACHO),
    (b"\xfe\xed\xfa\xcf", FileKind.MACHO),
    (b"\xca\xfe\xba\xbe", FileKind.MACHO),
    (b"PK\x03\x04", FileKind.ZIP),
    (b"\x1f\x8b", FileKind.GZIP),
    (b"\xfd7zXZ\x00", FileKind.XZ),
    (b"BZh", FileKind.BZIP2),
    (b"\x28\xb5\x2f\xfd", FileKind.ZSTD),
)
_TEXT_BYTES = bytes(range(0x20, 0x7F)) + b"\t\n\r\x0b\x0c\x1b"
_ASCII_LIMIT = 0x80
_BINARY_RATIO = 0.1


class DetectError(Exception):
    """No runner could be chosen.

    Args:
        what: Why, in one sentence.
        hint: What the user can do, usually ``--lang``.
        candidates: Runner names and scores that were considered.
    """

    def __init__(self, what: str, hint: str, candidates: list[tuple[str, float]]) -> None:
        """Keep the parts separate for the report."""
        super().__init__(f"{what} {hint}")
        self.what = what
        self.hint = hint
        self.candidates = candidates


@dataclass(frozen=True, slots=True)
class Signals:
    """The shared evidence about one file."""

    kind: FileKind
    shebang: str | None
    interpreter: str | None
    extension: str

    @property
    def is_text(self) -> bool:
        """True for scripts and plain text."""
        return self.kind in {FileKind.SCRIPT, FileKind.TEXT}


@dataclass(frozen=True, slots=True)
class Detection:
    """The chosen runner and why."""

    runner: Runner
    confidence: float
    signals: Signals
    forced: bool = False
    candidates: list[tuple[str, float]] = field(default_factory=list)

    @property
    def reasons(self) -> list[str]:
        """Human-readable evidence for the report."""
        out: list[str] = []
        if self.forced:
            out.append(f"--lang {self.runner.name}")
        if self.signals.shebang:
            out.append(f"shebang {self.signals.shebang}")
        if self.signals.extension:
            out.append(f"extension {self.signals.extension}")
        if not self.signals.is_text:
            out.append(f"magic {self.signals.kind.value}")
        return out


def sniff_kind(path: Path) -> FileKind:
    """Classify a file from its first bytes."""
    with path.open("rb") as fh:
        head = fh.read(_SNIFF_BYTES)
    if not head:
        return FileKind.EMPTY
    for magic, kind in _MAGIC:
        if head.startswith(magic):
            return kind
    if head.startswith(b"#!"):
        return FileKind.SCRIPT
    if b"\x00" in head:
        return FileKind.BINARY
    sample = head.translate(None, _TEXT_BYTES)
    # Allow UTF-8 multibyte sequences; anything with lots of control bytes is binary.
    control = sum(1 for b in sample if b < _ASCII_LIMIT)
    return FileKind.BINARY if control > len(head) * _BINARY_RATIO else FileKind.TEXT


def read_shebang(path: Path) -> str | None:
    """Return the shebang line without ``#!`` and trailing whitespace, or ``None``."""
    with path.open("rb") as fh:
        head = fh.read(_SHEBANG_MAX)
    if not head.startswith(b"#!"):
        return None
    line = head[2:].split(b"\n", 1)[0].strip()
    try:
        return line.decode("utf-8")
    except UnicodeDecodeError:
        return None


def interpreter_from_shebang(shebang: str) -> str | None:
    """Name of the interpreter a shebang asks for, such as ``python3`` or ``bash``.

    Handles ``/usr/bin/env name``, ``/usr/bin/env -S name args`` and plain
    ``/bin/name``. Returns ``None`` for an unparsable line.
    """
    try:
        parts = shlex.split(shebang)
    except ValueError:
        return None
    if not parts:
        return None
    if Path(parts[0]).name == "env":
        rest = [p for p in parts[1:] if not p.startswith("-") and "=" not in p]
        return Path(rest[0]).name if rest else None
    return Path(parts[0]).name


def signals_for(path: Path) -> Signals:
    """Gather the shared evidence for ``path``."""
    kind = sniff_kind(path)
    shebang = read_shebang(path) if kind == FileKind.SCRIPT else None
    return Signals(
        kind=kind,
        shebang=shebang,
        interpreter=interpreter_from_shebang(shebang) if shebang else None,
        extension=path.suffix.lower(),
    )


def detect(path: Path, registry: Registry, lang: str | None = None) -> Detection:
    """Choose the runner for ``path``.

    Args:
        path: The quarantined file.
        registry: Where runners come from.
        lang: ``--lang`` override; skips scoring and takes that runner.

    Raises:
        DetectError: When nothing is confident enough, or ``lang`` is unknown.
    """
    signals = signals_for(path)
    if lang is not None:
        try:
            runner = registry.get(lang)
        except LookupError as exc:
            raise DetectError(
                str(exc) + ".",
                "Pick one of the available runners with --lang.",
                [],
            ) from exc
        return Detection(runner=runner, confidence=1.0, signals=signals, forced=True)

    scored: list[tuple[float, Runner]] = []
    for runner in registry.all():
        score = float(runner.detect(path))
        scored.append((min(max(score, 0.0), 1.0), runner))
    scored.sort(key=lambda s: s[0], reverse=True)
    candidates = [(r.name, s) for s, r in scored]
    if not scored or scored[0][0] < THRESHOLD:
        what = f"Could not tell what kind of script {path.name} is ({signals.kind.value}"
        what += f", shebang {signals.shebang}" if signals.shebang else ""
        what += ")."
        names = ", ".join(registry.names()) or "none installed"
        raise DetectError(what, f"Force a runner with --lang NAME. Available: {names}.", candidates)
    best, runner = scored[0]
    if len(scored) > 1 and scored[1][0] == best:
        tied = ", ".join(r.name for s, r in scored if s == best)
        raise DetectError(
            f"{path.name} matches more than one runner equally ({tied}).",
            "Choose one with --lang NAME.",
            candidates,
        )
    return Detection(runner=runner, confidence=best, signals=signals, candidates=candidates)
