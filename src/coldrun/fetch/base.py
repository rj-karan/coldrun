"""Shared pieces of the fetch step: errors, the fetched-source record and the quarantine.

A quarantine directory holds exactly one fetched source plus a ``source.json``
describing where it came from. It is created mode 0700 and nothing in it is
ever imported or executed by the host.
"""

from __future__ import annotations

import hashlib
import json
import re
import stat
import tempfile
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Protocol

#: Largest script or archive coldrun will fetch, in bytes.
MAX_SOURCE_BYTES = 64 * 1024 * 1024
_FILENAME_OK = re.compile(r"[^A-Za-z0-9._+-]+")
_HASH_PREFIX = 16


class FetchError(Exception):
    """A source could not be fetched.

    Args:
        what: What failed, in one sentence.
        hint: The next command or action the user should try.
    """

    def __init__(self, what: str, hint: str) -> None:
        """Keep both halves so the report can show them separately."""
        super().__init__(f"{what} {hint}".strip())
        self.what = what
        self.hint = hint


@dataclass(frozen=True, slots=True)
class Fetched:
    """A source that now sits in quarantine.

    Attributes:
        kind: Fetcher that produced it, such as ``file`` or ``url``.
        origin: The spec as the user gave it.
        path: The quarantined file.
        sha256: Hex digest of the file contents.
        size: Size in bytes.
        fetched_at: UTC timestamp in ISO 8601.
    """

    kind: str
    origin: str
    path: Path
    sha256: str
    size: int
    fetched_at: str

    @property
    def quarantine(self) -> Path:
        """The directory holding the file and its ``source.json``."""
        return self.path.parent

    def to_json(self) -> str:
        """Serialise for ``source.json``."""
        data = asdict(self)
        data["path"] = str(self.path)
        return json.dumps(data, indent=2, sort_keys=True) + "\n"


class Fetcher(Protocol):
    """One way of obtaining a source."""

    kind: str

    def matches(self, spec: str) -> bool:
        """True when this fetcher understands ``spec``."""
        ...

    def fetch(self, spec: str, dest: Path) -> Path:
        """Place the source inside ``dest`` and return the file path.

        ``dest`` already exists, is empty and is private to this fetch.
        Raise :class:`FetchError` on any failure.
        """
        ...


def safe_filename(name: str, default: str = "script") -> str:
    """Reduce an arbitrary name to something safe to create in quarantine."""
    base = Path(name).name
    cleaned = _FILENAME_OK.sub("_", base).strip("._")
    if not cleaned or cleaned in {".", ".."}:
        return default
    return cleaned[:128]


def sha256_of(path: Path) -> str:
    """Hex SHA-256 of a file, streamed."""
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def new_quarantine(root: Path) -> Path:
    """Create a fresh private directory under ``root`` and return it."""
    root.mkdir(parents=True, exist_ok=True)
    root.chmod(stat.S_IRWXU)
    path = Path(tempfile.mkdtemp(prefix="q-", dir=root))
    path.chmod(stat.S_IRWXU)
    return path


def seal(kind: str, origin: str, file: Path) -> Fetched:
    """Hash the fetched file, make it read-only and write ``source.json``."""
    size = file.stat().st_size
    if size > MAX_SOURCE_BYTES:
        file.unlink()
        raise FetchError(
            f"{origin} is {size} bytes, above the {MAX_SOURCE_BYTES} byte limit.",
            "Fetch a smaller artefact or extract the one script you need.",
        )
    file.chmod(stat.S_IRUSR)
    record = Fetched(
        kind=kind,
        origin=origin,
        path=file,
        sha256=sha256_of(file),
        size=size,
        fetched_at=datetime.now(timezone.utc).isoformat(timespec="seconds"),
    )
    (file.parent / "source.json").write_text(record.to_json())
    return record
