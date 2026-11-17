"""Safe extraction of tar and zip archives into quarantine, and entry selection.

Every member name is checked before anything touches the disk: no absolute
paths, no ``..``, no links that leave the destination, no device or fifo
members, and caps on member count and total size. Files beside the entry
script that would shadow a module it is likely to import are refused, so a
planted ``requests.py`` cannot hijack the real package. Nothing is executed.
"""

from __future__ import annotations

import posixpath
import shutil
import stat
import tarfile
import zipfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import TYPE_CHECKING

from coldrun.detect import read_shebang
from coldrun.fetch.base import FetchError
from coldrun.runners.python import IMPORT_TO_DIST

if TYPE_CHECKING:
    from collections.abc import Iterator

MAX_MEMBERS = 10_000
MAX_EXTRACTED_BYTES = 256 * 1024 * 1024
_CHUNK = 1024 * 1024
_SCRIPT_SUFFIXES = frozenset({".py", ".sh", ".bash", ".zsh", ".pl", ".rb", ".js", ".php", ".ps1"})
# shortcut: a curated list, not every stdlib name, so a repo's own test/ or utils/ still works
_POPULAR = (
    "requests urllib3 numpy pandas scapy pwn yaml bs4 Crypto cryptography paramiko impacket",
    "httpx aiohttp flask django boto3 jwt nmap click rich typer colorama six",
    "os sys socket subprocess json re base64 hashlib urllib http ssl shutil pathlib random",
    "time struct zlib ctypes threading select signal tempfile platform getpass pwd io codecs",
    "logging argparse",
)
_SHADOWED = frozenset(IMPORT_TO_DIST) | frozenset(" ".join(_POPULAR).split())


@dataclass(frozen=True, slots=True)
class Member:
    """One archive entry, normalised for the checks."""

    name: str
    size: int
    kind: str  # file, dir, symlink, hardlink or special
    link: str = ""


def is_archive(path: Path) -> bool:
    """True for zip files and tar files, plain or compressed, judged by their magic bytes."""
    if zipfile.is_zipfile(path):
        return True
    with path.open("rb") as fh:
        head = fh.read(512)
    # tarfile.is_tarfile() also says yes to a run of zero bytes, so look for real magic
    return head.startswith((b"\x1f\x8b", b"\xfd7zXZ\x00", b"BZh")) or head[257:262] == b"ustar"


def unpack(archive: Path, dest: Path, subpath: str = "") -> Path:
    """Extract ``archive`` into ``dest/src`` and return the entry script inside it.

    ``subpath`` is a path inside the archive's single top directory (a GitHub
    ``tree`` URL): a file there is the entry, a directory is where to look.
    """
    tree = dest / "src"
    tree.mkdir()
    try:
        if zipfile.is_zipfile(archive):
            with zipfile.ZipFile(archive) as zf:
                _check(list(_zip_members(zf)), archive)
                _extract_zip(zf, tree)
        else:
            with tarfile.open(archive) as tf:
                _check(list(_tar_members(tf)), archive)
                _extract_tar(tf, tree)
    except (zipfile.BadZipFile, tarfile.TarError, EOFError, OSError) as exc:
        raise FetchError(
            f"{archive.name} is not a readable archive: {exc}.", "Download it again."
        ) from exc
    return pick_entry(tree, subpath)


def pick_entry(tree: Path, subpath: str = "") -> Path:
    """The one script to run: descend lone directories, then expect one script file."""
    here = _descend(tree, subpath) if subpath else tree
    if here.is_file():
        _refuse_planted(here.parent)
        return here
    while True:
        items = sorted(p for p in here.iterdir() if not p.name.startswith("."))
        if len(items) == 1 and items[0].is_dir():
            here = items[0]
            continue
        break
    _refuse_planted(here)
    scripts = [p for p in items if p.is_file() and not p.is_symlink() and _looks_like_script(p)]
    if len(scripts) == 1:
        return scripts[0]
    names = ", ".join(p.name for p in items[:12]) or "nothing"
    if not scripts:
        raise FetchError(
            f"No script found at the top of the archive (it holds: {names}).",
            "Extract it yourself and point coldrun at the script.",
        )
    raise FetchError(
        f"The archive holds several scripts: {', '.join(p.name for p in scripts)}.",
        "Point coldrun at one of them, for GitHub with the file's blob URL.",
    )


def _descend(tree: Path, subpath: str) -> Path:
    """``subpath`` below the archive's single top directory, refusing anything that leaves it."""
    tops = list(tree.iterdir())
    root = tops[0] if len(tops) == 1 and tops[0].is_dir() else tree
    if ".." in PurePosixPath(subpath).parts or PurePosixPath(subpath).is_absolute():
        raise FetchError(f"{subpath} leaves the repository.", "Use a path inside it.")
    here = root / subpath
    if not here.exists() or not here.resolve().is_relative_to(tree.resolve()):
        raise FetchError(f"{subpath} is not in the repository.", "Check the path and the ref.")
    return here


def _looks_like_script(path: Path) -> bool:
    return path.suffix.lower() in _SCRIPT_SUFFIXES or read_shebang(path) is not None


def _refuse_planted(here: Path) -> None:
    for p in here.iterdir():
        name = p.stem if p.is_file() and p.suffix == ".py" else p.name
        if name in _SHADOWED and (p.suffix == ".py" or (p / "__init__.py").is_file()):
            raise FetchError(
                f"The archive plants {p.name} beside the script; it would shadow the real {name}.",
                "This is how a dropper hijacks imports; do not run it.",
            )


def _check(members: list[Member], archive: Path) -> None:
    if len(members) > MAX_MEMBERS:
        raise FetchError(
            f"{archive.name} has {len(members)} members, above the {MAX_MEMBERS} limit.",
            "Extract the one script you need.",
        )
    total = sum(m.size for m in members)
    if total > MAX_EXTRACTED_BYTES:
        raise FetchError(
            f"{archive.name} would extract to {total} bytes; the limit is {MAX_EXTRACTED_BYTES}.",
            "Extract the one script you need.",
        )
    for m in members:
        _check_name(m.name, archive, "member")
        if m.kind == "special":
            raise FetchError(
                f"{archive.name} contains a device or fifo entry: {m.name}.", "Refuse it."
            )
        if m.kind in {"symlink", "hardlink"}:
            target = posixpath.normpath(posixpath.join(posixpath.dirname(m.name), m.link))
            if m.kind == "hardlink":
                target = posixpath.normpath(m.link)
            _check_name(target, archive, f"{m.kind} {m.name} -> {m.link}")


def _check_name(name: str, archive: Path, what: str) -> None:
    pure = PurePosixPath(name.replace("\\", "/"))
    if pure.is_absolute() or ".." in pure.parts or not name or ":" in pure.parts[0]:
        raise FetchError(
            f"{archive.name} has a {what} that escapes the extraction directory: {name}.",
            "Path traversal in an archive is an attack; refuse it.",
        )


def _tar_members(tf: tarfile.TarFile) -> Iterator[Member]:
    for m in tf.getmembers():
        if m.isfile():
            kind = "file"
        elif m.isdir():
            kind = "dir"
        elif m.issym():
            kind = "symlink"
        elif m.islnk():
            kind = "hardlink"
        else:
            kind = "special"
        yield Member(m.name, m.size, kind, m.linkname)


def _zip_members(zf: zipfile.ZipFile) -> Iterator[Member]:
    for info in zf.infolist():
        mode = info.external_attr >> 16
        if info.is_dir():
            kind = "dir"
        elif stat.S_ISLNK(mode):
            kind = "symlink"
        elif stat.S_ISCHR(mode) or stat.S_ISBLK(mode) or stat.S_ISFIFO(mode) or stat.S_ISSOCK(mode):
            kind = "special"
        else:
            kind = "file"
        link = zf.read(info).decode("utf-8", "replace") if kind == "symlink" else ""
        yield Member(info.filename, info.file_size, kind, link)


def _place(tree: Path, name: str) -> Path:
    path = tree / PurePosixPath(name.replace("\\", "/"))
    path.parent.mkdir(parents=True, exist_ok=True)
    return path


def _extract_tar(tf: tarfile.TarFile, tree: Path) -> None:
    for m in tf.getmembers():
        path = _place(tree, m.name)
        if m.isdir():
            path.mkdir(exist_ok=True)
        elif m.isfile():
            src = tf.extractfile(m)
            if src is None:  # pragma: no cover - isfile() guarantees a stream
                continue
            with src, path.open("wb") as dst:
                shutil.copyfileobj(src, dst, _CHUNK)
            path.chmod(0o755 if m.mode & stat.S_IXUSR else 0o644)
        elif m.issym():
            path.symlink_to(m.linkname)
        else:  # hardlink, already checked to stay inside
            (tree / m.linkname).link_to(path) if hasattr(Path, "link_to") else path.hardlink_to(
                tree / m.linkname
            )


def _extract_zip(zf: zipfile.ZipFile, tree: Path) -> None:
    for info in zf.infolist():
        path = _place(tree, info.filename)
        mode = info.external_attr >> 16
        if info.is_dir():
            path.mkdir(exist_ok=True)
        elif stat.S_ISLNK(mode):
            path.symlink_to(zf.read(info).decode("utf-8", "replace"))
        else:
            with zf.open(info) as src, path.open("wb") as dst:
                shutil.copyfileobj(src, dst, _CHUNK)
            path.chmod(0o755 if mode & stat.S_IXUSR else 0o644)
