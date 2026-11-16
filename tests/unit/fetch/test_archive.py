"""Synthetic archives: traversal, absolute paths, links out, planted modules, limits."""

from __future__ import annotations

import io
import stat
import tarfile
import zipfile
from pathlib import Path

import pytest

from coldrun.fetch import FetchError, archive, fetch


def tar_with(path: Path, members: list[tuple[str, bytes | None, str]]) -> Path:
    """``(name, data, kind)``; kind is file, dir, symlink:target, hardlink:target or fifo."""
    with tarfile.open(path, "w:gz") as tf:
        for name, data, kind in members:
            info = tarfile.TarInfo(name)
            if kind == "file":
                assert data is not None
                info.size = len(data)
                info.mode = 0o755 if name.endswith(".sh") else 0o644
                tf.addfile(info, io.BytesIO(data))
                continue
            if kind == "dir":
                info.type = tarfile.DIRTYPE
            elif kind.startswith("symlink:"):
                info.type, info.linkname = tarfile.SYMTYPE, kind.split(":", 1)[1]
            elif kind.startswith("hardlink:"):
                info.type, info.linkname = tarfile.LNKTYPE, kind.split(":", 1)[1]
            elif kind == "fifo":
                info.type = tarfile.FIFOTYPE
            tf.addfile(info)
    return path


def zip_with(path: Path, members: dict[str, bytes], links: dict[str, str] | None = None) -> Path:
    with zipfile.ZipFile(path, "w") as zf:
        for name, data in members.items():
            zf.writestr(name, data)
        for name, target in (links or {}).items():
            info = zipfile.ZipInfo(name)
            info.external_attr = (stat.S_IFLNK | 0o777) << 16
            zf.writestr(info, target)
    return path


SCRIPT = b"#!/bin/sh\necho hi\n"


def test_is_archive(tmp_path: Path) -> None:
    assert archive.is_archive(zip_with(tmp_path / "a.zip", {"x.sh": SCRIPT}))
    assert archive.is_archive(tar_with(tmp_path / "a.tgz", [("x.sh", SCRIPT, "file")]))
    plain = tmp_path / "x.sh"
    plain.write_bytes(SCRIPT)
    assert not archive.is_archive(plain)


def test_tar_with_lone_top_dir_yields_entry_and_siblings(tmp_path: Path, qroot: Path) -> None:
    tar_with(
        tmp_path / "tool.tgz",
        [
            ("tool-1.0/", None, "dir"),
            ("tool-1.0/run.sh", SCRIPT, "file"),
            ("tool-1.0/lib/", None, "dir"),
            ("tool-1.0/lib/helper.sh", b"echo helper\n", "file"),
            ("tool-1.0/README", b"docs\n", "file"),
            ("tool-1.0/latest.sh", None, "symlink:run.sh"),
            ("tool-1.0/lib/copy.sh", None, "hardlink:tool-1.0/run.sh"),
        ],
    )
    got = fetch(str(tmp_path / "tool.tgz"), root=qroot)
    assert got.path.name == "run.sh" and got.tree == got.quarantine / "src"
    assert got.path == got.quarantine / "src" / "tool-1.0" / "run.sh"
    assert (
        got.quarantine / "src" / "tool-1.0" / "lib" / "helper.sh"
    ).read_text() == "echo helper\n"
    assert (got.quarantine / "src" / "tool-1.0" / "latest.sh").is_symlink()
    assert (got.quarantine / "src" / "tool-1.0" / "lib" / "copy.sh").read_bytes() == SCRIPT
    assert (got.quarantine / "source.json").exists()
    assert not (got.quarantine / "tool.tgz").exists()  # the archive itself is gone


def test_zip_single_script(tmp_path: Path, qroot: Path) -> None:
    members = {"poc.py": b"print(1)\n", "notes.txt": b"x", "docs/": b"", "docs/a.md": b"# a"}
    got = fetch(str(zip_with(tmp_path / "t.zip", members)), root=qroot)
    assert got.path == got.quarantine / "src" / "poc.py"
    assert (got.quarantine / "src" / "docs" / "a.md").read_text() == "# a"


@pytest.mark.parametrize(
    ("members", "match"),
    [
        ([("../x.sh", SCRIPT, "file")], "escapes"),
        ([("/etc/x.sh", SCRIPT, "file")], "escapes"),
        ([("a/../../x.sh", SCRIPT, "file")], "escapes"),
        ([("x.sh", SCRIPT, "file"), ("out", None, "symlink:../../etc/passwd")], "symlink out"),
        ([("x.sh", SCRIPT, "file"), ("d/out", None, "symlink:../../up")], "symlink d/out"),
        ([("x.sh", SCRIPT, "file"), ("out", None, "hardlink:/etc/passwd")], "hardlink out"),
        ([("x.sh", SCRIPT, "file"), ("pipe", None, "fifo")], "device or fifo"),
        (
            [("x.sh", SCRIPT, "file"), ("requests.py", b"evil\n", "file")],
            "shadow the real requests",
        ),
        ([("x.py", b"1\n", "file"), ("os/__init__.py", b"evil\n", "file")], "shadow the real os"),
    ],
)
def test_bad_tar_members_are_rejected(
    tmp_path: Path, qroot: Path, members: list[tuple[str, bytes | None, str]], match: str
) -> None:
    tar_with(tmp_path / "bad.tgz", members)
    with pytest.raises(FetchError, match=match):
        fetch(str(tmp_path / "bad.tgz"), root=qroot)
    assert not list(qroot.iterdir())  # quarantine cleaned up


def test_bad_zip_members_are_rejected(tmp_path: Path, qroot: Path) -> None:
    fifo = zipfile.ZipInfo("pipe")
    fifo.external_attr = (stat.S_IFIFO | 0o644) << 16
    with zipfile.ZipFile(tmp_path / "f.zip", "w") as zf:
        zf.writestr("x.sh", SCRIPT)
        zf.writestr(fifo, b"")
    with pytest.raises(FetchError, match="device or fifo"):
        fetch(str(tmp_path / "f.zip"), root=qroot)
    with pytest.raises(FetchError, match="escapes"):
        fetch(str(zip_with(tmp_path / "a.zip", {"..\\x.sh": SCRIPT})), root=qroot)
    with pytest.raises(FetchError, match="symlink"):
        fetch(
            str(zip_with(tmp_path / "b.zip", {"x.sh": SCRIPT}, {"l": "../../etc/passwd"})),
            root=qroot,
        )
    inside = zip_with(tmp_path / "c.zip", {"x.sh": SCRIPT}, {"l": "x.sh"})
    got = fetch(str(inside), root=qroot)
    assert (got.quarantine / "src" / "l").is_symlink()  # a link that stays inside is fine


def test_limits(tmp_path: Path, qroot: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(archive, "MAX_MEMBERS", 2)
    tar_with(tmp_path / "many.tgz", [(f"f{i}.txt", b"x", "file") for i in range(3)])
    with pytest.raises(FetchError, match="members, above"):
        fetch(str(tmp_path / "many.tgz"), root=qroot)
    monkeypatch.setattr(archive, "MAX_EXTRACTED_BYTES", 10)
    tar_with(tmp_path / "big.tgz", [("x.sh", b"#!/bin/sh\n" + b"x" * 20, "file")])
    with pytest.raises(FetchError, match="the limit is 10"):
        fetch(str(tmp_path / "big.tgz"), root=qroot)


def test_entry_selection_errors(tmp_path: Path, qroot: Path) -> None:
    with pytest.raises(FetchError, match="No script found") as exc:
        fetch(
            str(zip_with(tmp_path / "none.zip", {"README": b"x", "data.bin": b"\x00"})), root=qroot
        )
    assert "README" in exc.value.what
    with pytest.raises(FetchError, match=r"several scripts: a\.py, b\.sh"):
        fetch(str(zip_with(tmp_path / "two.zip", {"a.py": b"1", "b.sh": SCRIPT})), root=qroot)
    with pytest.raises(FetchError, match="not a readable archive"):
        broken = tmp_path / "x.tgz"
        broken.write_bytes(b"\x1f\x8bgarbage" + b"\x00" * 40)
        (tmp_path / "q").mkdir()
        archive.unpack(broken, tmp_path / "q")
    zeros = tmp_path / "zeros.bin"
    zeros.write_bytes(b"\x00" * 2048)
    assert not archive.is_archive(zeros)  # tarfile.is_tarfile would say yes


def test_shebang_without_extension_counts_as_script(tmp_path: Path, qroot: Path) -> None:
    got = fetch(
        str(zip_with(tmp_path / "s.zip", {"exploit": SCRIPT, "LICENSE": b"MIT"})), root=qroot
    )
    assert got.path.name == "exploit"
