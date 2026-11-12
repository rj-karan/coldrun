from __future__ import annotations

import json
import os
import stat
from pathlib import Path

import pytest

from coldrun.fetch import FetchError, LocalFetcher, fetch
from coldrun.fetch.base import MAX_SOURCE_BYTES, safe_filename


def test_copies_into_private_quarantine_and_seals(tmp_path: Path, qroot: Path) -> None:
    src = tmp_path / "tool.py"
    src.write_text("print('hi')\n")

    got = fetch(str(src), root=qroot)

    assert got.kind == "file"
    assert got.origin == str(src)
    assert got.path.name == "tool.py"
    assert got.path.read_text() == "print('hi')\n"
    assert got.size == len("print('hi')\n")
    assert len(got.sha256) == 64
    assert got.quarantine.parent == qroot
    assert stat.S_IMODE(qroot.stat().st_mode) == 0o700
    assert stat.S_IMODE(got.quarantine.stat().st_mode) == 0o700
    assert stat.S_IMODE(got.path.stat().st_mode) == 0o400
    meta = json.loads((got.quarantine / "source.json").read_text())
    assert meta["sha256"] == got.sha256
    assert meta["kind"] == "file"
    assert meta["fetched_at"].endswith("+00:00")


def test_each_fetch_gets_its_own_directory(tmp_path: Path, qroot: Path) -> None:
    src = tmp_path / "a.sh"
    src.write_text("echo\n")
    a = fetch(str(src), root=qroot)
    b = fetch(str(src), root=qroot)
    assert a.quarantine != b.quarantine
    assert a.sha256 == b.sha256


def test_tilde_is_expanded(tmp_path: Path, qroot: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("HOME", str(tmp_path))
    (tmp_path / "x.sh").write_text("echo\n")
    assert fetch("~/x.sh", root=qroot).path.name == "x.sh"


def test_missing_path_says_what_to_try(qroot: Path) -> None:
    with pytest.raises(FetchError) as exc:
        fetch("/no/such/script.py", root=qroot)
    assert "does not exist" in exc.value.what
    assert "https://" in exc.value.hint
    assert not qroot.exists() or list(qroot.iterdir()) == []


def test_directory_is_rejected(tmp_path: Path, qroot: Path) -> None:
    with pytest.raises(FetchError, match="is a directory"):
        fetch(str(tmp_path), root=qroot)


def test_special_file_is_rejected(qroot: Path) -> None:
    with pytest.raises(FetchError, match="not a regular file"):
        fetch("/dev/null", root=qroot)


def test_symlink_is_followed_to_its_regular_target(tmp_path: Path, qroot: Path) -> None:
    real = tmp_path / "real.sh"
    real.write_text("echo\n")
    link = tmp_path / "link.sh"
    link.symlink_to(real)
    got = fetch(str(link), root=qroot)
    assert got.path.name == "link.sh"
    assert not got.path.is_symlink()


def test_unreadable_file_reports_permissions(tmp_path: Path, qroot: Path) -> None:
    if os.geteuid() == 0:
        pytest.skip("root can read anything")
    src = tmp_path / "secret.sh"
    src.write_text("echo\n")
    src.chmod(0)
    try:
        with pytest.raises(FetchError, match="Could not read"):
            fetch(str(src), root=qroot)
    finally:
        src.chmod(0o600)


def test_oversized_file_is_rejected_and_cleaned(tmp_path: Path, qroot: Path) -> None:
    big = tmp_path / "big.bin"
    with big.open("wb") as fh:
        fh.truncate(MAX_SOURCE_BYTES + 1)
    with pytest.raises(FetchError, match=r"above the .* byte limit"):
        fetch(str(big), root=qroot)
    assert list(qroot.iterdir()) == []


def test_quarantine_is_removed_when_fetcher_fails(tmp_path: Path, qroot: Path) -> None:
    class Boom:
        kind = "boom"

        def matches(self, spec: str) -> bool:
            return True

        def fetch(self, spec: str, dest: Path) -> Path:
            (dest / "partial").write_text("x")
            msg = "network died"
            raise FetchError(msg, "retry")

    with pytest.raises(FetchError, match="network died"):
        fetch("anything", root=qroot, fetchers=[Boom()])
    assert list(qroot.iterdir()) == []


def test_unknown_scheme_is_refused(qroot: Path) -> None:
    with pytest.raises(FetchError, match="ftp is not supported"):
        fetch("ftp://example.com/x.sh", root=qroot)


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("tool.py", "tool.py"),
        ("../../etc/passwd", "passwd"),
        ("weird name!.sh", "weird_name_.sh"),
        ("...", "script"),
        ("", "script"),
        ("a" * 300 + ".py", "a" * 128),
    ],
)
def test_safe_filename(raw: str, expected: str) -> None:
    assert safe_filename(raw) == expected


def test_local_fetcher_does_not_claim_urls() -> None:
    assert LocalFetcher().matches("./x.py")
    assert not LocalFetcher().matches("https://example.com/x.py")
