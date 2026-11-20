from __future__ import annotations

import os
from pathlib import Path

import pytest

from coldrun.safefs import tree_size, write_nofollow


def test_write_replaces_a_planted_symlink_instead_of_following_it(tmp_path: Path) -> None:
    victim = tmp_path / "victim"
    victim.write_text("original")
    target = tmp_path / "out"
    target.symlink_to(victim)
    write_nofollow(target, "coldrun data", mode=0o600)
    assert victim.read_text() == "original"
    assert not target.is_symlink() and target.read_text() == "coldrun data"
    assert (target.stat().st_mode & 0o777) == 0o600
    write_nofollow(target, b"bytes too")
    assert target.read_bytes() == b"bytes too"


def test_a_symlink_that_reappears_makes_the_write_fail(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    victim = tmp_path / "victim"
    victim.write_text("original")
    target = tmp_path / "out"
    target.symlink_to(victim)
    monkeypatch.setattr(Path, "unlink", lambda self, missing_ok=False: None)  # lose the race
    with pytest.raises(OSError):
        write_nofollow(target, "x")
    assert victim.read_text() == "original"


def test_tree_size_skips_symlinks(tmp_path: Path) -> None:
    (tmp_path / "d").mkdir()
    (tmp_path / "d" / "a").write_bytes(b"12345")
    big = tmp_path.parent / f"{tmp_path.name}-big"
    big.write_bytes(b"x" * 10_000)
    (tmp_path / "d" / "link").symlink_to(big)
    (tmp_path / "dirlink").symlink_to(tmp_path.parent)
    assert tree_size(tmp_path) == 5
    os.remove(big)  # noqa: PTH107 - plain cleanup
