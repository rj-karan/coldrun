"""GitHub repo and tree URLs, gists and exploit-db, against recorded responses on localhost."""

from __future__ import annotations

import io
import json
import tarfile
from pathlib import Path

import pytest

from coldrun.fetch import (
    ExploitDbFetcher,
    FetchError,
    GistFetcher,
    GithubFetcher,
    fetch,
    github,
    url,
)
from tests.unit.fetch.conftest import Server


@pytest.fixture
def local(server: Server, monkeypatch: pytest.MonkeyPatch) -> Server:
    base = server.url("")
    for name in ("GITHUB", "GIST_API", "EXPLOIT_DB"):
        monkeypatch.setattr(github, name, base)
    return server


def tarball(files: dict[str, bytes], top: str = "repo-0a1b2c3") -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        for name, data in files.items():
            info = tarfile.TarInfo(f"{top}/{name}")
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))
    return buf.getvalue()


REPO = {
    "README.md": b"# tool\n",
    "run.sh": b"#!/bin/sh\necho run\n",
    "tools/scan.py": b"print('scan')\n",
    "tools/notes.txt": b"x\n",
}


@pytest.mark.parametrize(
    ("spec", "ok"),
    [
        ("https://github.com/o/r", True),
        ("https://github.com/o/r.git", True),
        ("https://github.com/o/r/", True),
        ("https://github.com/o/r/tree/main", True),
        ("https://github.com/o/r/tree/v1.2/tools/scan.py", True),
        ("https://github.com/o/r/blob/main/x.py", False),  # single file: the URL fetcher
        ("https://github.com/o", False),
        ("https://gitlab.com/o/r", False),
    ],
)
def test_github_matches(spec: str, ok: bool) -> None:
    assert GithubFetcher().matches(spec) is ok


def test_repo_url_runs_the_top_level_script(local: Server, qroot: Path) -> None:
    local.route(
        "/o/r/archive/HEAD.tar.gz",
        tarball(REPO),
        headers={"Content-Disposition": "attachment; filename=r-HEAD.tar.gz"},
    )
    got = fetch("https://github.com/o/r", root=qroot)
    assert got.kind == "github"
    assert got.path.relative_to(got.quarantine).as_posix() == "src/repo-0a1b2c3/run.sh"
    assert got.tree is not None and (got.tree / "repo-0a1b2c3" / "tools" / "scan.py").exists()
    assert not list(got.quarantine.glob("*.tar.gz"))  # the tarball is gone


def test_tree_url_with_directory_and_file_subpaths(local: Server, qroot: Path) -> None:
    local.route("/o/r/archive/v1.tar.gz", tarball(REPO))
    assert fetch("https://github.com/o/r/tree/v1/tools", root=qroot).path.name == "scan.py"
    got = fetch("https://github.com/o/r/tree/v1/tools/scan.py", root=qroot)
    assert got.path.name == "scan.py" and got.tree is not None


@pytest.mark.parametrize(
    ("path", "match"),
    [("nope", "not in the repository"), ("tools/../../x", "leaves the repository")],
)
def test_bad_subpaths(local: Server, qroot: Path, path: str, match: str) -> None:
    local.route("/o/r/archive/v1.tar.gz", tarball(REPO))
    with pytest.raises(FetchError, match=match):
        fetch(f"https://github.com/o/r/tree/v1/{path}", root=qroot)
    assert not list(qroot.iterdir())


def test_repo_download_failure_is_a_fetch_error(local: Server, qroot: Path) -> None:
    with pytest.raises(FetchError, match="HTTP 404"):
        fetch("https://github.com/o/missing", root=qroot)


def gist(files: dict[str, dict[str, object]]) -> bytes:
    return json.dumps({"files": files}).encode()


def test_gist_writes_files_and_picks_the_script(local: Server, qroot: Path) -> None:
    local.route(
        "/gists/abc123",
        gist({"poc.py": {"content": "print(1)\n"}, "README.md": {"content": "# x"}}),
    )
    got = fetch("https://gist.github.com/someone/abc123", root=qroot)
    assert got.kind == "gist" and got.path.name == "poc.py"
    assert got.path.read_text() == "print(1)\n"
    assert got.tree is not None and (got.tree / "README.md").exists()
    assert GistFetcher().matches("https://gist.github.com/abc123")
    assert not GistFetcher().matches("https://gist.githubusercontent.com/u/abc123/raw/x.py")


def test_gist_size_problems(local: Server, qroot: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    local.route("/gists/abc1234", gist({"big.py": {"truncated": True, "raw_url": "https://x/raw"}}))
    with pytest.raises(FetchError, match="too large") as exc:
        fetch("https://gist.github.com/abc1234", root=qroot)
    assert "https://x/raw" in exc.value.hint
    monkeypatch.setattr(github, "MAX_SOURCE_BYTES", 3)
    local.route("/gists/abc12345", gist({"a.py": {"content": "print(1)"}}))
    with pytest.raises(FetchError, match="above the size limit"):
        fetch("https://gist.github.com/abc12345", root=qroot)


@pytest.mark.parametrize(
    ("spec", "ok"),
    [
        ("edb:12345", True),
        ("EDB:1", True),
        ("https://www.exploit-db.com/exploits/12345", True),
        ("https://www.exploit-db.com/raw/12345/", True),
        ("https://www.exploit-db.com/download/12345", True),
        ("edb:abc", False),
        ("https://www.exploit-db.com/search", False),
    ],
)
def test_exploitdb_matches(spec: str, ok: bool) -> None:
    assert ExploitDbFetcher().matches(spec) is ok


def test_exploitdb_uses_the_name_the_site_gives(local: Server, qroot: Path) -> None:
    local.route(
        "/download/12345",
        b"#!/usr/bin/env python3\nprint('poc')\n",
        headers={"Content-Disposition": 'attachment; filename="12345.py"'},
    )
    got = fetch("edb:12345", root=qroot)
    assert got.kind == "exploitdb" and got.path.name == "12345.py"
    assert got.tree is None  # a lone file, not a tree


def test_get_json_errors_and_token(server: Server, monkeypatch: pytest.MonkeyPatch) -> None:
    with pytest.raises(FetchError, match="HTTP 404"):
        url.get_json(server.url("/none"))
    server.route("/html", b"<html>")
    with pytest.raises(FetchError, match="did not return JSON"):
        url.get_json(server.url("/html"))
    server.route("/ok", b'{"a": 1}')
    monkeypatch.setenv("GITHUB_TOKEN", "t0ken")
    assert url.get_json(server.url("/ok"), auth=True) == {"a": 1}
    assert server.last_headers.get("Authorization") == "Bearer t0ken"
    assert url.get_json(server.url("/ok")) == {"a": 1}
    assert "Authorization" not in server.last_headers  # only when asked
    monkeypatch.setattr(url, "MAX_SOURCE_BYTES", 3)
    with pytest.raises(FetchError, match="more than 3 bytes"):
        url.get_json(server.url("/ok"))
    with pytest.raises(FetchError, match="Could not reach"):
        url.get_json("http://127.0.0.1:9/nothing")
