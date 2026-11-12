from __future__ import annotations

from pathlib import Path

import pytest

from coldrun.fetch import FetchError, UrlFetcher, fetch
from coldrun.fetch.base import MAX_SOURCE_BYTES
from coldrun.fetch.url import filename_for, to_raw
from tests.unit.fetch.conftest import Server


def test_downloads_and_seals(server: Server, qroot: Path) -> None:
    url = server.route("/tools/scan.py", b"import os\n")
    got = fetch(url, root=qroot)
    assert got.kind == "url"
    assert got.path.name == "scan.py"
    assert got.path.read_bytes() == b"import os\n"
    assert (got.quarantine / "source.json").exists()


def test_http_error_names_status_and_hint(server: Server, qroot: Path) -> None:
    url = server.route("/gone", b"", status=404)
    with pytest.raises(FetchError) as exc:
        fetch(url, root=qroot)
    assert "HTTP 404" in exc.value.what
    assert "browser" in exc.value.hint
    assert list(qroot.iterdir()) == []


def test_unreachable_host(qroot: Path) -> None:
    with pytest.raises(FetchError, match="Could not reach"):
        fetch("http://127.0.0.1:9/x.sh", root=qroot)


def test_declared_size_over_limit_is_refused(server: Server, qroot: Path) -> None:
    url = server.route("/big", b"x", headers={"Content-Length": str(MAX_SOURCE_BYTES + 1)})
    with pytest.raises(FetchError, match=r"above the .* byte limit"):
        fetch(url, root=qroot)


def test_streamed_size_over_limit_is_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # A server that lies about Content-Length, or sends none, must still be capped.
    monkeypatch.setattr("coldrun.fetch.url.MAX_SOURCE_BYTES", 10)

    class Chunky:
        def __init__(self) -> None:
            self.left = 64

        def read(self, n: int) -> bytes:
            take = min(n, self.left)
            self.left -= take
            return b"y" * take

    target = tmp_path / "out"
    with pytest.raises(FetchError, match="exceeded the 10 byte limit"):
        UrlFetcher._stream(Chunky(), target, "http://h/x")
    assert not target.exists()


def test_http_redirect_is_followed(server: Server, qroot: Path) -> None:
    final = server.route("/final.sh", b"echo ok\n")
    start = server.route("/start", b"", status=302, headers={"Location": final})
    got = fetch(start, root=qroot)
    assert got.path.read_bytes() == b"echo ok\n"
    assert got.path.name == "start"  # named after what the user asked for


def test_redirect_to_file_scheme_is_refused(server: Server, qroot: Path, tmp_path: Path) -> None:
    secret = tmp_path / "id_rsa"
    secret.write_text("private\n")
    start = server.route("/evil", b"", status=302, headers={"Location": f"file://{secret}"})
    with pytest.raises(FetchError, match=r"Redirect to file:// refused"):
        fetch(start, root=qroot)
    assert list(qroot.iterdir()) == []


def test_redirect_loop_is_capped(server: Server, qroot: Path) -> None:
    loop = server.url("/loop")
    server.route("/loop", b"", status=302, headers={"Location": loop})
    with pytest.raises(FetchError, match="Too many redirects"):
        fetch(loop, root=qroot)


def test_github_blob_url_is_rewritten_to_raw() -> None:
    blob = "https://github.com/o/r/blob/main/dir/script.py"
    assert to_raw(blob) == "https://raw.githubusercontent.com/o/r/main/dir/script.py"
    raw = "https://raw.githubusercontent.com/o/r/main/x.py"
    assert to_raw(raw) == raw
    assert to_raw("https://example.com/blob/main/x") == "https://example.com/blob/main/x"


@pytest.mark.parametrize(
    ("url", "name"),
    [
        ("https://h/a/b/tool.py", "tool.py"),
        ("https://h/a/b/tool.py?x=1#frag", "tool.py"),
        ("https://h/", "script"),
        ("https://h/weird%20name.sh", "weird_name.sh"),
    ],
)
def test_filename_for(url: str, name: str) -> None:
    assert filename_for(url) == name


def test_matches_only_http_schemes() -> None:
    f = UrlFetcher()
    assert f.matches("https://x/y")
    assert f.matches("http://x/y")
    assert not f.matches("ftp://x/y")
    assert not f.matches("/local/path")
