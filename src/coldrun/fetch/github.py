"""GitHub repositories, gists and exploit-db entries.

A repository or ``tree`` URL downloads the ref's tarball and goes through the
same safe extraction as any archive; a ``tree`` subpath picks the directory
or file to run. A gist is read from the API and written file by file. An
exploit-db ID downloads the raw exploit with the file name the site gives it.
Blob and raw URLs stay with :class:`~coldrun.fetch.url.UrlFetcher`.
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

from coldrun.fetch import archive
from coldrun.fetch.base import MAX_SOURCE_BYTES, FetchError, safe_filename
from coldrun.fetch.url import UrlFetcher, get_json

if TYPE_CHECKING:
    from pathlib import Path

#: Base URLs, module level so tests can point them at a local server.
GITHUB = "https://github.com"
GIST_API = "https://api.github.com"
EXPLOIT_DB = "https://www.exploit-db.com"

_REPO = re.compile(
    r"^https://github\.com/([\w.-]+)/([\w.-]+?)(?:\.git)?/?(?:/tree/([^/]+)(?:/(.+?))?)?/?$"
)
_GIST = re.compile(r"^https://gist\.github\.com/(?:[\w-]+/)?([0-9a-f]{5,})/?$")
_EDB = re.compile(
    r"^(?:edb:|https://www\.exploit-db\.com/(?:exploits|raw|download)/)(\d+)/?$", re.IGNORECASE
)


class GithubFetcher:
    """``github.com/OWNER/REPO`` and ``.../tree/REF[/PATH]``."""

    kind = "github"

    def __init__(self, url_fetcher: UrlFetcher | None = None) -> None:
        """Downloads go through ``url_fetcher``: same size cap and redirect rules."""
        self._url = url_fetcher or UrlFetcher()

    def matches(self, spec: str) -> bool:
        """Repository and tree URLs; blob URLs are single files for the URL fetcher."""
        return _REPO.match(spec) is not None

    def fetch(self, spec: str, dest: Path) -> Path:
        """Download the tarball, extract it safely, return the entry script."""
        m = _REPO.match(spec)
        assert m is not None  # noqa: S101 - matches() ran first
        owner, repo, ref, subpath = m.groups()
        # shortcut: a ref with a slash (feature/x) is read as ref "feature" + path "x"; use the SHA
        tarball = self._url.fetch(f"{GITHUB}/{owner}/{repo}/archive/{ref or 'HEAD'}.tar.gz", dest)
        try:
            return archive.unpack(tarball, dest, subpath or "")
        finally:
            tarball.unlink(missing_ok=True)


class GistFetcher:
    """``gist.github.com/[USER/]ID``; raw gist URLs stay with the URL fetcher."""

    kind = "gist"

    def matches(self, spec: str) -> bool:
        """Gist page URLs."""
        return _GIST.match(spec) is not None

    def fetch(self, spec: str, dest: Path) -> Path:
        """Write every file of the gist, then pick the one script among them."""
        m = _GIST.match(spec)
        assert m is not None  # noqa: S101 - matches() ran first
        data = get_json(f"{GIST_API}/gists/{m.group(1)}")
        tree = dest / "src"
        tree.mkdir()
        for name, f in sorted(data.get("files", {}).items()):
            if f.get("truncated"):
                # shortcut: the API inlines up to 1 MB per file; fetch its raw URL for more
                raise FetchError(
                    f"Gist file {name} is too large to read from the API.",
                    f"Fetch its raw URL instead: {f.get('raw_url', '')}",
                )
            content = str(f.get("content", "")).encode()
            if len(content) > MAX_SOURCE_BYTES:
                raise FetchError(f"Gist file {name} is above the size limit.", "Fetch less.")
            (tree / safe_filename(name)).write_bytes(content)
        return archive.pick_entry(tree)


class ExploitDbFetcher:
    """``edb:ID`` or an exploit-db exploit, raw or download URL."""

    kind = "exploitdb"

    def __init__(self, url_fetcher: UrlFetcher | None = None) -> None:
        """Downloads go through ``url_fetcher``."""
        self._url = url_fetcher or UrlFetcher()

    def matches(self, spec: str) -> bool:
        """``edb:12345`` and the site's URL forms."""
        return _EDB.match(spec) is not None

    def fetch(self, spec: str, dest: Path) -> Path:
        """Download the raw exploit; the site names the file, which sets its extension."""
        m = _EDB.match(spec)
        assert m is not None  # noqa: S101 - matches() ran first
        return self._url.fetch(f"{EXPLOIT_DB}/download/{m.group(1)}", dest)
