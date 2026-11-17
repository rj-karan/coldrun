"""Fetchers that place a source into a quarantine directory without executing it.

:func:`fetch` is the only entry point the pipeline uses. It picks the first
fetcher whose :meth:`Fetcher.matches` accepts the spec, gives it a fresh
quarantine directory, then seals the result with a hash and ``source.json``.
"""

from __future__ import annotations

import shutil
import urllib.parse
from typing import TYPE_CHECKING

from coldrun.config import quarantine_root
from coldrun.fetch import archive
from coldrun.fetch.base import (
    MAX_SOURCE_BYTES,
    Fetched,
    Fetcher,
    FetchError,
    new_quarantine,
    seal,
)
from coldrun.fetch.github import ExploitDbFetcher, GistFetcher, GithubFetcher
from coldrun.fetch.local import LocalFetcher
from coldrun.fetch.url import UrlFetcher

if TYPE_CHECKING:
    from collections.abc import Sequence
    from pathlib import Path

__all__ = [
    "MAX_SOURCE_BYTES",
    "ExploitDbFetcher",
    "FetchError",
    "Fetched",
    "Fetcher",
    "GistFetcher",
    "GithubFetcher",
    "LocalFetcher",
    "UrlFetcher",
    "default_fetchers",
    "fetch",
]


def default_fetchers() -> list[Fetcher]:
    """Fetchers in the order they are tried. URL forms first, paths last."""
    return [GithubFetcher(), GistFetcher(), ExploitDbFetcher(), UrlFetcher(), LocalFetcher()]


def _pick(spec: str, fetchers: Sequence[Fetcher]) -> Fetcher:
    for f in fetchers:
        if f.matches(spec):
            return f
    scheme = urllib.parse.urlsplit(spec).scheme or "that"
    raise FetchError(
        f"No fetcher understands {spec!r} ({scheme} is not supported).",
        "Use a local path or archive, an http(s) URL, a GitHub repo or gist, or edb:ID.",
    )


def fetch(
    spec: str, root: Path | None = None, fetchers: Sequence[Fetcher] | None = None
) -> Fetched:
    """Fetch ``spec`` into a new quarantine directory.

    Args:
        spec: Local path or URL as the user typed it.
        root: Parent for quarantine directories; defaults to the cache.
        fetchers: Override the fetcher list; tests use this.

    Returns:
        The sealed :class:`Fetched` record.

    Raises:
        FetchError: With what failed and what to try next. The quarantine
            directory is removed on failure.
    """
    fetcher = _pick(spec, fetchers if fetchers is not None else default_fetchers())
    qdir = new_quarantine(root if root is not None else quarantine_root())
    try:
        file = fetcher.fetch(spec, qdir)
        if archive.is_archive(file):
            entry = archive.unpack(file, qdir)
            file.unlink()
            file = entry
        # repos, gists and archives leave a tree in src/ that the script runs beside
        root = qdir if file.is_relative_to(qdir / "src") else None
        return seal(fetcher.kind, spec, file, root=root)
    except BaseException:
        shutil.rmtree(qdir, ignore_errors=True)
        raise
