"""Fetch a script from a plain http or https URL.

Downloads stream to disk with a size cap. Redirects are followed only to
http or https, never to ``file://`` or anything else that could reach the
host, and the GitHub ``blob`` and gist page forms are rewritten to their raw
equivalents so the user can paste what the browser shows.
"""

from __future__ import annotations

import re
import urllib.error
import urllib.parse
import urllib.request
from typing import TYPE_CHECKING, Any

from coldrun import __version__
from coldrun.fetch.base import MAX_SOURCE_BYTES, FetchError, safe_filename

if TYPE_CHECKING:
    from pathlib import Path

TIMEOUT_SECONDS = 30
MAX_REDIRECTS = 5
_CHUNK = 256 * 1024
_GITHUB_BLOB = re.compile(r"^https://github\.com/([^/]+)/([^/]+)/blob/([^/]+)/(.+)$")
_GITHUB_RAW = re.compile(r"^https://raw\.githubusercontent\.com/([^/]+)/([^/]+)/([^/]+)/(.+)$")


class _SafeRedirects(urllib.request.HTTPRedirectHandler):
    """Refuse redirects that leave http or https, and cap how many we follow.

    The check runs before urllib's own handling so the user sees why the
    fetch stopped instead of a bare ``HTTP 302``.
    """

    def http_error_302(
        self,
        req: urllib.request.Request,
        fp: Any,  # noqa: ANN401 - urllib's own signature
        code: int,
        msg: str,
        headers: Any,  # noqa: ANN401
    ) -> Any:  # noqa: ANN401
        location = headers.get("location") or headers.get("uri") or ""
        newurl = urllib.parse.urljoin(req.full_url, location)
        scheme = urllib.parse.urlsplit(newurl).scheme
        if scheme not in {"http", "https"}:
            raise FetchError(
                f"Redirect to {scheme}:// refused.",
                "Only http and https destinations are followed.",
            )
        hops = sum(getattr(req, "redirect_dict", {}).values())
        if hops >= MAX_REDIRECTS:
            raise FetchError("Too many redirects.", "Fetch the final URL directly.")
        return super().http_error_302(req, fp, code, msg, headers)

    http_error_301 = http_error_303 = http_error_307 = http_error_308 = http_error_302


def to_raw(url: str) -> str:
    """Turn a GitHub ``blob`` page URL into its raw download URL."""
    if m := _GITHUB_BLOB.match(url):
        owner, repo, ref, path = m.groups()
        return f"https://raw.githubusercontent.com/{owner}/{repo}/{ref}/{path}"
    return url


def filename_for(url: str) -> str:
    """Pick the quarantine file name from the URL path."""
    return safe_filename(urllib.parse.unquote(urllib.parse.urlsplit(url).path))


class UrlFetcher:
    """Plain downloads. Repos, gists and exploit-db have their own fetchers."""

    kind = "url"

    def __init__(self, opener: urllib.request.OpenerDirector | None = None) -> None:
        """Use ``opener`` for requests; tests inject one, callers leave it."""
        self._opener = opener or urllib.request.build_opener(_SafeRedirects())

    def matches(self, spec: str) -> bool:
        """Accept http and https only; other schemes are refused by :func:`fetch`."""
        return spec.startswith(("http://", "https://"))

    def fetch(self, spec: str, dest: Path) -> Path:
        """Download ``spec`` into ``dest`` with a size cap and a timeout."""
        url = to_raw(spec)
        target = dest / filename_for(url)
        req = urllib.request.Request(  # noqa: S310 - scheme checked by matches()
            url, headers={"User-Agent": f"coldrun/{__version__}"}
        )
        try:
            with self._opener.open(req, timeout=TIMEOUT_SECONDS) as resp:
                declared = resp.headers.get("Content-Length")
                if declared and int(declared) > MAX_SOURCE_BYTES:
                    raise FetchError(
                        f"{url} is {declared} bytes, above the {MAX_SOURCE_BYTES} byte limit.",
                        "Fetch a smaller artefact.",
                    )
                self._stream(resp, target, url)
        except urllib.error.HTTPError as exc:
            target.unlink(missing_ok=True)
            if 300 <= exc.code < 400:  # noqa: PLR2004 - HTTP redirect class
                # urllib gives up on loops and repeated hops with a 3xx error.
                raise FetchError("Too many redirects.", "Fetch the final URL directly.") from exc
            raise FetchError(
                f"{url} returned HTTP {exc.code}.",
                "Check the URL in a browser; for private repos use a local clone.",
            ) from exc
        except urllib.error.URLError as exc:
            target.unlink(missing_ok=True)
            raise FetchError(
                f"Could not reach {url}: {exc.reason}.",
                "Check the host name and your network, then retry.",
            ) from exc
        except TimeoutError as exc:
            target.unlink(missing_ok=True)
            raise FetchError(f"{url} timed out after {TIMEOUT_SECONDS}s.", "Retry later.") from exc
        return target

    @staticmethod
    def _stream(resp: Any, target: Path, url: str) -> None:  # noqa: ANN401 - http.client response
        written = 0
        with target.open("wb") as out:
            while chunk := resp.read(_CHUNK):
                written += len(chunk)
                if written > MAX_SOURCE_BYTES:
                    out.close()
                    target.unlink(missing_ok=True)
                    raise FetchError(
                        f"{url} exceeded the {MAX_SOURCE_BYTES} byte limit while downloading.",
                        "Fetch a smaller artefact.",
                    )
                out.write(chunk)
