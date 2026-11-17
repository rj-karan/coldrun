"""Source signals for GitHub origins: repository and owner age, recent force-pushes.

A repository or account created days ago is the usual vehicle for a poisoned
proof of concept, and a force-push rewrites what a reviewer may have read.
Read from the public API, with ``GITHUB_TOKEN`` when set for a higher rate
limit. Failure to check is an info finding, never a block.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import quote

from coldrun.fetch.base import FetchError
from coldrun.fetch.url import get_json
from coldrun.vet.findings import Finding, Severity

API = "https://api.github.com"
NEW_DAYS = 30
_REPO = re.compile(
    r"^https://(?:github\.com|raw\.githubusercontent\.com)/([\w.-]+)/([\w.-]+)"
    r"(?:/(?:tree/|blob/)?([^/]+))?"
)


def scan_source(origin: str) -> list[Finding]:
    """Findings for a new repository or a new owner account; empty for other origins."""
    m = _REPO.match(origin)
    if m is None:
        return []
    owner, repo, url_ref = m.group(1), m.group(2).removesuffix(".git"), m.group(3)
    where = Path(f"{owner}/{repo}")
    try:
        meta = get_json(f"{API}/repos/{owner}/{repo}", auth=True)
        repo_born = meta["created_at"]
        owner_born = get_json(f"{API}/users/{owner}", auth=True)["created_at"]
        # only the branch being fetched matters; a bot rebasing its own branch is noise
        ref = quote(f"refs/heads/{url_ref or meta['default_branch']}", safe="")
        pushes = get_json(
            f"{API}/repos/{owner}/{repo}/activity?activity_type=force_push&ref={ref}&per_page=1",
            auth=True,
        )
    except (FetchError, KeyError, TypeError, IndexError):
        msg = "Could not read the repository and owner age from the GitHub API."
        return [Finding("source.unchecked", Severity.INFO, where, msg)]
    out: list[Finding] = []
    for rule, what, stamp in (
        ("source.new-repo", "repository", repo_born),
        ("source.new-account", "owner account", owner_born),
    ):
        days = _days_since(stamp)
        if days < NEW_DAYS:
            msg = f"The {what} was created {days} days ago; new ones often carry poisoned PoCs."
            out.append(Finding(rule, Severity.MEDIUM, where, msg))
    if pushes and _days_since(pushes[0]["timestamp"]) < NEW_DAYS:
        ref = str(pushes[0].get("ref", "")).removeprefix("refs/heads/")
        days = _days_since(pushes[0]["timestamp"])
        msg = f"Branch {ref} was force-pushed {days} days ago; history was rewritten."
        out.append(Finding("source.force-pushed", Severity.MEDIUM, where, msg))
    return out


def _days_since(stamp: object) -> int:
    when = datetime.fromisoformat(str(stamp).replace("Z", "+00:00"))
    return (datetime.now(timezone.utc) - when).days
