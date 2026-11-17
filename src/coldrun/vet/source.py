"""Source signals for GitHub origins: how old the repository and its owner are.

A repository or account created days ago is the usual vehicle for a poisoned
proof of concept. Read from the public API, with ``GITHUB_TOKEN`` when set
for a higher rate limit. Failure to check is an info finding, never a block.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from pathlib import Path

from coldrun.fetch.base import FetchError
from coldrun.fetch.url import get_json
from coldrun.vet.findings import Finding, Severity

API = "https://api.github.com"
NEW_DAYS = 30
_REPO = re.compile(r"^https://(?:github\.com|raw\.githubusercontent\.com)/([\w.-]+)/([\w.-]+)")
# shortcut: recent force-pushes are not detected; the events API does not say "forced" (#91)


def scan_source(origin: str) -> list[Finding]:
    """Findings for a new repository or a new owner account; empty for other origins."""
    m = _REPO.match(origin)
    if m is None:
        return []
    owner, repo = m.group(1), m.group(2).removesuffix(".git")
    where = Path(f"{owner}/{repo}")
    try:
        repo_born = get_json(f"{API}/repos/{owner}/{repo}", auth=True)["created_at"]
        owner_born = get_json(f"{API}/users/{owner}", auth=True)["created_at"]
    except (FetchError, KeyError, TypeError):
        msg = "Could not read the repository and owner age from the GitHub API."
        return [Finding("source.unchecked", Severity.INFO, where, msg)]
    out: list[Finding] = []
    for rule, what, stamp in (
        ("source.new-repo", "repository", repo_born),
        ("source.new-account", "owner account", owner_born),
    ):
        when = datetime.fromisoformat(str(stamp).replace("Z", "+00:00"))
        days = (datetime.now(timezone.utc) - when).days
        if days < NEW_DAYS:
            msg = f"The {what} was created {days} days ago; new ones often carry poisoned PoCs."
            out.append(Finding(rule, Severity.MEDIUM, where, msg))
    return out
