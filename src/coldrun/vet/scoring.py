"""Risk score: fold findings into one verdict with the reasons behind it.

The verdict is the highest severity present, mapped to ``low``, ``medium`` or
``high``. ``INFO`` never changes it. A finding about a hardcoded host is
dropped when that host is in ``--allow-host`` and is always a reason when it
is not, whatever its severity.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from coldrun.vet.findings import Severity

if TYPE_CHECKING:
    from collections.abc import Iterable, Sequence

    from coldrun.vet.findings import Finding

LEVELS = {
    Severity.INFO: "low",
    Severity.LOW: "low",
    Severity.MEDIUM: "medium",
    Severity.HIGH: "high",
}


@dataclass(frozen=True, slots=True)
class Verdict:
    """The decision input: a level, why, and the findings that survived."""

    level: str
    reasons: tuple[str, ...]
    findings: tuple[Finding, ...]


def score(findings: Iterable[Finding], allow_hosts: Sequence[str] = ()) -> Verdict:
    """Aggregate ``findings`` into a :class:`Verdict`.

    Args:
        findings: Everything the rules and runners reported.
        allow_hosts: Hosts the user named; findings about them are dropped.
    """
    # shortcut: exact host match, no subdomain or CIDR logic; revisit with --allow-host (#26)
    allowed = {h.lower() for h in allow_hosts}
    kept = sorted(
        (f for f in findings if f.host is None or f.host.lower() not in allowed),
        key=lambda f: -f.severity.rank,
    )
    top = max((f.severity for f in kept), key=lambda s: s.rank, default=Severity.LOW)
    reasons = tuple(
        f"{f.rule_id} {f.location()}: {f.message}"
        for f in kept
        if f.severity is not Severity.INFO or f.host is not None
    )
    return Verdict(LEVELS[top], reasons, tuple(kept))
