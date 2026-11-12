"""Finding model shared by runners and the vetting engine.

Scoring and aggregation arrive with the vetting milestone; this module only
defines what a single finding looks like so runners can emit them.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pathlib import Path


class Severity(str, Enum):
    """How much a finding should worry the user.

    ``INFO`` is shown but never changes the verdict. The other three feed the
    risk score: low runs, medium asks, high refuses.
    """

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"

    @property
    def rank(self) -> int:
        """Numeric order so severities can be compared and maxed."""
        return _RANK[self]


_RANK = {Severity.INFO: 0, Severity.LOW: 1, Severity.MEDIUM: 2, Severity.HIGH: 3}


@dataclass(frozen=True, slots=True)
class Finding:
    """One observation about a script or dependency.

    Every finding carries a rule ID, a severity, the file it was found in, the
    line when one applies, and a one-line explanation the user can act on.
    """

    rule_id: str
    severity: Severity
    file: Path
    message: str
    line: int | None = None

    def __post_init__(self) -> None:
        """Reject findings that would be useless to the user."""
        if not self.rule_id:
            msg = "a finding needs a rule_id"
            raise ValueError(msg)
        if not self.message:
            msg = f"{self.rule_id}: a finding needs a one-line message"
            raise ValueError(msg)
        if self.line is not None and self.line < 1:
            msg = f"{self.rule_id}: line numbers start at 1, got {self.line}"
            raise ValueError(msg)

    def location(self) -> str:
        """Return ``file:line`` or just ``file`` for display."""
        return f"{self.file}:{self.line}" if self.line is not None else str(self.file)
