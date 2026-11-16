from __future__ import annotations

from itertools import combinations_with_replacement
from pathlib import Path

import pytest

from coldrun.vet.findings import Finding, Severity
from coldrun.vet.scoring import LEVELS, score

SEVERITIES = list(Severity)


def finding(sev: Severity, host: str | None = None, rule: str = "R1") -> Finding:
    return Finding(rule, sev, Path("s.py"), f"{rule} says", line=2, host=host)


def test_empty_is_low_with_no_reasons() -> None:
    v = score([])
    assert (v.level, v.reasons, v.findings) == ("low", (), ())


@pytest.mark.parametrize(
    "combo", [c for n in (1, 2, 3) for c in combinations_with_replacement(SEVERITIES, n)]
)
def test_level_is_the_highest_severity(combo: tuple[Severity, ...]) -> None:
    v = score([finding(s) for s in combo])
    assert v.level == LEVELS[max(combo, key=lambda s: s.rank)]
    assert [f.severity for f in v.findings] == sorted(combo, key=lambda s: -s.rank)
    assert len(v.reasons) == sum(s is not Severity.INFO for s in combo)


def test_reason_text_names_rule_location_and_message() -> None:
    assert score([finding(Severity.HIGH)]).reasons == ("R1 s.py:2: R1 says",)


def test_allowed_host_is_dropped_entirely() -> None:
    v = score([finding(Severity.HIGH, host="Evil.example")], allow_hosts=["evil.EXAMPLE"])
    assert (v.level, v.reasons, v.findings) == ("low", (), ())


def test_unallowed_host_is_always_a_reason_even_at_info() -> None:
    v = score([finding(Severity.INFO, host="10.0.0.1")], allow_hosts=["10.0.0.2"])
    assert v.level == "low"
    assert v.reasons == ("R1 s.py:2: R1 says",)
    assert v.findings[0].host == "10.0.0.1"


def test_hostless_findings_ignore_allow_hosts() -> None:
    assert score([finding(Severity.MEDIUM)], allow_hosts=["a"]).level == "medium"
