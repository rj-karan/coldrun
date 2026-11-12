from __future__ import annotations

from pathlib import Path

import pytest

from coldrun.runners.base import DepSet
from coldrun.vet.findings import Finding, Severity


def test_severity_ranks_in_order() -> None:
    ranks = [s.rank for s in (Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH)]
    assert ranks == sorted(ranks)
    assert max(Severity.LOW, Severity.HIGH, key=lambda s: s.rank) is Severity.HIGH


def test_finding_location_with_and_without_line() -> None:
    f = Finding("R1", Severity.LOW, Path("a.py"), "msg", line=3)
    assert f.location() == "a.py:3"
    assert Finding("R1", Severity.LOW, Path("a.py"), "msg").location() == "a.py"


@pytest.mark.parametrize(
    ("kwargs", "match"),
    [
        ({"rule_id": ""}, "needs a rule_id"),
        ({"message": ""}, "needs a one-line message"),
        ({"line": 0}, "line numbers start at 1"),
    ],
)
def test_finding_rejects_useless_values(kwargs: dict[str, object], match: str) -> None:
    base: dict[str, object] = {
        "rule_id": "R1",
        "severity": Severity.LOW,
        "file": Path("a"),
        "message": "m",
    }
    with pytest.raises(ValueError, match=match):
        Finding(**{**base, **kwargs})  # type: ignore[arg-type]


def test_depset_normalises_and_hashes() -> None:
    a = DepSet(ecosystem="pypi", packages=("b", "a", "a"), system_binaries=("jq", "curl"))
    b = DepSet(ecosystem="pypi", packages=("a", "b"), system_binaries=("curl", "jq"))
    assert a == b
    assert hash(a) == hash(b)
    assert a.packages == ("a", "b")
    assert not a.is_empty
    assert DepSet().is_empty
