"""Every rule has one fixture that must match and one that must not."""

from __future__ import annotations

import re
import shutil
from pathlib import Path

import pytest

from coldrun.vet import engine

FX = Path(__file__).resolve().parents[2] / "fixtures" / "vet"
SEMGREP_IDS = sorted(
    re.findall(
        r"^  - id: (\S+)", (engine.RULES / "semgrep" / "python.yaml").read_text(), re.MULTILINE
    )
)
YARA_IDS = sorted(
    re.findall(r"^rule (\w+)", (engine.RULES / "yara" / "host.yar").read_text(), re.MULTILINE)
)


def fixture_pair(kind: str, rule: str) -> tuple[Path, Path]:
    match = next(iter((FX / kind).glob(f"{rule}.match.*")), None)
    nomatch = next(iter((FX / kind).glob(f"{rule}.nomatch.*")), None)
    assert match and nomatch, f"{kind}/{rule} needs a match and a nomatch fixture"
    return match, nomatch


def test_every_rule_has_fixtures() -> None:
    assert SEMGREP_IDS and YARA_IDS
    for rule in SEMGREP_IDS:
        fixture_pair("semgrep", rule)
    for rule in YARA_IDS:
        fixture_pair("yara", rule)


def test_semgrep_rules_match_only_their_sample(tmp_path: Path) -> None:
    # one semgrep run for all samples; semgrep's default ignore list skips tests/ dirs
    shutil.copytree(FX / "semgrep", tmp_path / "s")
    found = engine.scan_semgrep(tmp_path / "s")
    hits = {(f.file.name, f.rule_id) for f in found}
    assert not [f for f in found if f.rule_id.endswith(".failed")], found
    for rule in SEMGREP_IDS:
        match, nomatch = fixture_pair("semgrep", rule)
        assert (match.name, f"semgrep.{rule}") in hits, f"{rule} must match {match.name}"
        assert (nomatch.name, f"semgrep.{rule}") not in hits, (
            f"{rule} must not match {nomatch.name}"
        )


@pytest.mark.parametrize("rule", YARA_IDS)
def test_yara_rule_matches_only_its_sample(rule: str) -> None:
    match, nomatch = fixture_pair("yara", rule)
    assert f"yara.{rule}" in {f.rule_id for f in engine.scan_yara(match)}
    assert f"yara.{rule}" not in {f.rule_id for f in engine.scan_yara(nomatch)}


def test_every_rule_carries_severity_and_explanation() -> None:
    sem = (engine.RULES / "semgrep" / "python.yaml").read_text()
    assert sem.count("severity: high") + sem.count("severity: medium") == len(SEMGREP_IDS)
    assert sem.count("message:") == len(SEMGREP_IDS)
    yar = (engine.RULES / "yara" / "host.yar").read_text()
    assert yar.count('severity = "') == len(YARA_IDS)
    assert yar.count("description = ") == len(YARA_IDS)
