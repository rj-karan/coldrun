from __future__ import annotations

from pathlib import Path

import pytest

from coldrun.runners.base import DepSet
from coldrun.vet import guarddog
from coldrun.vet.findings import Severity

FAKE = str(Path(__file__).resolve().parents[2] / "fixtures" / "deps" / "fake_guarddog.py")


def pypi(*pkgs: str) -> DepSet:
    return DepSet("pypi", pkgs, (), "python3", "test")


def test_skips_unknown_ecosystem_and_empty_depsets() -> None:
    assert guarddog.scan_deps(DepSet("system", ("x",)), exe=FAKE) == []
    assert guarddog.scan_deps(pypi(), exe=FAKE) == []


def test_missing_guarddog_is_one_low_finding(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("shutil.which", lambda _: None)
    (f,) = guarddog.scan_deps(pypi("requests"))
    assert (f.rule_id, f.severity) == ("guarddog.missing", Severity.LOW)
    assert guarddog.INSTALL_HINT in f.message


def test_hits_map_to_severities_and_locations() -> None:
    found = guarddog.scan_deps(pypi("hooked"), exe=FAKE)
    by = {f.rule_id: f for f in found}
    assert set(by) == {
        "guarddog.capability-process-hooks",
        "guarddog.threat-process-download-exec",
        "guarddog.typosquatting",
        "guarddog.deceptive_author",
    }  # plain capability-network-outbound is dropped
    hook = by["guarddog.capability-process-hooks"]
    assert hook.location() == "hooked/setup.py:11"
    assert hook.message == 'cmdclass={"install": PostInstall}'
    # the package label "suspicious" sets every hit to medium
    assert {f.severity for f in found} == {Severity.MEDIUM}
    assert by["guarddog.threat-process-download-exec"].message == "dl+exec"
    assert by["guarddog.typosquatting"].message == "requests"
    assert by["guarddog.deceptive_author"].location() == "hooked"


@pytest.mark.parametrize(
    ("target", "sev"),
    [
        ("evil", Severity.HIGH),  # label high_risk
        ("lowish", Severity.LOW),  # label low
        ("fp", Severity.INFO),  # label no_risks_detected: shown, never changes the verdict
        ("unscored", Severity.HIGH),  # no risk_score at all: assume the worst
    ],
)
def test_package_label_decides_threat_severity(target: str, sev: Severity) -> None:
    (f,) = guarddog.scan_deps(pypi(target), exe=FAKE)
    assert (f.rule_id, f.severity) == ("guarddog.threat-network-exfiltration", sev)


def test_install_hook_is_at_least_medium_even_when_unscored_package_is_clean() -> None:
    assert guarddog._severity("capability-process-hooks", "no_risks_detected") is Severity.MEDIUM
    assert guarddog._severity("capability-process-hooks", "high_risk") is Severity.HIGH
    assert guarddog._severity("capability-network-outbound", "high_risk") is None


def test_clean_package_has_no_findings() -> None:
    assert guarddog.scan_deps(pypi("clean"), exe=FAKE) == []


def test_pin_version_and_extras_are_parsed() -> None:
    # the fake echoes the version it was given; a scan error would mention it
    assert guarddog.scan_deps(pypi("clean[socks] == 2.0", "clean>=1", "   "), exe=FAKE) == []
    (f,) = guarddog.scan_package(FAKE, "pypi", "nodl", version="1.0")
    assert f.rule_id == "guarddog.failed"
    assert f.message == "not vetted, guarddog failed: download-package: GitError: Permission denied"
    assert f.severity is Severity.LOW


@pytest.mark.parametrize(
    ("target", "why"),
    [("broken", "exit 2: boom"), ("garbage", "exit 0: not json")],
)
def test_crash_and_bad_output_become_low_findings(target: str, why: str) -> None:
    (f,) = guarddog.scan_deps(pypi(target), exe=FAKE)
    assert f.rule_id == "guarddog.failed"
    assert f.message.endswith(why)


def test_unrunnable_binary_is_a_low_finding(tmp_path: Path) -> None:
    (f,) = guarddog.scan_deps(pypi("x"), exe=str(tmp_path / "nope"))
    assert f.rule_id == "guarddog.failed"
    assert "No such file" in f.message
