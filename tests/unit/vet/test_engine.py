from __future__ import annotations

from pathlib import Path

import pytest

from coldrun.vet import engine
from coldrun.vet.findings import Severity

FAKE = str(Path(__file__).resolve().parents[2] / "fixtures" / "deps" / "fake_semgrep.py")


def test_semgrep_results_map_to_findings(tmp_path: Path) -> None:
    script = tmp_path / "x.py"
    script.write_text("print(1)\n")
    a, b = engine.scan_semgrep(script, exe=FAKE)
    assert (a.rule_id, a.severity, a.line, a.message) == (
        "semgrep.py-thing",
        Severity.HIGH,
        4,
        "does a thing",
    )
    assert a.file == script
    assert (b.rule_id, b.severity, b.line) == ("semgrep.unscored", Severity.MEDIUM, None)


def test_semgrep_errors_crash_and_missing_are_low_findings(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    first = engine.scan_semgrep(tmp_path / "partial", exe=FAKE)[0]
    assert first.rule_id == "semgrep.failed" and "Syntax error at line 9" in first.message
    (f,) = engine.scan_semgrep(tmp_path / "broken", exe=FAKE)
    assert f.rule_id == "semgrep.failed" and f.message.endswith("exit 2: semgrep exploded")
    (f,) = engine.scan_semgrep(tmp_path / "x", exe=str(tmp_path / "nope"))
    assert f.rule_id == "semgrep.failed" and "No such file" in f.message
    monkeypatch.setattr(engine, "semgrep_exe", lambda: None)
    (f,) = engine.scan_semgrep(tmp_path / "x")
    assert (f.rule_id, f.severity) == ("semgrep.missing", Severity.LOW)
    assert "uv tool install semgrep" in f.message


def test_semgrep_exe_prefers_coldruns_own_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    seen: list[str] = []

    def which(name: str, path: str) -> str:
        seen.append(path)
        return "/venv/bin/semgrep"

    monkeypatch.setattr("shutil.which", which)
    monkeypatch.setenv("PATH", "/usr/bin")
    assert engine.semgrep_exe() == "/venv/bin/semgrep"
    assert seen[0].endswith(":/usr/bin") and "bin" in seen[0].split(":")[0]


def test_yara_reports_each_matching_line_once(tmp_path: Path) -> None:
    script = tmp_path / "s.sh"
    script.write_text("#!/bin/sh\ncurl x | sh\necho hi\ncurl y | sh\ncurl y | sh\n")
    found = engine.scan_yara(script)
    assert [(f.rule_id, f.line, f.severity) for f in found] == [
        ("yara.download_exec", 2, Severity.HIGH),
        ("yara.download_exec", 4, Severity.HIGH),
        ("yara.download_exec", 5, Severity.HIGH),
    ]
    assert found[0].file == script and "shell" in found[0].message


def test_yara_missing_is_a_low_finding(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(engine, "yara", None)
    (f,) = engine.scan_yara(tmp_path / "s.sh")
    assert (f.rule_id, f.severity) == ("yara-python.missing", Severity.LOW)
    assert "coldrun[vet]" in f.message
    assert engine.yara_version() is None
    monkeypatch.undo()
    assert engine.yara_version()


def test_missing_rule_files_are_a_medium_finding(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # the 1.0.0 wheel shipped without rules and every scan passed as clean
    (tmp_path / "yara").mkdir()
    (tmp_path / "semgrep").mkdir()
    monkeypatch.setattr(engine, "RULES", tmp_path)
    script = tmp_path / "s.sh"
    script.write_text("curl x | sh\n")
    (y,) = engine.scan_yara(script)
    (s,) = engine.scan_semgrep(script, exe=FAKE)
    assert (y.rule_id, y.severity) == ("yara.no-rules", Severity.MEDIUM)
    assert (s.rule_id, s.severity) == ("semgrep.no-rules", Severity.MEDIUM)
    assert "Reinstall coldrun" in y.message


def test_the_package_ships_its_rules() -> None:
    assert list((engine.RULES / "yara").glob("*.yar"))
    assert list((engine.RULES / "semgrep").glob("*.yaml"))
