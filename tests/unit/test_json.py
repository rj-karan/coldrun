"""``--json``: one document on stdout that matches docs/report.schema.json."""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

import jsonschema
import pytest
from typer.testing import CliRunner

from coldrun import cli, pipeline
from coldrun.pipeline import RunOptions, Services
from coldrun.report import Report, emit_json
from coldrun.vet.findings import Finding, Severity
from tests.unit.test_pipeline import FakeBackend, VettingRunner, console, finding, registry, script

SCHEMA = json.loads(
    (Path(__file__).resolve().parents[2] / "docs" / "report.schema.json").read_text()
)


def valid(text: str) -> dict[str, Any]:
    doc: dict[str, Any] = json.loads(text)
    jsonschema.validate(doc, SCHEMA)
    return doc


def test_empty_report_is_valid(capsys: pytest.CaptureFixture[str]) -> None:
    emit_json(Report())
    doc = valid(capsys.readouterr().out)
    assert doc["schema_version"] == 1 and doc["source"] is None and doc["findings"] == []


def test_run_json_is_valid_and_keeps_stdout_clean(
    script: Path, tmp_path: Path, capfd: pytest.CaptureFixture[str]
) -> None:
    class Chatty(FakeBackend):
        def run(self, policy: Any, argv: Any) -> int:
            os.write(1, b"script says hi\n")
            return 3

    runner = VettingRunner([Finding("R", Severity.LOW, Path("s"), "m", host="1.2.3.4")])
    con, buf = console()
    opts = RunOptions(source=str(script), out=tmp_path / "o", tty=False, json=True)
    code = pipeline.run(opts, con, Services(registry(runner), {"c": Chatty()}))
    out, err = capfd.readouterr()
    assert code == 3 and "script says hi" in err and "script says hi" not in out
    doc = valid(out)
    assert doc["exit_code"] == 3 and doc["verdict"] == "low" and doc["error"] is None
    assert doc["findings"][0]["host"] == "1.2.3.4" and doc["sandbox"]["backend"] == "fake"
    assert doc["runner"]["name"] == "vetsh" and doc["source"]["kind"] == "file"
    assert "verdict" in buf.getvalue()  # the human report still goes to the console


def test_errors_carry_what_and_hint(capsys: pytest.CaptureFixture[str]) -> None:
    con, _ = console()
    assert (
        pipeline.run(
            RunOptions(source="/nope.sh", tty=False, json=True), con, Services(registry(), {})
        )
        == 2
    )
    doc = valid(capsys.readouterr().out)
    assert doc["exit_code"] == 2 and doc["error"]["what"] and doc["error"]["hint"]
    assert doc["source"] is None


def test_scan_and_deps_json(script: Path, capsys: pytest.CaptureFixture[str]) -> None:
    runner = VettingRunner([finding(Severity.HIGH)])
    con, _ = console()
    svc = Services(registry(runner), {}, scan_deps=lambda d: [])
    assert pipeline.scan(str(script), None, con, svc, as_json=True) == 100
    doc = valid(capsys.readouterr().out)
    assert doc["verdict"] == "high" and doc["sandbox"] is None and doc["exit_code"] == 100
    assert pipeline.deps(str(script), None, con, svc, as_json=True) == 0
    doc = valid(capsys.readouterr().out)
    assert doc["deps"]["interpreter"] == "sh" and doc["verdict"] is None and doc["exit_code"] == 0


def test_cli_passes_json_flag(monkeypatch: pytest.MonkeyPatch) -> None:
    seen: list[bool] = []

    def fake_run(opts: RunOptions, console: object, services: object = None) -> int:
        seen.append(opts.json)
        return 0

    def fake_cmd(
        source: str,
        lang: str | None,
        console: object,
        services: object = None,
        *,
        as_json: bool = False,
    ) -> int:
        seen.append(as_json)
        return 0

    monkeypatch.setattr(pipeline, "run", fake_run)
    monkeypatch.setattr(pipeline, "scan", fake_cmd)
    monkeypatch.setattr(pipeline, "deps", fake_cmd)
    for cmd in (
        ["run", "x", "--json"],
        ["scan", "x", "--json"],
        ["deps", "x", "--json"],
        ["deps", "x"],
    ):
        assert CliRunner().invoke(cli.app, cmd).exit_code == 0
    assert seen == [True, True, True, False]


__all__ = ["script"]  # the fixture is imported, not unused
