from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from coldrun.vet import source
from coldrun.vet.findings import Severity
from tests.unit.fetch.conftest import Server, server

__all__ = ["server"]  # the fixture is imported, not unused


def days_ago(n: int) -> str:
    return (datetime.now(timezone.utc) - timedelta(days=n)).isoformat().replace("+00:00", "Z")


@pytest.fixture
def api(server: Server, monkeypatch: pytest.MonkeyPatch) -> Server:
    monkeypatch.setattr(source, "API", server.url(""))
    return server


def test_other_origins_are_not_checked() -> None:
    assert source.scan_source("/home/me/x.py") == []
    assert source.scan_source("edb:1") == []


def pushes(*ages: int) -> bytes:
    return json.dumps([{"timestamp": days_ago(n), "ref": "refs/heads/main"} for n in ages]).encode()


ACTIVITY = "/repos/o/r/activity?activity_type=force_push&ref=refs%2Fheads%2F{}&per_page=1"


def test_new_repo_is_medium_and_old_owner_is_quiet(api: Server) -> None:
    api.route(
        "/repos/o/r", json.dumps({"created_at": days_ago(3), "default_branch": "main"}).encode()
    )
    api.route("/users/o", json.dumps({"created_at": days_ago(2000)}).encode())
    api.route(ACTIVITY.format("main"), pushes())
    (f,) = source.scan_source("https://github.com/o/r.git")
    assert (f.rule_id, f.severity, f.file) == ("source.new-repo", Severity.MEDIUM, Path("o/r"))
    assert "3 days ago" in f.message


def test_raw_origin_and_new_account(api: Server) -> None:
    api.route(
        "/repos/o/r", json.dumps({"created_at": days_ago(400), "default_branch": "main"}).encode()
    )
    api.route("/users/o", json.dumps({"created_at": days_ago(1)}).encode())
    api.route(ACTIVITY.format("v2"), pushes(90))  # an old force-push is quiet; ref from the URL
    found = source.scan_source("https://raw.githubusercontent.com/o/r/v2/x.py")
    assert [f.rule_id for f in found] == ["source.new-account"]


def test_recent_force_push_is_medium(api: Server) -> None:
    api.route(
        "/repos/o/r", json.dumps({"created_at": days_ago(400), "default_branch": "main"}).encode()
    )
    api.route("/users/o", json.dumps({"created_at": days_ago(900)}).encode())
    api.route(ACTIVITY.format("main"), pushes(2))
    (f,) = source.scan_source("https://github.com/o/r")
    assert (f.rule_id, f.severity) == ("source.force-pushed", Severity.MEDIUM)
    assert "main was force-pushed 2 days ago" in f.message


@pytest.mark.parametrize("body", [b'{"nope": 1}', b"[]"])
def test_api_trouble_is_one_info_finding(api: Server, body: bytes) -> None:
    api.route("/repos/o/r", body)
    api.route("/users/o", body)
    (f,) = source.scan_source("https://github.com/o/r")
    assert (f.rule_id, f.severity) == ("source.unchecked", Severity.INFO)
    (f,) = source.scan_source("https://github.com/o/missing")  # 404
    assert f.rule_id == "source.unchecked"
