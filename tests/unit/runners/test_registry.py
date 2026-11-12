from __future__ import annotations

import logging
from importlib.metadata import EntryPoint

import pytest

from coldrun.runners import registry
from coldrun.runners.registry import GROUP, Registry, RunnerNotFoundError, discover

MOD = "tests.unit.runners.fake_runner"


def ep(name: str, attr: str) -> EntryPoint:
    return EntryPoint(name=name, value=f"{MOD}:{attr}", group=GROUP)


def test_loads_class_and_factory_entry_points() -> None:
    found = discover([ep("fake", "FakeRunner")])
    assert list(found) == ["fake"]
    assert found["fake"].entry_point == f"{MOD}:FakeRunner"
    assert found["fake"].distribution is None

    found = discover([ep("fake", "factory")])
    assert found["fake"].runner.name == "fake"


def test_broken_plugin_is_skipped_and_logged(caplog: pytest.LogCaptureFixture) -> None:
    with caplog.at_level(logging.WARNING, logger="coldrun.runners.registry"):
        found = discover([ep("bad", "broken"), ep("fake", "FakeRunner")])
    assert list(found) == ["fake"]
    assert "plugin exploded on load" in caplog.text


def test_object_without_protocol_is_rejected(caplog: pytest.LogCaptureFixture) -> None:
    with caplog.at_level(logging.WARNING):
        found = discover([ep("x", "NotARunner")])
    assert found == {}
    assert "does not satisfy the Runner protocol" in caplog.text


def test_empty_name_is_rejected(caplog: pytest.LogCaptureFixture) -> None:
    with caplog.at_level(logging.WARNING):
        found = discover([ep("x", "NamelessRunner")])
    assert found == {}
    assert "no non-empty name" in caplog.text


def test_first_registration_wins_on_duplicate_name(caplog: pytest.LogCaptureFixture) -> None:
    with caplog.at_level(logging.WARNING):
        found = discover([ep("a", "FakeRunner"), ep("b", "factory")])
    assert found["fake"].entry_point == f"{MOD}:FakeRunner"
    assert "already provided by" in caplog.text


def test_missing_module_is_skipped(caplog: pytest.LogCaptureFixture) -> None:
    bad = EntryPoint(name="ghost", value="no.such.module:Thing", group=GROUP)
    with caplog.at_level(logging.WARNING):
        assert discover([bad]) == {}
    assert "failed to load" in caplog.text


def test_registry_lookup_and_errors() -> None:
    reg = Registry([ep("fake", "FakeRunner")])
    assert reg.names() == ["fake"]
    assert reg.get("fake").name == "fake"
    assert [r.name for r in reg.all()] == ["fake"]
    with pytest.raises(RunnerNotFoundError, match="no runner named 'nope'; available: fake"):
        reg.get("nope")


def test_registry_is_lazy_and_loads_once(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[int] = []

    def fake_discover(eps: object) -> dict[str, object]:
        calls.append(1)
        return {}

    monkeypatch.setattr(registry, "discover", fake_discover)
    reg = Registry([])
    assert calls == []
    reg.names()
    reg.names()
    assert calls == [1]


def test_default_registry_reads_installed_group(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(registry, "_default", None)
    monkeypatch.setattr(registry, "entry_points", lambda group: [ep("fake", "FakeRunner")])
    reg = registry.default_registry()
    assert reg is registry.default_registry()
    assert reg.names() == ["fake"]


def test_installed_group_is_empty_until_runners_land() -> None:
    # No built-in runners are registered yet; M1 adds the first one in #15.
    assert Registry().names() == []
