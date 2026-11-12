from __future__ import annotations

from pathlib import Path

import pytest

from coldrun import config


def test_xdg_variables_win(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "cfg"))
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path / "cache"))
    assert config.config_dir() == tmp_path / "cfg" / "coldrun"
    assert config.cache_dir() == tmp_path / "cache" / "coldrun"
    assert config.quarantine_root() == tmp_path / "cache" / "coldrun" / "quarantine"


def test_defaults_under_home(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.delenv("XDG_CONFIG_HOME", raising=False)
    monkeypatch.delenv("XDG_CACHE_HOME", raising=False)
    monkeypatch.setenv("HOME", str(tmp_path))
    assert config.config_dir() == tmp_path / ".config" / "coldrun"
    assert config.cache_dir() == tmp_path / ".cache" / "coldrun"
