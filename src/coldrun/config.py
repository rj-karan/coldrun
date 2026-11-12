"""Where coldrun keeps its files on the host.

Only paths live here for now; the TOML config file arrives when there are
settings worth persisting. Both directories honour the XDG variables.
"""

from __future__ import annotations

import os
from pathlib import Path

APP = "coldrun"


def config_dir() -> Path:
    """``$XDG_CONFIG_HOME/coldrun`` or ``~/.config/coldrun``."""
    base = os.environ.get("XDG_CONFIG_HOME") or str(Path.home() / ".config")
    return Path(base) / APP


def cache_dir() -> Path:
    """``$XDG_CACHE_HOME/coldrun`` or ``~/.cache/coldrun``."""
    base = os.environ.get("XDG_CACHE_HOME") or str(Path.home() / ".cache")
    return Path(base) / APP


def quarantine_root() -> Path:
    """Parent of every quarantine directory, under the cache."""
    return cache_dir() / "quarantine"
