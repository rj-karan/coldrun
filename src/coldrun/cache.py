"""Environment cache: one installed dependency set per content key.

An environment lives in ``~/.cache/coldrun/envs/<key>`` and is bound into the
sandbox at the runner's deps directory: read-write while installing, read-only
while running. ``<key>`` hashes the runner, interpreter and resolved packages,
so the same needs are installed once.
"""

from __future__ import annotations

import hashlib
import json
import shutil
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any

from coldrun.config import cache_dir

if TYPE_CHECKING:
    from pathlib import Path

    from coldrun.runners.base import DepSet

_READY = ".ready"
_META = "meta.json"


def envs_root() -> Path:
    """Parent of every cached environment."""
    return cache_dir() / "envs"


def env_key(runner: str, deps: DepSet) -> str:
    """Stable 16-hex key for a runner's resolved dependency set."""
    blob = json.dumps([runner, deps.interpreter, deps.ecosystem, list(deps.packages)])
    return hashlib.sha256(blob.encode()).hexdigest()[:16]


def env_dir(runner: str, deps: DepSet) -> Path:
    """Host directory for this dependency set; created on demand."""
    path = envs_root() / env_key(runner, deps)
    path.mkdir(parents=True, exist_ok=True)
    return path


def is_ready(path: Path) -> bool:
    """True when an install finished here."""
    return (path / _READY).exists()


def mark_ready(path: Path, runner: str, deps: DepSet) -> None:
    """Record a successful install so later runs skip it."""
    meta = {
        "runner": runner,
        "interpreter": deps.interpreter,
        "ecosystem": deps.ecosystem,
        "packages": list(deps.packages),
        "created": datetime.now(timezone.utc).isoformat(timespec="seconds"),
    }
    (path / _META).write_text(json.dumps(meta, indent=2) + "\n")
    (path / _READY).touch()


def discard(path: Path) -> None:
    """Remove a half-installed environment."""
    shutil.rmtree(path, ignore_errors=True)


def list_envs() -> list[dict[str, Any]]:
    """Every ready environment with its metadata, size and key."""
    out: list[dict[str, Any]] = []
    root = envs_root()
    if not root.is_dir():
        return out
    for path in sorted(root.iterdir()):
        if not is_ready(path):
            continue
        meta: dict[str, Any] = json.loads((path / _META).read_text())
        meta["key"] = path.name
        meta["bytes"] = sum(f.stat().st_size for f in path.rglob("*") if f.is_file())
        out.append(meta)
    return out


def clean() -> int:
    """Delete every cached environment; return how many were removed."""
    root = envs_root()
    if not root.is_dir():
        return 0
    count = sum(1 for p in root.iterdir() if p.is_dir())
    shutil.rmtree(root, ignore_errors=True)
    return count
