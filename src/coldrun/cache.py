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
from pathlib import Path
from typing import TYPE_CHECKING, Any

from coldrun.config import cache_dir
from coldrun.safefs import tree_size, write_nofollow
from coldrun.vet.findings import Finding, Severity

if TYPE_CHECKING:
    from collections.abc import Sequence

    from coldrun.runners.base import DepSet

#: Suffix of the metadata file kept next to each environment, never inside it:
#: the sandbox can write inside the environment while dependencies install.
_META_SUFFIX = ".json"


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


def _meta(path: Path) -> Path:
    return path.parent / f"{path.name}{_META_SUFFIX}"


def is_ready(path: Path) -> bool:
    """True when an install finished here, by coldrun's own record next to it."""
    meta = _meta(path)
    return meta.is_file() and not meta.is_symlink()


def mark_ready(path: Path, runner: str, deps: DepSet, findings: Sequence[Finding] = ()) -> None:
    """Record a successful install, and what vetting its dependencies found, for later runs."""
    meta = {
        "runner": runner,
        "interpreter": deps.interpreter,
        "ecosystem": deps.ecosystem,
        "packages": list(deps.packages),
        "created": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "findings": [
            {
                "rule_id": f.rule_id,
                "severity": f.severity.value,
                "file": str(f.file),
                "message": f.message,
                "line": f.line,
                "host": f.host,
            }
            for f in findings
        ],
    }
    write_nofollow(_meta(path), json.dumps(meta, indent=2) + "\n")


def recorded_findings(path: Path) -> list[Finding]:
    """The dependency findings recorded when this environment was installed."""
    meta = json.loads(_meta(path).read_text())
    return [
        Finding(
            r["rule_id"],
            Severity(r["severity"]),
            Path(r["file"]),
            r["message"],
            r["line"],
            r["host"],
        )
        for r in meta.get("findings", [])
    ]


def discard(path: Path) -> None:
    """Remove a half-installed environment and its record."""
    shutil.rmtree(path, ignore_errors=True)
    _meta(path).unlink(missing_ok=True)


def list_envs() -> list[dict[str, Any]]:
    """Every ready environment with its metadata, size and key."""
    out: list[dict[str, Any]] = []
    root = envs_root()
    if not root.is_dir():
        return out
    for path in sorted(p for p in root.iterdir() if p.is_dir() and not p.is_symlink()):
        if not is_ready(path):
            continue
        meta: dict[str, Any] = json.loads(_meta(path).read_text())
        meta["key"] = path.name
        meta["bytes"] = tree_size(path)
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
