"""muzzle: fetch, vet and sandbox any downloaded script in one command."""

from __future__ import annotations

from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("muzzle")
except PackageNotFoundError:  # pragma: no cover - only when run from a bare checkout
    __version__ = "0.0.0+unknown"

__all__ = ["__version__"]
