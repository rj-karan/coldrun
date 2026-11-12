"""Discover runners through the ``coldrun.runners`` entry-point group.

Built-in runners and third-party ones register the same way, so a plugin
package only needs one line in its ``pyproject.toml``. A plugin that fails to
load is reported, not fatal: one broken plugin must not take the tool down.
"""

from __future__ import annotations

import logging
from importlib.metadata import EntryPoint, entry_points
from typing import TYPE_CHECKING

from coldrun.runners.base import Runner, RunnerInfo

if TYPE_CHECKING:
    from collections.abc import Iterable

GROUP = "coldrun.runners"
log = logging.getLogger(__name__)


class RunnerNotFoundError(LookupError):
    """Raised when a runner name is asked for that is not registered."""

    def __init__(self, name: str, available: Iterable[str]) -> None:
        """Build a message that lists what is available."""
        names = ", ".join(sorted(available)) or "none"
        super().__init__(f"no runner named {name!r}; available: {names}")
        self.name = name


def _instantiate(ep: EntryPoint) -> Runner:
    obj = ep.load()
    # A class also "has" every protocol attribute, so check for classes first;
    # otherwise an uninstantiated runner would slip through.
    if isinstance(obj, type) or (callable(obj) and not isinstance(obj, Runner)):
        runner = obj()
    else:
        runner = obj
    if not isinstance(runner, Runner):
        msg = f"{ep.value} does not satisfy the Runner protocol"
        raise TypeError(msg)
    name = getattr(runner, "name", None)
    if not isinstance(name, str) or not name:
        msg = f"{ep.value} has no non-empty name"
        raise TypeError(msg)
    return runner


def discover(eps: Iterable[EntryPoint] | None = None) -> dict[str, RunnerInfo]:
    """Load every runner in the entry-point group.

    Args:
        eps: Entry points to load. Defaults to the installed ``coldrun.runners``
            group; tests pass their own.

    Returns:
        Loaded runners keyed by name, in entry-point order. The first runner
        to claim a name wins; later duplicates are logged and dropped. Entry
        points that fail to load are left out and logged with the cause.
    """
    if eps is None:
        eps = entry_points(group=GROUP)
    found: dict[str, RunnerInfo] = {}
    for ep in eps:
        dist = ep.dist.name if ep.dist is not None else None
        try:
            runner = _instantiate(ep)
        except Exception as exc:
            log.warning("runner entry point %s failed to load: %s", ep.value, exc)
            continue
        if runner.name in found:
            log.warning(
                "runner %r from %s ignored; already provided by %s",
                runner.name,
                ep.value,
                found[runner.name].entry_point,
            )
            continue
        found[runner.name] = RunnerInfo(runner=runner, entry_point=ep.value, distribution=dist)
    return found


class Registry:
    """The set of runners available in this process.

    Loading is lazy so ``coldrun --version`` never imports a plugin.
    """

    def __init__(self, eps: Iterable[EntryPoint] | None = None) -> None:
        """Create a registry that will load ``eps`` on first use."""
        self._eps = eps
        self._loaded: dict[str, RunnerInfo] | None = None

    def _ensure(self) -> dict[str, RunnerInfo]:
        if self._loaded is None:
            self._loaded = discover(self._eps)
        return self._loaded

    def names(self) -> list[str]:
        """Names of every loaded runner, sorted."""
        return sorted(self._ensure())

    def all(self) -> list[Runner]:
        """Every loaded runner, in registration order."""
        return [info.runner for info in self._ensure().values()]

    def info(self, name: str) -> RunnerInfo:
        """Loaded runner plus provenance, or :class:`RunnerNotFoundError`."""
        loaded = self._ensure()
        try:
            return loaded[name]
        except KeyError:
            raise RunnerNotFoundError(name, loaded) from None

    def get(self, name: str) -> Runner:
        """The runner called ``name``, or :class:`RunnerNotFoundError`."""
        return self.info(name).runner


_default: Registry | None = None


def default_registry() -> Registry:
    """Process-wide registry backed by the installed entry points."""
    global _default  # noqa: PLW0603 - a single lazily-built registry per process
    if _default is None:
        _default = Registry()
    return _default
