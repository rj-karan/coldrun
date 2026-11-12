"""The sandbox policy model and the backend contract.

A :class:`Policy` says what the script may see and do. Backends turn a policy
into a concrete sandbox. Every rule in the spec's security model is encoded
here or enforced by a backend, and all of this code is covered by tests.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import TYPE_CHECKING, Protocol

if TYPE_CHECKING:
    from collections.abc import Mapping, Sequence

#: Where the script and its scratch space appear inside the sandbox.
WORKDIR = "/work"
#: Exit code the CLI uses when the sandbox itself could not be set up.
EXIT_SANDBOX_FAILED = 101

#: Variables copied from the host when present. Everything else is dropped.
ENV_PASSTHROUGH: frozenset[str] = frozenset(
    {
        "TERM",
        "COLORTERM",
        "NO_COLOR",
        "FORCE_COLOR",
        "LANG",
        "LANGUAGE",
        "LC_ALL",
        "LC_CTYPE",
        "TZ",
    }
)
#: Variables set to fixed values regardless of the host.
ENV_FIXED: Mapping[str, str] = {
    "PATH": "/usr/local/bin:/usr/bin:/bin",
    "HOME": WORKDIR,
    "TMPDIR": "/tmp",  # noqa: S108 - guest path on a private tmpfs
    "USER": "coldrun",
    "LOGNAME": "coldrun",
    "SHELL": "/bin/sh",
}

#: Host locations that may never be mounted read-write, even on request.
_FORBIDDEN_RW_NAMES = frozenset(
    {
        ".ssh",
        ".gnupg",
        ".aws",
        ".azure",
        ".config",
        ".kube",
        ".docker",
        ".mozilla",
        ".password-store",
    }
)


class NetPolicy(str, Enum):
    """Network access inside the sandbox."""

    NONE = "none"
    ALLOW = "allow"  # only --allow-host destinations; enforced from M4
    FULL = "full"


class SandboxError(Exception):
    """The sandbox could not be built or started.

    Args:
        what: What failed, in one sentence.
        hint: The next command to try, usually ``coldrun doctor``.
    """

    exit_code = EXIT_SANDBOX_FAILED

    def __init__(self, what: str, hint: str) -> None:
        """Keep the halves separate for the report."""
        super().__init__(f"{what} {hint}")
        self.what = what
        self.hint = hint


class PolicyError(ValueError):
    """A requested policy breaks a rule that is not negotiable."""


@dataclass(frozen=True, slots=True)
class Policy:
    """What one sandboxed run may access.

    Attributes:
        script: The quarantined file to run. Mounted read-only at
            ``/work/<name>``.
        scratch: Private host directory mounted read-write at ``/work``; the
            script's cwd. Files it writes land here and are copied to
            ``--out`` by the pipeline.
        net: Network policy. ``NONE`` by default.
        rw_paths: Host paths mounted read-write at the same location
            (``--rw``). Validated against the forbidden list.
        ro_paths: Host paths mounted read-only at the same location, for
            dependency environments and interpreters.
        env: Extra variables, already decided safe by the caller, layered on
            top of the scrubbed allowlist.
        tty: Whether stdin is a terminal and should pass through.
        hostname: Hostname inside the sandbox.
    """

    script: Path
    scratch: Path
    net: NetPolicy = NetPolicy.NONE
    rw_paths: tuple[Path, ...] = ()
    ro_paths: tuple[Path, ...] = ()
    env: Mapping[str, str] = field(default_factory=dict)
    tty: bool = False
    hostname: str = "coldrun"

    def __post_init__(self) -> None:
        """Reject policies that would hand the host to the script."""
        if not self.script.is_absolute() or not self.scratch.is_absolute():
            msg = "script and scratch must be absolute paths"
            raise PolicyError(msg)
        for p in self.rw_paths:
            check_rw_path(p)
        for p in self.ro_paths:
            if not p.is_absolute():
                msg = f"read-only path must be absolute: {p}"
                raise PolicyError(msg)

    @property
    def guest_script(self) -> str:
        """Where the script appears inside the sandbox."""
        return f"{WORKDIR}/{self.script.name}"


def check_rw_path(path: Path) -> None:
    """Refuse read-write mounts that would expose the host.

    Blocks ``/``, the home directory itself, anything under a credential
    directory, and relative paths.

    Raises:
        PolicyError: With the reason.
    """
    if not path.is_absolute():
        msg = f"--rw path must be absolute: {path}"
        raise PolicyError(msg)
    resolved = Path(os.path.realpath(path))
    home = Path.home().resolve()
    if resolved == Path("/") or resolved == home:
        msg = f"--rw {path} would expose the whole filesystem or home directory"
        raise PolicyError(msg)
    if any(part in _FORBIDDEN_RW_NAMES for part in resolved.parts):
        msg = f"--rw {path} is inside a credential or configuration directory"
        raise PolicyError(msg)
    if not resolved.exists():
        msg = f"--rw {path} does not exist"
        raise PolicyError(msg)


def scrub_env(host: Mapping[str, str], extra: Mapping[str, str] | None = None) -> dict[str, str]:
    """Build the environment the script sees.

    Fixed values first, then the allowlisted host variables, then ``extra``
    from the caller. ``extra`` may not override the fixed values that keep
    the script inside its scratch space.
    """
    env = dict(ENV_FIXED)
    for name in sorted(ENV_PASSTHROUGH):
        if name in host:
            env[name] = host[name]
    for name, value in (extra or {}).items():
        if name in {"HOME", "TMPDIR", "PATH"} and value != env[name]:
            msg = f"environment override of {name} is not allowed"
            raise PolicyError(msg)
        env[name] = value
    return env


@dataclass(frozen=True, slots=True)
class Availability:
    """Whether a backend can be used here, and if not, why."""

    ok: bool
    reason: str = ""
    hint: str = ""


class Backend(Protocol):
    """One way of building a sandbox."""

    name: str

    def available(self) -> Availability:
        """Cheap check that the backend can work on this host."""
        ...

    def command(self, policy: Policy, argv: Sequence[str]) -> list[str]:
        """Full host argument list that runs ``argv`` under ``policy``.

        Pure: no side effects, so tests can inspect it.
        """
        ...

    def run(self, policy: Policy, argv: Sequence[str]) -> int:
        """Run ``argv`` under ``policy`` with stdio passed through.

        Returns:
            The script's exit code.

        Raises:
            SandboxError: When the sandbox cannot be set up.
        """
        ...
