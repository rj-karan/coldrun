"""Sandbox backends behind one policy interface."""

from __future__ import annotations

from coldrun.sandbox.base import (
    EXIT_SANDBOX_FAILED,
    WORKDIR,
    Availability,
    Backend,
    NetPolicy,
    Policy,
    PolicyError,
    SandboxError,
    scrub_env,
)
from coldrun.sandbox.bwrap import BwrapBackend
from coldrun.sandbox.podman import PodmanBackend

__all__ = [
    "EXIT_SANDBOX_FAILED",
    "WORKDIR",
    "Availability",
    "Backend",
    "BwrapBackend",
    "NetPolicy",
    "PodmanBackend",
    "Policy",
    "PolicyError",
    "SandboxError",
    "scrub_env",
]
