"""Dependency vetting with GuardDog, run on the host as a fixed argument list.

GuardDog downloads a package and analyses it with Semgrep and registry
metadata rules inside its own extraction sandbox; nothing from the package is
executed. It is optional: when it is missing or a scan fails, the report says
so as a low finding and the verdict is otherwise unchanged.
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess  # nosemgrep: gitlab.bandit.B404 -- guarddog with a fixed argv list
from pathlib import Path
from typing import TYPE_CHECKING

from coldrun.vet.findings import Finding, Severity

if TYPE_CHECKING:
    from coldrun.runners.base import DepSet

#: DepSet ecosystems that are also guarddog subcommands.
ECOSYSTEMS = frozenset({"pypi", "npm", "go", "rubygems", "crates"})
INSTALL_HINT = "uv tool install guarddog"
TIMEOUT = 300
# name, optional [extras], optional ==pin; other specifiers scan the latest release
_SPEC = re.compile(r"^\s*([A-Za-z0-9@][A-Za-z0-9._/-]*)(?:\[[^\]]*\])?\s*(?:==\s*([^\s,;]+))?")


def scan_deps(deps: DepSet, exe: str | None = None) -> list[Finding]:
    """One finding per GuardDog hit across every package in ``deps``."""
    if deps.ecosystem not in ECOSYSTEMS or not deps.packages:
        return []
    exe = exe or shutil.which("guarddog")
    if exe is None:
        msg = f"guarddog is not installed, so dependencies were not vetted. Fix: {INSTALL_HINT}"
        return [Finding("guarddog.missing", Severity.LOW, Path(deps.ecosystem), msg)]
    out: list[Finding] = []
    for spec in deps.packages:
        m = _SPEC.match(spec)
        if m is None:
            continue
        out += scan_package(exe, deps.ecosystem, m.group(1), version=m.group(2))
    return out


def scan_package(
    exe: str, ecosystem: str, target: str, *, version: str | None = None
) -> list[Finding]:
    """Scan one registry package or local directory and map the JSON to findings."""
    argv = [exe, ecosystem, "scan", target, "--output-format", "json"]
    if version:
        argv += ["-v", version]
    where = Path(target)
    try:
        proc = subprocess.run(  # noqa: S603 - fixed argv of a known tool
            argv, capture_output=True, text=True, check=False, timeout=TIMEOUT
        )
        data = json.loads(proc.stdout)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return [_failed(where, str(exc))]
    except ValueError:
        detail = (proc.stderr.strip() or proc.stdout.strip()).splitlines()[-1:] or ["no output"]
        return [_failed(where, f"exit {proc.returncode}: {detail[0]}")]
    out = [
        _failed(where, f"{step}: {_last_line(err)}") for step, err in data.get("errors", {}).items()
    ]
    for rule, hits in data.get("results", {}).items():
        sev = _severity(rule)
        if sev is None or not hits:
            continue
        for hit in hits if isinstance(hits, list) else [hits]:
            if not isinstance(hit, dict):
                out.append(Finding(f"guarddog.{rule}", sev, where, _one_line(hit)))
                continue
            file, _, line = str(hit.get("location", "")).partition(":")
            text = _one_line(hit.get("code") or hit.get("message") or rule)
            out.append(
                Finding(
                    f"guarddog.{rule}",
                    sev,
                    where / file,
                    text,
                    line=int(line) if line.isdigit() else None,
                )
            )
    return out


def _severity(rule: str) -> Severity | None:
    if rule.startswith("threat-"):
        return Severity.HIGH
    if rule == "capability-process-hooks" or not rule.startswith("capability-"):
        return Severity.MEDIUM  # install hooks and registry metadata rules
    # shortcut: plain capability-* hits describe every library; show them once --verbose exists
    return None


def _failed(where: Path, why: str) -> Finding:
    return Finding("guarddog.failed", Severity.LOW, where, f"not vetted, guarddog failed: {why}")


def _one_line(value: object) -> str:
    return " ".join(str(value).split())[:120]


def _last_line(text: str) -> str:
    lines = text.strip().splitlines()
    return _one_line(lines[-1]) if lines else "unknown error"
