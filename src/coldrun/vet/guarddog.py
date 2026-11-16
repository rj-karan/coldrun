"""Dependency vetting with GuardDog, run on the host as a fixed argument list.

GuardDog downloads a package and analyses it with Semgrep and registry
metadata rules inside its own extraction sandbox; nothing from the package is
executed. Its own package risk label decides the severity of what it found,
because single rule hits fire on popular libraries (PyYAML's ``__import__``
is a "dynamic loader"). GuardDog still scores PyYAML ``high_risk``, so a
release older than :data:`TRUSTED_AGE_DAYS` is capped at low: the spec's
threat is a package published days ago, and malware does not survive on a
registry for a month. It is optional: when it is missing or a scan fails,
the report says so as a low finding and the verdict is otherwise unchanged.
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess  # nosemgrep: gitlab.bandit.B404 -- guarddog with a fixed argv list
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING
from urllib.parse import quote

from coldrun.vet.findings import Finding, Severity

if TYPE_CHECKING:
    from coldrun.runners.base import DepSet

#: DepSet ecosystems that are also guarddog subcommands.
ECOSYSTEMS = frozenset({"pypi", "npm", "go", "rubygems", "crates"})
INSTALL_HINT = "uv tool install guarddog"
TIMEOUT = 300
#: A release this old that still sits on the registry is a false positive, not malware.
TRUSTED_AGE_DAYS = 30
# name, optional [extras], optional ==pin; other specifiers scan the latest release
#: GuardDog's package risk label -> severity of every hit it reports for that package.
_LABELS = {
    "no_risks_detected": Severity.INFO,
    "low": Severity.LOW,
    "suspicious": Severity.MEDIUM,
    "high_risk": Severity.HIGH,
}
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
        age = release_age_days(deps.ecosystem, m.group(1), m.group(2))
        cap = Severity.LOW if age is not None and age > TRUSTED_AGE_DAYS else None
        out += scan_package(exe, deps.ecosystem, m.group(1), version=m.group(2), cap=cap)
    return out


def release_age_days(ecosystem: str, name: str, version: str | None) -> int | None:
    """Days since the pinned or latest release was uploaded; ``None`` when unknown."""
    # shortcut: PyPI only; npm/go/rubygems ages arrive with their runners (M5)
    if ecosystem != "pypi":
        return None
    path = "/".join(quote(part, safe="") for part in (name, version) if part)
    url = f"https://pypi.org/pypi/{path}/json"
    try:
        # nosemgrep -- the scheme and host are fixed and the path is quoted
        with urllib.request.urlopen(url, timeout=10) as resp:
            files = json.load(resp).get("urls", [])
        uploaded = max(f["upload_time_iso_8601"] for f in files)
    except (OSError, ValueError, KeyError, TypeError):
        return None
    when = datetime.fromisoformat(uploaded.replace("Z", "+00:00"))
    return (datetime.now(timezone.utc) - when).days


def scan_package(
    exe: str,
    ecosystem: str,
    target: str,
    *,
    version: str | None = None,
    cap: Severity | None = None,
) -> list[Finding]:
    """Scan one registry package or local directory and map the JSON to findings.

    ``cap`` is the highest severity a hit may get; see :data:`TRUSTED_AGE_DAYS`.
    """
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
    label = str(data.get("risk_score", {}).get("label", ""))
    for rule, hits in data.get("results", {}).items():
        sev = _severity(rule, label)
        if sev is None or not hits:
            continue
        if cap is not None and sev.rank > cap.rank:
            sev = cap
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


def _severity(rule: str, label: str) -> Severity | None:
    if rule.startswith("capability-") and rule != "capability-process-hooks":
        # shortcut: plain capability-* hits describe every library; show them once --verbose exists
        return None
    sev = _LABELS.get(label, Severity.HIGH)  # no or unknown package score: assume the worst
    if rule == "capability-process-hooks" and sev.rank < Severity.MEDIUM.rank:
        return Severity.MEDIUM  # install hooks always ask, whatever the package score
    return sev


def _failed(where: Path, why: str) -> Finding:
    return Finding("guarddog.failed", Severity.LOW, where, f"not vetted, guarddog failed: {why}")


def _one_line(value: object) -> str:
    return " ".join(str(value).split())[:120]


def _last_line(text: str) -> str:
    lines = text.strip().splitlines()
    return _one_line(lines[-1]) if lines else "unknown error"
