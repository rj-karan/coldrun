"""Script rules: Semgrep for Python semantics, YARA for text patterns in any language.

Both read the script and nothing more. Semgrep runs as a subprocess with a
fixed argument list; YARA runs through ``yara-python``. Both come from the
``vet`` extra and are optional: a missing tool or a failed scan is one low
finding, so "not vetted" is always visible.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess  # nosemgrep: gitlab.bandit.B404 -- semgrep with a fixed argv list
import sys
from pathlib import Path

from coldrun.vet.findings import Finding, Severity

try:
    import yara
except ImportError:  # pragma: no cover - the vet extra is installed for the tests
    yara = None

RULES = Path(__file__).resolve().parent.parent / "rules"
INSTALL_HINT = "uv tool install 'coldrun[vet]'"
TIMEOUT = 120
_SEVERITY = {"low": Severity.LOW, "medium": Severity.MEDIUM, "high": Severity.HIGH}


def semgrep_exe() -> str | None:
    """Semgrep from ``PATH`` or from coldrun's own environment (the ``vet`` extra)."""
    own = str(Path(sys.executable).parent)
    return shutil.which("semgrep", path=f"{own}{os.pathsep}{os.environ.get('PATH', '')}")


def yara_version() -> str | None:
    """The yara-python version, or ``None`` when it is not installed."""
    return None if yara is None else str(yara.__version__)


def scan_semgrep(path: Path, exe: str | None = None) -> list[Finding]:
    """Run the Semgrep rules on ``path`` (a file or a directory)."""
    exe = exe or semgrep_exe()
    if exe is None:
        return [_missing(path, "semgrep")]
    argv = [
        exe, "scan", "--config", str(RULES / "semgrep"), "--json", "--quiet", "--metrics=off",
        "--disable-version-check", "--scan-unknown-extensions", str(path),
    ]  # fmt: skip
    try:
        proc = subprocess.run(  # noqa: S603 - fixed argv of a known tool
            argv, capture_output=True, text=True, check=False, timeout=TIMEOUT
        )
        data = json.loads(proc.stdout)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return [_failed(path, "semgrep", str(exc))]
    except ValueError:
        last = (proc.stderr.strip() or "no output").splitlines()[-1]
        return [_failed(path, "semgrep", f"exit {proc.returncode}: {last}")]
    out = [_failed(path, "semgrep", str(e.get("message", "error"))) for e in data.get("errors", [])]
    for r in data.get("results", []):
        extra = r.get("extra", {})
        sev = _SEVERITY.get(str(extra.get("metadata", {}).get("severity")), Severity.MEDIUM)
        rule = str(r["check_id"]).rsplit(".", 1)[-1]
        out.append(
            Finding(
                f"semgrep.{rule}",
                sev,
                Path(r.get("path", path)),
                str(extra.get("message", rule)),
                line=r.get("start", {}).get("line"),
            )
        )
    return out


def scan_yara(path: Path) -> list[Finding]:
    """Run the YARA rules on one script; one finding per rule and matching line."""
    if yara is None:
        return [_missing(path, "yara-python")]
    rules = yara.compile(filepaths={p.stem: str(p) for p in (RULES / "yara").glob("*.yar")})
    data = path.read_bytes()
    out: list[Finding] = []
    for m in rules.match(data=data, timeout=30):
        sev = _SEVERITY.get(str(m.meta.get("severity")), Severity.MEDIUM)
        text = str(m.meta.get("description", m.rule))
        lines = sorted({data.count(b"\n", 0, i.offset) + 1 for s in m.strings for i in s.instances})
        out += [Finding(f"yara.{m.rule}", sev, path, text, line=ln) for ln in lines[:5]]
    return out


def _missing(path: Path, tool: str) -> Finding:
    msg = f"{tool} is not installed, so the script was not vetted. Fix: {INSTALL_HINT}"
    return Finding(f"{tool}.missing", Severity.LOW, path, msg)


def _failed(path: Path, tool: str, why: str) -> Finding:
    why = " ".join(why.split())[:160]
    return Finding(f"{tool}.failed", Severity.LOW, path, f"not fully vetted, {tool} failed: {why}")
