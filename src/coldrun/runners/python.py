"""Python 3 runner: dependencies from PEP 723, requirements.txt or imports; installed with uv.

Only ``ast.parse`` touches the script. Packages are installed inside the
sandbox into ``/work/.coldrun/deps`` and the script runs with that on
``PYTHONPATH``, so no venv has to survive the sandbox boundary.
"""

from __future__ import annotations

import ast
import re
import sys
from typing import TYPE_CHECKING

from coldrun.detect import interpreter_from_shebang, read_shebang
from coldrun.runners.base import GUEST_DEPS_DIR, DepSet
from coldrun.vet.engine import scan_semgrep

if TYPE_CHECKING:
    from pathlib import Path

    from coldrun.vet.findings import Finding

if sys.version_info >= (3, 11):
    import tomllib
else:  # pragma: no cover - exercised on the 3.10 CI job
    import tomli as tomllib  # type: ignore[import-not-found,no-redef,unused-ignore]

_PEP723 = re.compile(r"^# /// script\s*$(.*?)^# ///\s*$", re.MULTILINE | re.DOTALL)
_PY_SHEBANG = re.compile(r"^python(3(\.\d+)?)?$")
#: Import name -> distribution name where they differ. Extend as runners meet them.
IMPORT_TO_DIST = {
    "bs4": "beautifulsoup4",
    "yaml": "PyYAML",
    "PIL": "Pillow",
    "cv2": "opencv-python",
    "sklearn": "scikit-learn",
    "Crypto": "pycryptodome",
    "Cryptodome": "pycryptodomex",
    "dns": "dnspython",
    "nmap": "python-nmap",
    "pwn": "pwntools",
    "dateutil": "python-dateutil",
    "jwt": "PyJWT",
    "serial": "pyserial",
    "usb": "pyusb",
    "websocket": "websocket-client",
    "OpenSSL": "pyOpenSSL",
    "ldap": "python-ldap",
    "magic": "python-magic",
    "docx": "python-docx",
    "pptx": "python-pptx",
    "Levenshtein": "python-Levenshtein",
    "gi": "PyGObject",
    "wx": "wxPython",
    "attr": "attrs",
    "google.protobuf": "protobuf",
}


class PythonRunner:
    """Detect, resolve, install and run Python 3 scripts."""

    name = "python"
    interpreter = "python3"

    def detect(self, path: Path) -> float:
        """A python3 shebang is certain; a bare ``python`` one or ``.py`` alone is likely."""
        shebang = read_shebang(path)
        interp = interpreter_from_shebang(shebang) if shebang else None
        if interp and _PY_SHEBANG.match(interp):
            return 0.9 if interp == "python" else 1.0  # bare python may be Python 2 code
        if shebang is not None:
            return 0.0
        return 0.8 if path.suffix.lower() == ".py" else 0.0

    def resolve_deps(self, path: Path) -> DepSet:
        """PEP 723 block, then ``requirements.txt`` beside the script, else imports."""
        text = path.read_text(encoding="utf-8", errors="replace")
        if m := _PEP723.search(text):
            body = "\n".join(
                line[2:] if line.startswith("# ") else line[1:] for line in m.group(1).splitlines()
            )
            pkgs = tomllib.loads(body).get("dependencies", [])
            return DepSet("pypi", tuple(pkgs), (), self.interpreter, "PEP 723")
        req = path.parent / "requirements.txt"
        if req.is_file():
            lines = (ln.split("#", 1)[0].strip() for ln in req.read_text().splitlines())
            pkgs = tuple(ln for ln in lines if ln and not ln.startswith("-"))
            return DepSet("pypi", pkgs, (), self.interpreter, "requirements.txt")
        pkgs = tuple(self._imports(text, path.parent))
        return DepSet("pypi", pkgs, (), self.interpreter, "inferred")

    def _imports(self, text: str, beside: Path) -> list[str]:
        return _third_party_imports(text, beside)

    def install_cmd(self, deps: DepSet) -> list[str]:
        """``uv pip install --target`` into the deps dir; empty when nothing is needed."""
        if not deps.packages:
            return []
        # shortcut: requires-python ignored, host python3 used; upgrade with the env cache (#18)
        return [
            "/usr/bin/env", "UV_CACHE_DIR=/tmp/uv-cache", "uv", "pip", "install", "--quiet",
            "--python", "/usr/bin/python3", "--target", GUEST_DEPS_DIR, *deps.packages,
        ]  # fmt: skip

    def run_cmd(self, path: Path, args: list[str]) -> list[str]:
        """Run with the host interpreter and the installed deps on ``PYTHONPATH``."""
        return [
            "/usr/bin/env",
            f"PYTHONPATH={GUEST_DEPS_DIR}",
            "PYTHONDONTWRITEBYTECODE=1",
            "/usr/bin/python3",
            str(path),
            *args,
        ]

    def vet(self, path: Path, deps: DepSet) -> list[Finding]:
        """Semgrep rules for Python; the text-level YARA rules run for every language."""
        return scan_semgrep(path)


def _third_party_imports(text: str, beside: Path) -> list[str]:
    """Distribution names for imports that are neither stdlib nor files next to the script."""
    try:
        tree = ast.parse(text)
    except SyntaxError:
        return []
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module and not node.level:
            names.add(node.module)
    out: set[str] = set()
    for dotted in names:
        top = dotted.split(".")[0]
        if top in sys.stdlib_module_names or top == "__main__":
            continue
        if (beside / f"{top}.py").exists() or (beside / top).is_dir():
            continue
        out.add(IMPORT_TO_DIST.get(dotted) or IMPORT_TO_DIST.get(top) or top)
    return sorted(out)
