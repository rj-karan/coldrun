"""Python 2 runner: same dependency sources as Python 3, run in a pinned Python 2.7 image.

Old exploits are often Python 2. The host has no Python 2, so this runner
ships an image and runs on the Podman backend. ``ast`` cannot read Python 2,
so imports are read line by line. pip inside the image honours each
package's ``Requires-Python`` and picks the last release that supports 2.7.
"""

from __future__ import annotations

import ast
import re
import sys
from typing import TYPE_CHECKING

from coldrun.detect import interpreter_from_shebang, read_shebang
from coldrun.runners.base import GUEST_DEPS_DIR, DepSet
from coldrun.runners.python import IMPORT_TO_DIST, PythonRunner

if TYPE_CHECKING:
    from pathlib import Path

IMAGE = (
    "docker.io/library/python:2.7.18-slim"
    "@sha256:6c1ffdff499e29ea663e6e67c9b6b9a3b401d554d2c9f061f9a45344e3992363"
)
_PY2_SHEBANG = re.compile(r"^python2(\.\d+)?$")
#: Syntax only Python 2 accepts; any of these plus a failed Python 3 parse means Python 2.
_PY2_SYNTAX = re.compile(
    r"^\s*print\s+[^\s(=]|^\s*print\s*>>|^\s*except\s+[\w.]+\s*,\s*\w+\s*:|^\s*exec\s+['\"\w]",
    re.MULTILINE,
)
_PRINT_CHEVRON = re.compile(r"^\s*print\s*>>", re.MULTILINE)
_IMPORT = re.compile(
    r"^\s*import\s+([\w.]+(?:\s+as\s+\w+)?(?:\s*,\s*[\w.]+(?:\s+as\s+\w+)?)*)", re.MULTILINE
)
_FROM = re.compile(r"^\s*from\s+(\w[\w.]*)\s+import\b", re.MULTILINE)
#: Python 2 standard library names that Python 3 renamed or removed.
PY2_STDLIB = frozenset(
    " ".join(
        (
            "BaseHTTPServer CGIHTTPServer ConfigParser Cookie Queue SimpleHTTPServer",
            "SocketServer StringIO Tkinter UserDict UserList UserString __builtin__ anydbm",
            "commands cPickle cStringIO cookielib copy_reg dbhash dumbdbm dummy_thread",
            "exceptions htmlentitydefs htmllib httplib md5 mimetools mimetypes new popen2",
            "repr rfc822 robotparser sets sgmllib sha thread urllib2 urlparse whichdb",
            "xmlrpclib",
        )
    ).split()
)


class Python2Runner(PythonRunner):
    """Python 2.7 scripts, in a container image."""

    name = "python2"
    interpreter = "python2"
    image = IMAGE

    def detect(self, path: Path) -> float:
        """A python2 shebang is certain; Python 2-only syntax beats the Python 3 runner."""
        shebang = read_shebang(path)
        interp = interpreter_from_shebang(shebang) if shebang else None
        if interp and _PY2_SHEBANG.match(interp):
            return 1.0
        if shebang is not None and interp != "python":
            return 0.0
        if shebang is None and path.suffix.lower() != ".py":
            return 0.0
        text = path.read_text(encoding="utf-8", errors="replace")
        try:
            ast.parse(text)
        except SyntaxError:
            return 0.95 if _PY2_SYNTAX.search(text) else 0.0
        # `print >>f, x` parses as a Python 3 expression, but only Python 2 code writes it
        return 0.95 if _PRINT_CHEVRON.search(text) else 0.0

    def _imports(self, text: str, beside: Path) -> list[str]:
        names = [m.split(" as ")[0].strip() for g in _IMPORT.findall(text) for m in g.split(",")]
        names += _FROM.findall(text)
        out: set[str] = set()
        for dotted in names:
            top = dotted.split(".")[0]
            if top in sys.stdlib_module_names or top in PY2_STDLIB or top == "__future__":
                continue
            if (beside / f"{top}.py").exists() or (beside / top).is_dir():
                continue
            out.add(IMPORT_TO_DIST.get(dotted) or IMPORT_TO_DIST.get(top) or top)
        return sorted(out)

    def install_cmd(self, deps: DepSet) -> list[str]:
        """The image's pip into the cached environment; network is registry-only."""
        if not deps.packages:
            return []
        return [
            "python", "-m", "pip", "install", "--quiet", "--no-cache-dir",
            "--disable-pip-version-check", "--no-warn-script-location",
            "--target", GUEST_DEPS_DIR, *deps.packages,
        ]  # fmt: skip

    def run_cmd(self, path: Path, args: list[str]) -> list[str]:
        """The image's Python 2 with the installed packages on ``PYTHONPATH``."""
        return [
            "/usr/bin/env", f"PYTHONPATH={GUEST_DEPS_DIR}", "PYTHONDONTWRITEBYTECODE=1",
            "python", str(path), *args,
        ]  # fmt: skip
