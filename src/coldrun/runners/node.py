"""Node runner: dependencies from package.json or require/import statements; npm installs.

Uses the system Node in ``/usr/bin``: a version manager's Node lives in the home
directory, which the sandbox hides. Packages install with ``--ignore-scripts``
into the cached environment, so no install hook runs, and the script finds
them through ``NODE_PATH``.
"""

from __future__ import annotations

import json
import re
from typing import TYPE_CHECKING

from coldrun.runners.base import GUEST_DEPS_DIR, DepSet, detect_by

if TYPE_CHECKING:
    from pathlib import Path

    from coldrun.vet.findings import Finding

NODE = "/usr/bin/node"
NPM = "/usr/bin/npm"
_IMPORT = re.compile(
    r"""require\(\s*['"]([^'"]+)['"]\s*\)"""
    r"""|\bfrom\s*['"]([^'"]+)['"]"""
    r"""|\bimport\s*\(?\s*['"]([^'"]+)['"]"""
)
#: ``require('module').builtinModules`` of Node 22, without the ``node:``-only ones.
BUILTINS = frozenset(
    [
        "assert",
        "async_hooks",
        "buffer",
        "child_process",
        "cluster",
        "console",
        "constants",
        "crypto",
        "dgram",
        "diagnostics_channel",
        "dns",
        "domain",
        "events",
        "fs",
        "http",
        "http2",
        "https",
        "inspector",
        "module",
        "net",
        "os",
        "path",
        "perf_hooks",
        "process",
        "punycode",
        "querystring",
        "readline",
        "repl",
        "stream",
        "string_decoder",
        "sys",
        "timers",
        "tls",
        "trace_events",
        "tty",
        "url",
        "util",
        "v8",
        "vm",
        "wasi",
        "worker_threads",
        "zlib",
    ]
)


class NodeRunner:
    """Detect, resolve, install and run Node scripts."""

    name = "node"

    def detect(self, path: Path) -> float:
        """A node shebang is certain; a JavaScript extension alone is likely."""
        return detect_by(
            path, frozenset({"node", "nodejs"}), {".js": 0.8, ".mjs": 0.9, ".cjs": 0.9}
        )

    def resolve_deps(self, path: Path) -> DepSet:
        """``package.json`` beside the script, else the packages it requires or imports."""
        manifest = path.parent / "package.json"
        if manifest.is_file():
            deps = json.loads(manifest.read_text()).get("dependencies") or {}
            pkgs = tuple(f"{name}@{ver}" for name, ver in deps.items())
            source = "package.json"
        else:
            pkgs = tuple(_packages(path.read_text(encoding="utf-8", errors="replace")))
            source = "inferred"
        bins = (NODE, NPM) if pkgs else (NODE,)
        return DepSet("npm", pkgs, bins, "node", source)

    def install_cmd(self, deps: DepSet) -> list[str]:
        """``npm install`` into the deps dir, never running package scripts."""
        if not deps.packages:
            return []
        return [
            "/usr/bin/env", "npm_config_cache=/tmp/npm-cache", "npm_config_update_notifier=false",
            NPM, "install", "--no-audit", "--no-fund", "--ignore-scripts",
            "--prefix", GUEST_DEPS_DIR, *deps.packages,
        ]  # fmt: skip

    def run_cmd(self, path: Path, args: list[str]) -> list[str]:
        """Run with the installed packages on ``NODE_PATH``."""
        # shortcut: NODE_PATH serves require(); an ESM `import` of a package is not found, upgrade
        # with a /node_modules mount if ESM scripts with dependencies show up
        return ["/usr/bin/env", f"NODE_PATH={GUEST_DEPS_DIR}/node_modules", NODE, str(path), *args]

    def vet(self, path: Path, deps: DepSet) -> list[Finding]:
        """The YARA rules read JavaScript too; nothing Node-specific yet."""
        return []


def _packages(text: str) -> list[str]:
    """Npm package names for every bare specifier; relative paths and builtins are skipped."""
    out: set[str] = set()
    for m in _IMPORT.finditer(text):
        spec = next(g for g in m.groups() if g)
        if spec.startswith((".", "/", "node:")):
            continue
        parts = spec.split("/")
        name = "/".join(parts[:2]) if spec.startswith("@") else parts[0]
        if name not in BUILTINS:
            out.add(name)
    return sorted(out)
