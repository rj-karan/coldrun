"""Ruby runner: dependencies from a Gemfile or require statements; gems installed with gem.

Uses the system Ruby in ``/usr/bin``. Gems install into the cached environment
(``GEM_HOME``); Ruby's default and bundled gems stay visible because
``GEM_PATH`` is left alone. Native extensions build inside the sandbox.
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

from coldrun.runners.base import GUEST_DEPS_DIR, DepSet, detect_by

if TYPE_CHECKING:
    from pathlib import Path

    from coldrun.vet.findings import Finding

RUBY = "/usr/bin/ruby"
GEM = "/usr/bin/gem"
_REQUIRE = re.compile(r"""^\s*require\s*\(?\s*['"]([^'"]+)['"]""", re.MULTILINE)
_GEMFILE = re.compile(r"""^\s*gem\s+['"]([\w.-]+)['"]""", re.MULTILINE)
#: Libraries that ship with Ruby (default gems and the standard library).
STDLIB = frozenset(
    " ".join(
        (
            "English abbrev base64 benchmark bigdecimal cgi coverage csv date delegate",
            "did_you_mean",
            "digest drb erb etc fcntl fiddle fileutils find forwardable getoptlong io ipaddr irb",
            "json logger matrix monitor mutex_m net objspace observer open-uri open3 openssl",
            "optparse ostruct pathname pp prettyprint prime pstore psych racc rdoc readline",
            "reline resolv ripper securerandom set shellwords singleton socket stringio strscan",
            "syslog tempfile time timeout tmpdir tsort un uri weakref yaml zlib",
        )
    ).split()
)
#: require name -> gem name where they differ.
REQUIRE_TO_GEM = {
    "active_support": "activesupport",
    "net/ssh": "net-ssh",
    "net/scp": "net-scp",
    "net/sftp": "net-sftp",
    "net/smtp": "net-smtp",
    "net/http/persistent": "net-http-persistent",
    "http": "http",
    "pry": "pry",
    "rest-client": "rest-client",
    "rest_client": "rest-client",
    "msfrpc-client": "msfrpc-client",
}


class RubyRunner:
    """Detect, resolve, install and run Ruby scripts."""

    name = "ruby"

    def detect(self, path: Path) -> float:
        """A ruby shebang is certain; ``.rb`` alone is likely."""
        return detect_by(path, frozenset({"ruby"}), {".rb": 0.8})

    def resolve_deps(self, path: Path) -> DepSet:
        """``Gemfile`` beside the script, else the gems behind its ``require`` lines."""
        manifest = path.parent / "Gemfile"
        if manifest.is_file():
            # shortcut: names only, version constraints and groups are ignored; use bundler later
            pkgs = tuple(_GEMFILE.findall(manifest.read_text()))
            source = "Gemfile"
        else:
            pkgs = tuple(_gems(path.read_text(encoding="utf-8", errors="replace")))
            source = "inferred"
        bins = (RUBY, GEM) if pkgs else (RUBY,)
        return DepSet("rubygems", pkgs, bins, "ruby", source)

    def install_cmd(self, deps: DepSet) -> list[str]:
        """``gem install`` into the cached environment over registry-only network."""
        if not deps.packages:
            return []
        return [
            "/usr/bin/env", f"GEM_HOME={GUEST_DEPS_DIR}",
            GEM, "install", "--no-document", "--quiet", "--install-dir", GUEST_DEPS_DIR,
            *deps.packages,
        ]  # fmt: skip

    def run_cmd(self, path: Path, args: list[str]) -> list[str]:
        """Run with the cached gems added to Ruby's own gem path."""
        return ["/usr/bin/env", f"GEM_HOME={GUEST_DEPS_DIR}", RUBY, str(path), *args]

    def vet(self, path: Path, deps: DepSet) -> list[Finding]:
        """The YARA rules read Ruby too; nothing Ruby-specific yet."""
        return []


def _gems(text: str) -> list[str]:
    """Gem names for every ``require`` that is not the standard library."""
    out: set[str] = set()
    for name in _REQUIRE.findall(text):
        if name in REQUIRE_TO_GEM:
            out.add(REQUIRE_TO_GEM[name])
        elif name.split("/")[0] not in STDLIB and not name.startswith("."):
            out.add(name.split("/")[0])
    return sorted(out)
