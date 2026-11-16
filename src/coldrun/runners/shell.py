"""POSIX shell and Bash runner.

Commands the script invokes become ``system_binaries``; the pipeline checks
they exist on the host (bubblewrap binds the host's ``/usr``) and names the
distro package for anything missing. Nothing is installed: distro packages
need root, and the Podman backend (#30) is where images with extra tools land.
"""

from __future__ import annotations

import re
import shlex
from typing import TYPE_CHECKING

from coldrun.detect import interpreter_from_shebang, read_shebang
from coldrun.runners.base import DepSet

if TYPE_CHECKING:
    from pathlib import Path

    from coldrun.vet.findings import Finding

_SHELLS = {
    "sh": "/bin/sh",
    "bash": "/bin/bash",
    "dash": "/bin/dash",
    "ksh": "/bin/ksh",
    "zsh": "/bin/zsh",
}
_EXTENSIONS = {".sh": 0.8, ".bash": 0.9}
#: Builtins and keywords that own the rest of their segment.
_BUILTINS = frozenset(
    [
        "for",
        "case",
        "select",
        "function",
        "fi",
        "done",
        "esac",
        "in",
        "echo",
        "printf",
        "cd",
        "export",
        "source",
        ".",
        "[",
        "[[",
        "test",
        "read",
        "exit",
        "return",
        "local",
        "set",
        "shift",
        "unset",
        "true",
        "false",
        "eval",
        "trap",
        "wait",
        "break",
        "continue",
        "let",
        "declare",
        "typeset",
        "readonly",
        "pushd",
        "popd",
        "alias",
        "getopts",
        "hash",
        "type",
        "ulimit",
        "umask",
        "kill",
        "jobs",
        "bg",
        "fg",
    ]
)
#: Keywords and wrappers whose next word is the real command.
_PRECEDERS = frozenset(
    [
        "if",
        "then",
        "else",
        "elif",
        "do",
        "while",
        "until",
        "!",
        "{",
        "}",
        "sudo",
        "doas",
        "time",
        "command",
        "env",
        "nohup",
        "nice",
        "exec",
        "xargs",
    ]
)
_SPLIT = re.compile(r"\|\||&&|[|;&]|\$\(|`|\(|\)")
#: command -> (arch package, debian package); extend as scripts meet them.
PACKAGES: dict[str, tuple[str, str]] = {
    "jq": ("jq", "jq"),
    "curl": ("curl", "curl"),
    "wget": ("wget", "wget"),
    "nmap": ("nmap", "nmap"),
    "nc": ("gnu-netcat", "netcat-openbsd"),
    "ncat": ("nmap", "ncat"),
    "socat": ("socat", "socat"),
    "dig": ("bind", "dnsutils"),
    "nslookup": ("bind", "dnsutils"),
    "host": ("bind", "dnsutils"),
    "whois": ("whois", "whois"),
    "tcpdump": ("tcpdump", "tcpdump"),
    "openssl": ("openssl", "openssl"),
    "git": ("git", "git"),
    "python3": ("python", "python3"),
    "python": ("python", "python3"),
    "perl": ("perl", "perl"),
    "ruby": ("ruby", "ruby"),
    "node": ("nodejs", "nodejs"),
    "gcc": ("gcc", "gcc"),
    "make": ("make", "make"),
    "unzip": ("unzip", "unzip"),
    "7z": ("p7zip", "p7zip-full"),
    "sqlmap": ("sqlmap", "sqlmap"),
    "hydra": ("hydra", "hydra"),
    "john": ("john", "john"),
    "hashcat": ("hashcat", "hashcat"),
    "gobuster": ("gobuster", "gobuster"),
    "ffuf": ("ffuf", "ffuf"),
    "nikto": ("nikto", "nikto"),
    "smbclient": ("smbclient", "smbclient"),
    "ssh": ("openssh", "openssh-client"),
    "xxd": ("tinyxxd", "xxd"),
    "strings": ("binutils", "binutils"),
    "file": ("file", "file"),
    "base64": ("coreutils", "coreutils"),
}


def commands_in(text: str) -> list[str]:
    """External command names a shell script invokes, in first-seen order.

    shortcut: a tokenizer, not a parser; heredocs and quoted command strings
    are read as plain words. Upgrade to bashlex if false positives bite.
    """
    seen: dict[str, None] = {}
    for raw in text.splitlines():
        line = raw.split("#", 1)[0] if not raw.lstrip().startswith("#!") else ""
        for segment in _SPLIT.split(line):
            try:
                words = shlex.split(segment, comments=False)
            except ValueError:
                continue
            for word in words:
                if word in _PRECEDERS or word.startswith("-") or ("=" in word and word[0] != "-"):
                    continue  # keyword, wrapper, flag or VAR=value prefix
                name = word.rsplit("/", 1)[-1]
                if name and name not in _BUILTINS and not name.startswith(("$", "{", "(")):
                    seen.setdefault(name, None)
                break
    return list(seen)


def package_for(command: str, distro: str) -> str | None:
    """Distro package that provides ``command``, or ``None`` when unknown."""
    pair = PACKAGES.get(command)
    if pair is None:
        return None
    return pair[0] if distro == "arch" else pair[1]


class ShellRunner:
    """Run ``sh`` and ``bash`` scripts with the interpreter their shebang names."""

    name = "sh"

    def detect(self, path: Path) -> float:
        """A shell shebang is certain; a shell extension alone is likely."""
        shebang = read_shebang(path)
        interp = interpreter_from_shebang(shebang) if shebang else None
        if interp in _SHELLS:
            return 1.0
        if shebang is not None:
            return 0.0  # some other interpreter owns it
        return _EXTENSIONS.get(path.suffix.lower(), 0.0)

    def resolve_deps(self, path: Path) -> DepSet:
        """Interpreter from the shebang, system binaries from the commands used."""
        text = path.read_text(encoding="utf-8", errors="replace")
        binaries = tuple(c for c in commands_in(text) if c not in _SHELLS)
        return DepSet(
            interpreter=self._interpreter(path), system_binaries=binaries, source="commands"
        )

    def install_cmd(self, deps: DepSet) -> list[str]:
        """Nothing to install for plain shell scripts."""
        return []

    def run_cmd(self, path: Path, args: list[str]) -> list[str]:
        """Run with the shebang's shell, falling back to ``/bin/sh``."""
        return [_SHELLS[self._interpreter(path)], str(path), *args]

    def vet(self, path: Path, deps: DepSet) -> list[Finding]:
        """Shell-specific rules arrive with the vetting milestone."""
        return []

    @staticmethod
    def _interpreter(path: Path) -> str:
        shebang = read_shebang(path) if path.exists() else None
        interp = interpreter_from_shebang(shebang) if shebang else None
        return interp if interp in _SHELLS else "sh"
