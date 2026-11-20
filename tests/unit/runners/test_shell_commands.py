from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from coldrun import distro, pipeline
from coldrun.pipeline import DepsError, install_hint
from coldrun.runners.shell import ShellRunner, commands_in, package_for

FX = Path(__file__).resolve().parents[2] / "fixtures" / "sh"


def test_commands_in_skips_builtins_assignments_wrappers_and_comments() -> None:
    text = (
        "#!/bin/bash\n"
        "set -euo pipefail  # strict\n"
        "TARGET=$1\n"
        'if [ -z "$TARGET" ]; then echo usage; exit 1; fi\n'
        'sudo nmap -sV "$TARGET" | tee out.txt && jq . < x.json\n'
        'for f in *.txt; do /usr/bin/wc -l "$f"; done\n'
        "result=$(curl -s http://x) || true\n"
        "env FOO=1 python3 x.py; time ./local.sh\n"
    )
    assert commands_in(text) == ["nmap", "tee", "jq", "wc", "curl", "python3", "local.sh"]


def test_commands_in_survives_unbalanced_quotes() -> None:
    assert commands_in("echo 'oops\ncurl x\n") == ["curl"]


def test_resolve_deps_lists_binaries() -> None:
    deps = ShellRunner().resolve_deps(FX / "jq_curl.sh")
    assert deps.system_binaries == ("curl", "cut", "head", "jq")
    assert deps.interpreter == "bash"
    assert deps.source == "commands"
    assert ShellRunner().resolve_deps(FX / "hello.sh").system_binaries == ()


@pytest.mark.parametrize(
    ("command", "family", "package"),
    [
        ("dig", "arch", "bind"),
        ("dig", "debian", "dnsutils"),
        ("dig", "fedora", "bind-utils"),
        ("dig", "alpine", "bind-tools"),
        ("nc", "suse", "netcat-openbsd"),
        ("go", "fedora", "golang"),
        ("go", "debian", "golang-go"),
        ("curl", "gentoo", "curl"),  # Arch's name where nothing differs
        ("jq", "alpine", "jq"),  # Debian's name where nothing differs
        ("mystery", "arch", None),
    ],
)
def test_package_for_each_family(command: str, family: str, package: str | None) -> None:
    assert package_for(command, family) == package


def test_missing_binary_is_exit_102_with_install_hint(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    script = tmp_path / "s.sh"
    script.write_text("#!/bin/sh\nnmap x\nmystery y\n")
    monkeypatch.setattr(shutil, "which", lambda name: None)
    monkeypatch.setattr(distro, "family", lambda: "arch")
    with pytest.raises(DepsError) as exc:
        pipeline._resolve(ShellRunner(), script)
    assert "mystery, nmap" in exc.value.what
    assert exc.value.hint == "sudo pacman -S nmap; no known package for: mystery."
    assert exc.value.exit_code == 102


@pytest.mark.parametrize(
    ("family", "hint"),
    [
        ("debian", "sudo apt install dnsutils."),
        ("fedora", "sudo dnf install bind-utils."),
        ("alpine", "sudo apk add bind-tools."),
        ("unknown", "install dnsutils with your package manager."),
    ],
)
def test_install_hint_per_family_and_dedup(
    monkeypatch: pytest.MonkeyPatch, family: str, hint: str
) -> None:
    monkeypatch.setattr(distro, "family", lambda: family)
    assert install_hint(["dig", "host"]) == hint
