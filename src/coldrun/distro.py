"""Which Linux family this is, and how its users install a package.

Read from ``/etc/os-release``: ``ID`` first, then each ``ID_LIKE`` entry, so a
derivative (Kali, Rocky, Manjaro) lands in its parent's family.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Sequence

OS_RELEASE = Path("/etc/os-release")
#: os-release ID or ID_LIKE value -> family
FAMILIES = {
    **dict.fromkeys(("arch", "manjaro", "endeavouros", "cachyos", "artix", "garuda"), "arch"),
    **dict.fromkeys(
        ("debian", "ubuntu", "kali", "linuxmint", "pop", "raspbian", "elementary", "zorin"),
        "debian",
    ),
    **dict.fromkeys(
        ("fedora", "rhel", "centos", "rocky", "almalinux", "ol", "amzn", "nobara"), "fedora"
    ),
    **dict.fromkeys(("opensuse", "opensuse-tumbleweed", "opensuse-leap", "suse", "sles"), "suse"),
    "alpine": "alpine",
    "void": "void",
    "gentoo": "gentoo",
    "nixos": "nixos",
}
#: family -> the command that installs packages
INSTALLERS = {
    "arch": "sudo pacman -S",
    "debian": "sudo apt install",
    "fedora": "sudo dnf install",
    "suse": "sudo zypper install",
    "alpine": "sudo apk add",
    "void": "sudo xbps-install",
    "gentoo": "sudo emerge",
    "nixos": "nix-shell -p",
}


def describe(os_release: Path = OS_RELEASE) -> tuple[str, str]:
    """``(family, pretty name)``; the family is ``unknown`` when nothing matches."""
    try:
        text = os_release.read_text()
    except OSError:
        return "unknown", "unknown Linux"
    fields = dict(re.findall(r'^([A-Z_]+)=["\']?([^"\'\n]*)', text, flags=re.MULTILINE))
    ids = [fields.get("ID", ""), *fields.get("ID_LIKE", "").split()]
    family = next((FAMILIES[i] for i in ids if i in FAMILIES), "unknown")
    return family, fields.get("PRETTY_NAME") or fields.get("NAME") or "Linux"


def family(os_release: Path = OS_RELEASE) -> str:
    """The family of this machine: arch, debian, fedora, suse, alpine, void, gentoo or nixos."""
    return describe(os_release)[0]


def install_command(packages: Sequence[str], fam: str | None = None) -> str:
    """The command a user of ``fam`` (this machine by default) runs to get ``packages``."""
    fam = fam or family()
    names = " ".join(dict.fromkeys(packages))
    if fam not in INSTALLERS:
        return f"install {names} with your package manager"
    return f"{INSTALLERS[fam]} {names}"
