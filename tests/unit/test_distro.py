from __future__ import annotations

from pathlib import Path

import pytest

from coldrun import distro


@pytest.mark.parametrize(
    ("text", "family", "name"),
    [
        ('NAME="Omarchy"\nID=omarchy\nID_LIKE=arch\n', "arch", "Omarchy"),
        (
            'PRETTY_NAME="Kali GNU/Linux Rolling"\nID=kali\nID_LIKE=debian\n',
            "debian",
            "Kali GNU/Linux Rolling",
        ),
        (
            'PRETTY_NAME="Ubuntu 24.04 LTS"\nID=ubuntu\nID_LIKE=debian\n',
            "debian",
            "Ubuntu 24.04 LTS",
        ),
        (
            'PRETTY_NAME="Rocky Linux 9.4"\nID="rocky"\nID_LIKE="rhel centos fedora"\n',
            "fedora",
            "Rocky Linux 9.4",
        ),
        ("ID=fedora\n", "fedora", "Linux"),
        ('ID="opensuse-tumbleweed"\nID_LIKE="opensuse suse"\n', "suse", "Linux"),
        ("ID=alpine\nNAME='Alpine Linux'\n", "alpine", "Alpine Linux"),
        ("ID=void\n", "void", "Linux"),
        ("ID=gentoo\n", "gentoo", "Linux"),
        ("ID=nixos\n", "nixos", "Linux"),
        ("ID=slackware\n", "unknown", "Linux"),
    ],
)
def test_describe(tmp_path: Path, text: str, family: str, name: str) -> None:
    rel = tmp_path / "os-release"
    rel.write_text(text)
    assert distro.describe(rel) == (family, name)
    assert distro.family(rel) == family


def test_missing_os_release(tmp_path: Path) -> None:
    assert distro.describe(tmp_path / "missing") == ("unknown", "unknown Linux")


def test_install_command(monkeypatch: pytest.MonkeyPatch) -> None:
    assert distro.install_command(["bubblewrap"], "suse") == "sudo zypper install bubblewrap"
    assert distro.install_command(["a", "b", "a"], "void") == "sudo xbps-install a b"
    assert distro.install_command(["x"], "nixos") == "nix-shell -p x"
    assert distro.install_command(["x"], "unknown") == "install x with your package manager"
    monkeypatch.setattr(distro, "family", lambda: "gentoo")
    assert distro.install_command(["bubblewrap"]) == "sudo emerge bubblewrap"
