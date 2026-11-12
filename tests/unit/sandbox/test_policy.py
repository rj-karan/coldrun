from __future__ import annotations

from pathlib import Path

import pytest

from coldrun.sandbox import NetPolicy, Policy, PolicyError, scrub_env
from coldrun.sandbox.base import ENV_FIXED, WORKDIR, check_rw_path


def mkpolicy(tmp_path: Path, **kw: object) -> Policy:
    script = tmp_path / "q" / "tool.sh"
    script.parent.mkdir(exist_ok=True)
    script.write_text("echo\n")
    scratch = tmp_path / "scratch"
    scratch.mkdir(exist_ok=True)
    return Policy(script=script, scratch=scratch, **kw)  # type: ignore[arg-type]


def test_defaults_are_deny(tmp_path: Path) -> None:
    p = mkpolicy(tmp_path)
    assert p.net is NetPolicy.NONE
    assert p.rw_paths == ()
    assert p.ro_paths == ()
    assert p.tty is False
    assert p.guest_script == f"{WORKDIR}/tool.sh"


def test_relative_paths_are_rejected(tmp_path: Path) -> None:
    with pytest.raises(PolicyError, match="absolute"):
        Policy(script=Path("tool.sh"), scratch=tmp_path)
    with pytest.raises(PolicyError, match="absolute"):
        Policy(script=tmp_path / "t", scratch=Path("rel"))
    with pytest.raises(PolicyError, match="read-only path must be absolute"):
        mkpolicy(tmp_path, ro_paths=(Path("venv"),))


@pytest.mark.parametrize("bad", ["/", "~"])
def test_rw_root_and_home_are_forbidden(
    bad: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("HOME", str(tmp_path))
    path = tmp_path if bad == "~" else Path("/")
    with pytest.raises(PolicyError, match="whole filesystem or home"):
        check_rw_path(path)


@pytest.mark.parametrize(
    "name", [".ssh", ".gnupg", ".aws", ".config", ".kube", ".docker", ".mozilla"]
)
def test_rw_credential_dirs_are_forbidden(name: str, tmp_path: Path) -> None:
    d = tmp_path / name / "sub"
    d.mkdir(parents=True)
    with pytest.raises(PolicyError, match="credential or configuration"):
        check_rw_path(d)


def test_rw_symlink_into_credentials_is_caught(tmp_path: Path) -> None:
    secret = tmp_path / ".ssh"
    secret.mkdir()
    link = tmp_path / "innocent"
    link.symlink_to(secret)
    with pytest.raises(PolicyError, match="credential"):
        check_rw_path(link)


def test_rw_must_exist_and_be_absolute(tmp_path: Path) -> None:
    with pytest.raises(PolicyError, match="does not exist"):
        check_rw_path(tmp_path / "nope")
    with pytest.raises(PolicyError, match="must be absolute"):
        check_rw_path(Path("out"))


def test_rw_ordinary_dir_is_accepted(tmp_path: Path) -> None:
    d = tmp_path / "loot"
    d.mkdir()
    p = mkpolicy(tmp_path, rw_paths=(d,))
    assert p.rw_paths == (d,)


def test_scrub_env_drops_everything_not_allowlisted() -> None:
    host = {
        "PATH": "/home/me/.local/bin:/usr/bin",
        "HOME": "/home/me",
        "AWS_SECRET_ACCESS_KEY": "x",
        "SSH_AUTH_SOCK": "/run/user/1000/ssh",
        "DBUS_SESSION_BUS_ADDRESS": "unix:path=/run/user/1000/bus",
        "GITHUB_TOKEN": "ghp_x",
        "TERM": "xterm-256color",
        "LANG": "en_GB.UTF-8",
        "LC_ALL": "C.UTF-8",
        "NO_COLOR": "1",
        "TZ": "Asia/Kolkata",
    }
    env = scrub_env(host)
    assert env["PATH"] == ENV_FIXED["PATH"]
    assert env["HOME"] == WORKDIR
    assert env["TMPDIR"] == "/tmp"  # noqa: S108 - guest path
    assert env["USER"] == "coldrun"
    assert env["TERM"] == "xterm-256color"
    assert env["LANG"] == "en_GB.UTF-8"
    assert env["LC_ALL"] == "C.UTF-8"
    assert env["NO_COLOR"] == "1"
    assert env["TZ"] == "Asia/Kolkata"
    for secret in (
        "AWS_SECRET_ACCESS_KEY",
        "SSH_AUTH_SOCK",
        "DBUS_SESSION_BUS_ADDRESS",
        "GITHUB_TOKEN",
    ):
        assert secret not in env


def test_scrub_env_extra_layers_but_cannot_move_home_or_path() -> None:
    env = scrub_env({}, {"PYTHONUNBUFFERED": "1", "HOME": WORKDIR})
    assert env["PYTHONUNBUFFERED"] == "1"
    for name in ("HOME", "TMPDIR", "PATH"):
        with pytest.raises(PolicyError, match=f"override of {name}"):
            scrub_env({}, {name: "/elsewhere"})
