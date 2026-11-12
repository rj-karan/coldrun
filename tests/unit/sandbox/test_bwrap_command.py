from __future__ import annotations

import itertools
import shutil
import subprocess
from pathlib import Path

import pytest

from coldrun.sandbox import BwrapBackend, NetPolicy, SandboxError
from coldrun.sandbox import bwrap as bw
from coldrun.sandbox.base import WORKDIR
from tests.unit.sandbox.test_policy import mkpolicy

FAKE_BWRAP = "/opt/fake/bwrap"


def backend() -> BwrapBackend:
    return BwrapBackend(
        bwrap=FAKE_BWRAP, environ={"TERM": "dumb", "SECRET": "x"}, uid=1000, gid=1000
    )


def pairs(cmd: list[str], flag: str) -> list[tuple[str, str]]:
    """Values of a two-argument flag such as --ro-bind SRC DST."""
    return [(cmd[i + 1], cmd[i + 2]) for i, a in enumerate(cmd) if a == flag]


def single(cmd: list[str], flag: str) -> list[str]:
    """Values of a one-argument flag such as --hostname NAME."""
    return [cmd[i + 1] for i, a in enumerate(cmd) if a == flag]


def test_command_shape_and_isolation_flags(tmp_path: Path) -> None:
    p = mkpolicy(tmp_path)
    cmd = backend().command(p, ["/bin/sh", p.guest_script, "--x"], tiocsti_blocked=False)

    assert cmd[0] == FAKE_BWRAP
    assert "--unshare-all" in cmd
    assert "--share-net" not in cmd
    assert "--die-with-parent" in cmd
    assert "--new-session" in cmd
    assert single(cmd, "--hostname") == ["coldrun"]
    assert single(cmd, "--uid") == ["1000"]
    assert single(cmd, "--gid") == ["1000"]
    assert single(cmd, "--remount-ro") == ["/"]
    assert cmd.index("--remount-ro") > max(
        i for i, a in enumerate(cmd) if a in {"--bind", "--ro-bind"}
    )
    assert cmd[cmd.index("--") + 1 :] == ["/bin/sh", p.guest_script, "--x"]
    assert cmd.count("--") == 1


def test_root_is_read_only_and_home_is_absent(tmp_path: Path) -> None:
    p = mkpolicy(tmp_path)
    cmd = backend().command(p, ["true"], tiocsti_blocked=False)
    ro = pairs(cmd, "--ro-bind")
    rw = pairs(cmd, "--bind")
    assert ("/usr", "/usr") in ro
    assert all(
        not src.startswith(str(Path.home())) or src.startswith(str(tmp_path)) for src, _ in ro + rw
    )
    assert not any(dst.startswith("/home") or dst == "/root" for _, dst in ro + rw)
    assert ("--symlink", "usr/lib64", "/lib64") in zip(cmd, cmd[1:], cmd[2:], strict=False)
    guest_tmp = "/tmp"  # noqa: S108 - guest path on a private tmpfs
    assert ("--tmpfs", guest_tmp) in itertools.pairwise(cmd)
    assert ("--tmpfs", "/run") in itertools.pairwise(cmd)
    assert ("--proc", "/proc") in itertools.pairwise(cmd)
    assert ("--dev", "/dev") in itertools.pairwise(cmd)
    # Work directory is the scratch dir, script is read-only inside it, cwd is /work.
    assert (str(p.scratch), WORKDIR) in rw
    assert (str(p.script), p.guest_script) in ro
    assert ("--chdir", WORKDIR) in itertools.pairwise(cmd)


def test_passwd_and_group_hide_host_users(tmp_path: Path) -> None:
    p = mkpolicy(tmp_path)
    cmd = backend().command(p, ["true"], tiocsti_blocked=False)
    ro = {dst: src for src, dst in pairs(cmd, "--ro-bind")}
    passwd = Path(ro["/etc/passwd"]).read_text()
    assert "coldrun:x:1000:1000" in passwd
    assert f":{WORKDIR}:" in passwd
    assert Path(ro["/etc/group"]).read_text().startswith("root:x:0:")
    assert Path(ro["/etc/passwd"]).parent == p.scratch / ".coldrun"


def test_network_none_hides_resolver_and_certs(tmp_path: Path) -> None:
    cmd = backend().command(mkpolicy(tmp_path), ["true"], tiocsti_blocked=False)
    bound = [dst for _, dst in pairs(cmd, "--ro-bind-try")]
    assert "/etc/resolv.conf" not in bound
    assert "/etc/ssl" not in bound
    assert "/etc/ld.so.cache" in bound


@pytest.mark.parametrize("net", [NetPolicy.ALLOW, NetPolicy.FULL])
def test_network_policies(tmp_path: Path, net: NetPolicy) -> None:
    cmd = backend().command(mkpolicy(tmp_path, net=net), ["true"], tiocsti_blocked=False)
    bound = [dst for _, dst in pairs(cmd, "--ro-bind-try")]
    assert "/etc/resolv.conf" in bound
    assert "/etc/ssl" in bound
    assert ("--share-net" in cmd) is (net is NetPolicy.FULL)
    assert "--unshare-all" in cmd


def test_environment_is_cleared_then_set_from_allowlist(tmp_path: Path) -> None:
    cmd = backend().command(
        mkpolicy(tmp_path, env={"PYTHONDONTWRITEBYTECODE": "1"}), ["true"], tiocsti_blocked=False
    )
    assert "--clearenv" in cmd
    env = dict(pairs(cmd, "--setenv"))
    assert env["TERM"] == "dumb"
    assert "SECRET" not in env
    assert env["HOME"] == WORKDIR
    assert env["PYTHONDONTWRITEBYTECODE"] == "1"
    assert cmd.index("--clearenv") < cmd.index("--setenv")


def test_rw_and_ro_paths_are_mounted_at_same_location(tmp_path: Path) -> None:
    out = tmp_path / "out"
    out.mkdir()
    venv = tmp_path / "venv"
    venv.mkdir()
    cmd = backend().command(
        mkpolicy(tmp_path, rw_paths=(out,), ro_paths=(venv,)), ["true"], tiocsti_blocked=False
    )
    assert (str(out), str(out)) in pairs(cmd, "--bind")
    assert (str(venv), str(venv)) in pairs(cmd, "--ro-bind")


def test_tty_keeps_session_only_when_tiocsti_is_blocked(tmp_path: Path) -> None:
    p = mkpolicy(tmp_path, tty=True)
    assert "--new-session" not in backend().command(p, ["sh"], tiocsti_blocked=True)
    assert "--new-session" in backend().command(p, ["sh"], tiocsti_blocked=False)
    assert "--new-session" in backend().command(
        mkpolicy(tmp_path, tty=False), ["sh"], tiocsti_blocked=True
    )


def test_tiocsti_probe_reads_sysctl(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    f = tmp_path / "legacy_tiocsti"
    monkeypatch.setattr(bw, "_TIOCSTI_SYSCTL", f)
    assert bw.tiocsti_is_blocked() is False  # missing: old kernel, assume allowed
    f.write_text("0\n")
    assert bw.tiocsti_is_blocked() is True
    f.write_text("1\n")
    assert bw.tiocsti_is_blocked() is False
    f.write_text("garbage")
    assert bw.tiocsti_is_blocked() is False
    # command() consults the probe when not overridden
    assert "--new-session" in backend().command(mkpolicy(tmp_path, tty=True), ["sh"])


def test_userns_problems(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    clone, aa, mx = (tmp_path / n for n in ("clone", "aa", "max"))
    monkeypatch.setattr(bw, "_USERNS_CLONE", clone)
    monkeypatch.setattr(bw, "_APPARMOR_USERNS", aa)
    monkeypatch.setattr(bw, "_MAX_USERNS", mx)
    assert bw.userns_problem() is None
    clone.write_text("0")
    assert "unprivileged_userns_clone" in bw.userns_problem()[0]  # type: ignore[index]
    clone.write_text("1")
    aa.write_text("1")
    assert "AppArmor" in bw.userns_problem()[0]  # type: ignore[index]
    aa.write_text("0")
    mx.write_text("0")
    assert "max_user_namespaces" in bw.userns_problem()[0]  # type: ignore[index]
    mx.write_text("15000")
    assert bw.userns_problem() is None


def test_available_reports_missing_binary_and_userns(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(shutil, "which", lambda name: None)
    a = BwrapBackend(bwrap=None).available()
    assert not a.ok
    assert "not installed" in a.reason
    assert "pacman" in a.hint
    monkeypatch.setattr(bw, "userns_problem", lambda: ("broken", "fix it"))
    a = backend().available()
    assert (a.ok, a.reason, a.hint) == (False, "broken", "fix it")
    monkeypatch.setattr(bw, "userns_problem", lambda: None)
    assert backend().available().ok


def test_probe_wraps_failures(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(bw, "userns_problem", lambda: None)
    b = backend()

    def failing(*a: object, **k: object) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(
            [], 1, "", "bwrap: setting up uid map: Permission denied\n"
        )

    monkeypatch.setattr(subprocess, "run", failing)
    with pytest.raises(SandboxError, match="Permission denied") as exc:
        b.probe()
    assert "doctor" in exc.value.hint
    assert exc.value.exit_code == 101

    def missing(*a: object, **k: object) -> subprocess.CompletedProcess[str]:
        raise FileNotFoundError(2, "no such file")

    monkeypatch.setattr(subprocess, "run", missing)
    with pytest.raises(SandboxError, match="could not start"):
        b.probe()

    def silent(*a: object, **k: object) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess([], 3, "", "")

    monkeypatch.setattr(subprocess, "run", silent)
    with pytest.raises(SandboxError, match="exit 3"):
        b.probe()


def test_probe_raises_when_unavailable(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(shutil, "which", lambda name: None)
    with pytest.raises(SandboxError, match="not installed"):
        BwrapBackend(bwrap=None).probe()


def test_run_probes_then_passes_exit_code(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(bw, "userns_problem", lambda: None)
    calls: list[list[str]] = []

    def fake_run(cmd: list[str], **k: object) -> subprocess.CompletedProcess[str]:
        calls.append(cmd)
        return subprocess.CompletedProcess(cmd, 0 if len(calls) == 1 else 7, "", "")

    monkeypatch.setattr(subprocess, "run", fake_run)
    code = backend().run(mkpolicy(tmp_path), ["/bin/sh", "-c", "exit 7"])
    assert code == 7
    assert len(calls) == 2
    assert calls[0][-1] == "/bin/true"
    assert calls[1][-3:] == ["/bin/sh", "-c", "exit 7"]

    def boom(cmd: list[str], **k: object) -> subprocess.CompletedProcess[str]:
        calls.append(cmd)
        if len(calls) > 1:  # the probe succeeded, the real run cannot exec
            raise OSError("exec failed")
        return subprocess.CompletedProcess(cmd, 0, "", "")

    calls.clear()
    monkeypatch.setattr(subprocess, "run", boom)
    with pytest.raises(SandboxError, match="could not start bubblewrap"):
        backend().run(mkpolicy(tmp_path), ["true"])
