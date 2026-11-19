from __future__ import annotations

import itertools
import shutil
import socket
import subprocess
from pathlib import Path

import pytest

from coldrun.sandbox import BwrapBackend, NetPolicy, Policy, SandboxError
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


def test_network_full_shares_net_and_binds_resolver(tmp_path: Path) -> None:
    cmd = backend().command(mkpolicy(tmp_path, net=NetPolicy.FULL), ["true"], tiocsti_blocked=False)
    bound = {src for src, _ in pairs(cmd, "--ro-bind-try")}
    assert {"/etc/resolv.conf", "/etc/hosts", "/etc/ssl"} <= bound
    assert "--share-net" in cmd


def test_network_allow_uses_the_bridge_and_proxy(tmp_path: Path) -> None:
    sock = tmp_path / "net" / "proxy.sock"
    pol = mkpolicy(tmp_path, net=NetPolicy.ALLOW, allow_hosts=("example.com:443",))
    cmd = backend().command(pol, ["/bin/sh", "x"], tiocsti_blocked=False, proxy_sock=sock)
    assert "--share-net" not in cmd  # the namespace stays empty; only the socket gets in
    bound = {src for src, _ in pairs(cmd, "--ro-bind-try")}
    assert "/etc/ssl" in bound and "/etc/resolv.conf" not in bound
    assert (str(sock.parent), "/run/coldrun/net") in pairs(cmd, "--bind")
    assert any(
        dst == "/run/coldrun/bridge.py" and src.endswith("bridge.py")
        for src, dst in pairs(cmd, "--ro-bind")
    )
    env = dict(pairs(cmd, "--setenv"))
    assert env["https_proxy"] == env["HTTP_PROXY"] == "http://127.0.0.1:3128"
    tail = cmd[cmd.index("--") + 1 :]
    assert tail == [
        "/usr/bin/python3",
        "/run/coldrun/bridge.py",
        "--proxy",
        "3128:/run/coldrun/net/proxy.sock",
        "--",
        "/bin/sh",
        "x",
    ]
    with pytest.raises(SandboxError, match="proxy socket"):
        backend().command(pol, ["true"], tiocsti_blocked=False)


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


def test_deps_dir_is_bound_rw_for_install_and_ro_for_run(tmp_path: Path) -> None:
    env = tmp_path / "env"
    env.mkdir()
    ro = backend().command(mkpolicy(tmp_path, deps_dir=env), ["x"], tiocsti_blocked=False)
    assert (str(env), "/work/.coldrun/deps") in pairs(ro, "--ro-bind")
    rw = backend().command(
        mkpolicy(tmp_path, deps_dir=env, deps_writable=True), ["x"], tiocsti_blocked=False
    )
    assert (str(env), "/work/.coldrun/deps") in pairs(rw, "--bind")


def test_binaries_are_exposed_under_usr_local_bin(tmp_path: Path) -> None:
    uv = tmp_path / ".local" / "bin" / "uv"
    uv.parent.mkdir(parents=True)
    uv.write_text("")
    cmd = backend().command(mkpolicy(tmp_path, binaries=(uv,)), ["uv"], tiocsti_blocked=False)
    assert (str(uv), "/usr/local/bin/uv") in pairs(cmd, "--ro-bind")
    assert cmd.index("--tmpfs", cmd.index("/usr/local/bin") - 1) < cmd.index(str(uv))
    plain = backend().command(mkpolicy(tmp_path), ["sh"], tiocsti_blocked=False)
    assert "/usr/local/bin" not in plain


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


def test_run_with_allow_hosts_owns_the_proxy_lifecycle(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    seen: list[str] = []

    def fake_exec(self: bw.BwrapBackend, cmd: list[str], pass_fds: tuple[int, ...] = ()) -> int:
        sock_dir = Path({dst: src for src, dst in pairs(cmd, "--bind")}["/run/coldrun/net"])
        assert (sock_dir / "proxy.sock").exists()  # the proxy is listening while the script runs
        assert "/run/coldrun/bridge.py" in cmd
        seen.append(str(sock_dir))
        return 5

    monkeypatch.setattr(bw.BwrapBackend, "probe", lambda self: None)
    monkeypatch.setattr(bw.BwrapBackend, "_exec", fake_exec)
    pol = mkpolicy(tmp_path, net=NetPolicy.ALLOW, allow_hosts=("example.com",))
    assert backend().run(pol, ["true"]) == 5
    assert seen and not Path(seen[0]).exists()  # the socket directory is gone afterwards

    monkeypatch.setattr(bw, "_GUEST_PYTHON", str(tmp_path / "no-python"))
    with pytest.raises(SandboxError, match=r"need .*no-python"):
        backend().run(pol, ["true"])


def test_tree_is_bound_read_only_instead_of_the_lone_script(tmp_path: Path) -> None:
    tree = tmp_path / "src"
    (tmp_path / "scratch").mkdir()
    pol = Policy(script=tree / "a" / "x.sh", scratch=tmp_path / "scratch", tree=tree)
    cmd = backend().command(pol, ["sh", pol.guest_script], tiocsti_blocked=False)
    ro = pairs(cmd, "--ro-bind")
    assert (str(tree), "/work/src") in ro
    assert not any(dst == "/work/src/a/x.sh" for _, dst in ro)
    assert cmd[-1] == "/work/src/a/x.sh"


def test_listen_ports_ride_the_bridge_as_inherited_fds(tmp_path: Path) -> None:
    pol = mkpolicy(tmp_path, listen=(("127.0.0.1", 4444), ("10.10.14.5", 8080)))
    cmd = backend().command(pol, ["nc"], tiocsti_blocked=False, listen_fds={4444: 7, 8080: 9})
    assert "--share-net" not in cmd and "--proxy" not in cmd
    tail = cmd[cmd.index("--") + 1 :]
    bridge = ["/usr/bin/python3", "/run/coldrun/bridge.py"]
    assert tail == [*bridge, "--listen", "7:4444", "--listen", "9:8080", "--", "nc"]
    assert not any(k.endswith("proxy") for k, _ in pairs(cmd, "--setenv"))
    with pytest.raises(SandboxError, match="no host socket"):
        backend().command(pol, ["nc"], tiocsti_blocked=False, listen_fds={4444: 7})


def test_run_with_listen_opens_host_sockets_and_passes_them(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    seen: dict[str, object] = {}

    def fake_exec(self: bw.BwrapBackend, cmd: list[str], pass_fds: tuple[int, ...] = ()) -> int:
        seen["fds"] = pass_fds
        seen["cmd"] = cmd
        with socket.create_connection(("127.0.0.1", port), timeout=5):
            pass  # the host port is open while the sandbox runs
        return 0

    free = socket.socket()
    free.bind(("127.0.0.1", 0))
    port = free.getsockname()[1]
    free.close()
    monkeypatch.setattr(bw.BwrapBackend, "probe", lambda self: None)
    monkeypatch.setattr(bw.BwrapBackend, "_exec", fake_exec)
    assert backend().run(mkpolicy(tmp_path, listen=(("127.0.0.1", port),)), ["nc"]) == 0
    fds = seen["fds"]
    assert isinstance(fds, tuple) and len(fds) == 1
    assert f"{fds[0]}:{port}" in seen["cmd"]  # type: ignore[operator]
    with pytest.raises(OSError, match="refused"):
        socket.create_connection(("127.0.0.1", port), timeout=2)  # closed again afterwards

    busy = socket.socket()
    busy.bind(("127.0.0.1", port))
    busy.listen(1)
    try:
        with pytest.raises(SandboxError, match=r"cannot listen on 127\.0\.0\.1:"):
            backend().run(mkpolicy(tmp_path, listen=(("127.0.0.1", port),)), ["nc"])
    finally:
        busy.close()


def test_bwrap_refuses_image_policies(tmp_path: Path) -> None:
    with pytest.raises(SandboxError, match="container image"):
        backend().command(mkpolicy(tmp_path, image="python:2.7"), ["true"], tiocsti_blocked=False)
