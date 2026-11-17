"""The podman command line for every policy field, and the run lifecycle, without podman."""

from __future__ import annotations

from pathlib import Path

import pytest

from coldrun.sandbox import NetPolicy, PodmanBackend, Policy, SandboxError
from coldrun.sandbox import podman as pm

IMAGE = "docker.io/library/python:3.12-slim"


def backend() -> PodmanBackend:
    return PodmanBackend(podman="/usr/bin/podman", environ={"TERM": "dumb", "SECRET": "x"})


def policy(tmp_path: Path, **kw: object) -> Policy:
    (tmp_path / "scratch").mkdir(exist_ok=True)
    base: dict[str, object] = {
        "script": tmp_path / "q" / "x.py",
        "scratch": tmp_path / "scratch",
        "image": IMAGE,
    }
    return Policy(**{**base, **kw})  # type: ignore[arg-type]


def volumes(cmd: list[str]) -> list[str]:
    return [cmd[i + 1] for i, a in enumerate(cmd) if a == "--volume"]


def test_hardening_flags_and_defaults(tmp_path: Path) -> None:
    pol = policy(tmp_path)
    cmd = backend().command(pol, ["python", pol.guest_script, "-v"])
    head = cmd[: cmd.index(IMAGE)]
    for flag in (
        "--rm", "--cap-drop=all", "--security-opt=no-new-privileges", "--read-only",
        "--userns=keep-id", f"--pids-limit={pm.PIDS_LIMIT}", "--network=none", "--pull=missing",
    ):  # fmt: skip
        assert flag in head, flag
    assert "--tty" not in head
    assert f"{tmp_path / 'scratch'}:/work:rw" in volumes(cmd)
    assert f"{pol.script}:/work/x.py:ro" in volumes(cmd)
    env = [cmd[i + 1] for i, a in enumerate(cmd) if a == "--env"]
    assert "TERM=dumb" in env and "HOME=/work" in env
    assert not any(e.startswith("SECRET=") for e in env)
    assert cmd[cmd.index(IMAGE) + 1 :] == ["python", "/work/x.py", "-v"]


def test_mounts_tty_and_full_network(tmp_path: Path) -> None:
    ro, rw, deps, uv = tmp_path / "ro", tmp_path / "rw", tmp_path / "env", tmp_path / "uv"
    for d in (ro, rw, deps):
        d.mkdir()
    tree = tmp_path / "src"
    pol = Policy(
        script=tree / "a" / "x.py",
        scratch=policy(tmp_path).scratch,
        tree=tree,
        image=IMAGE,
        net=NetPolicy.FULL,
        ro_paths=(ro,),
        rw_paths=(rw,),
        binaries=(uv,),
        deps_dir=deps,
        deps_writable=True,
        tty=True,
    )
    cmd = backend().command(pol, ["true"])
    assert "--network=none" not in cmd and "--tty" in cmd
    v = volumes(cmd)
    assert f"{tree}:/work/src:ro" in v
    assert f"{ro}:{ro}:ro" in v and f"{rw}:{rw}:rw" in v
    assert f"{uv}:/usr/local/bin/uv:ro" in v
    assert f"{deps}:/work/.coldrun/deps:rw" in v
    plain = backend().command(policy(tmp_path, deps_dir=deps), ["true"])
    assert f"{deps}:/work/.coldrun/deps:ro" in volumes(plain)


def test_allow_host_runs_the_bridge_with_the_image_python(tmp_path: Path) -> None:
    sock = tmp_path / "net" / "proxy.sock"
    pol = policy(tmp_path, net=NetPolicy.ALLOW, allow_hosts=("pypi.org",))
    cmd = backend().command(pol, ["pip", "install", "x"], proxy_sock=sock)
    assert "--network=none" in cmd
    assert f"{sock.parent}:/run/coldrun/net:rw" in volumes(cmd)
    assert any(v.endswith("bridge.py:/run/coldrun/bridge.py:ro") for v in volumes(cmd))
    assert "https_proxy=http://127.0.0.1:3128" in cmd
    tail = cmd[cmd.index(IMAGE) + 1 :]
    assert tail == [
        "python", "/run/coldrun/bridge.py", "--proxy", "3128:/run/coldrun/net/proxy.sock",
        "--", "pip", "install", "x",
    ]  # fmt: skip
    with pytest.raises(SandboxError, match="proxy socket"):
        backend().command(pol, ["true"])


@pytest.mark.parametrize(
    ("kw", "match"),
    [
        ({"image": None}, "ship an image"),
        ({"listen": (4444,)}, "--listen needs the bwrap backend"),
    ],
)
def test_refusals(tmp_path: Path, kw: dict[str, object], match: str) -> None:
    with pytest.raises(SandboxError, match=match):
        backend().command(policy(tmp_path, **kw), ["true"])


def test_paths_podman_cannot_express_are_refused(tmp_path: Path) -> None:
    odd = tmp_path / "a:b"
    odd.mkdir()
    with pytest.raises(SandboxError, match="':' or ','"):
        backend().command(policy(tmp_path, ro_paths=(odd,)), ["true"])


def test_available_and_run(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("shutil.which", lambda _: None)
    missing = PodmanBackend()
    assert not missing.available().ok and "pacman -S podman" in missing.available().hint
    with pytest.raises(SandboxError, match="not installed"):
        missing.run(policy(tmp_path), ["true"])

    seen: list[list[str]] = []

    def fake_exec(self: PodmanBackend, cmd: list[str]) -> int:
        seen.append(cmd)
        if "--proxy" in cmd:
            sock_dir = next(v for v in volumes(cmd) if v.endswith(":/run/coldrun/net:rw"))
            assert Path(sock_dir.split(":")[0], "proxy.sock").exists()  # proxy up while it runs
        return 3

    monkeypatch.setattr(PodmanBackend, "_exec", fake_exec)
    assert backend().run(policy(tmp_path), ["true"]) == 3
    allow = policy(tmp_path, net=NetPolicy.ALLOW, allow_hosts=("pypi.org",))
    assert backend().run(allow, ["true"]) == 3
    assert len(seen) == 2


def test_exec_maps_podman_failures(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    b = PodmanBackend(podman=str(tmp_path / "nope"))
    with pytest.raises(SandboxError, match="could not start podman"):
        b._exec([str(tmp_path / "nope")])
    with pytest.raises(SandboxError, match="exit 125"):
        b._exec(["/bin/sh", "-c", "exit 125"])
    assert b._exec(["/bin/sh", "-c", "exit 4"]) == 4
