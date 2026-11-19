"""The sandbox must hold: these run a real bubblewrap through the backend."""

from __future__ import annotations

import http.server
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
from collections.abc import Callable, Iterator
from pathlib import Path

import pytest

from coldrun.sandbox import BwrapBackend, NetPolicy, Policy

pytestmark = pytest.mark.sandbox

RunScript = Callable[..., tuple[int, str]]


@pytest.fixture
def run_script(tmp_path: Path) -> RunScript:
    """Write ``body`` as /work/probe.sh and run it; return the exit code and output."""

    def _run(body: str, **policy: object) -> tuple[int, str]:
        script = tmp_path / "q" / "probe.sh"
        script.parent.mkdir(exist_ok=True)
        script.write_text("#!/bin/sh\nset -u\n" + body + "\n")
        scratch = tmp_path / "scratch"
        scratch.mkdir(exist_ok=True)
        pol = Policy(script=script, scratch=scratch, **policy)  # type: ignore[arg-type]
        cmd = BwrapBackend().command(pol, ["/bin/sh", pol.guest_script])
        res = subprocess.run(  # noqa: S603 - argv built by the backend
            cmd, capture_output=True, text=True, check=False, timeout=60
        )
        return res.returncode, res.stdout + res.stderr

    return _run


def test_backend_is_available_here() -> None:
    a = BwrapBackend().available()
    assert a.ok, f"{a.reason} {a.hint}"
    BwrapBackend().probe()


def test_exit_code_passes_through(run_script: RunScript) -> None:
    code, _ = run_script("exit 7")
    assert code == 7


def test_home_and_ssh_do_not_exist(run_script: RunScript) -> None:
    real_home = Path.home()
    code, out = run_script(
        f'test "$HOME" = /work || {{ echo "HOME=$HOME"; exit 1; }}\n'
        f'test ! -e "{real_home}" || {{ echo "host home visible"; exit 2; }}\n'
        f"test ! -e /home || {{ echo /home visible; exit 3; }}\n"
        f"test ! -e /root || {{ echo /root visible; exit 4; }}\n"
        f"test ! -e ~/.ssh || {{ echo ssh visible; exit 5; }}\n"
        f"cat /etc/passwd | grep -q coldrun || {{ echo no synthetic passwd; exit 6; }}\n"
        f"! grep -q '^{os.environ.get('USER', 'nobody-here')}:' /etc/passwd "
        f"|| {{ echo host user leaked; exit 7; }}"
    )
    assert code == 0, out


def test_cannot_write_outside_scratch(run_script: RunScript, tmp_path: Path) -> None:
    host_tmp = Path(tempfile.mkdtemp(prefix="coldrun-host-"))
    marker = host_tmp / "marker"
    marker.write_text("host\n")
    try:
        code, out = run_script(
            f"touch /usr/coldrun-escape 2>/dev/null && {{ echo wrote /usr; exit 1; }}\n"
            f"touch /etc/coldrun-escape 2>/dev/null && {{ echo wrote /etc; exit 2; }}\n"
            f"test ! -e {marker} || {{ echo host /tmp visible; exit 3; }}\n"
            f"echo inside > /tmp/private && echo ok > /work/output.txt"
        )
        assert code == 0, out
        assert not Path("/usr/coldrun-escape").exists()
        assert (tmp_path / "scratch" / "output.txt").read_text() == "ok\n"
        assert not (host_tmp / "private").exists()
    finally:
        shutil.rmtree(host_tmp, ignore_errors=True)


def test_script_is_read_only_inside(run_script: RunScript, tmp_path: Path) -> None:
    body = 'echo "TAM""PERED" >> /work/probe.sh 2>/dev/null && exit 1; exit 0'
    code, out = run_script(body)
    assert code == 0, out
    assert (tmp_path / "q" / "probe.sh").read_text() == "#!/bin/sh\nset -u\n" + body + "\n"


def test_network_is_unreachable_by_default(run_script: RunScript) -> None:
    if not shutil.which("bash"):
        pytest.skip("bash needed for /dev/tcp probe")
    code, out = run_script(
        "test ! -e /etc/resolv.conf || { echo resolv.conf visible; exit 1; }\n"
        '[ "$(wc -l < /proc/net/route)" -eq 1 ] || { echo has routes; exit 2; }\n'
        "if timeout 5 bash -c 'exec 3<>/dev/tcp/1.1.1.1/53' 2>/dev/null; "
        "then echo connected; exit 3; fi"
    )
    assert code == 0, out


def test_full_network_when_asked(run_script: RunScript) -> None:
    code, out = run_script(
        '[ "$(wc -l < /proc/net/route)" -ge 1 ] && test -e /etc/resolv.conf', net=NetPolicy.FULL
    )
    assert code == 0, out


def test_environment_is_scrubbed(run_script: RunScript, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("COLDRUN_SECRET_PROBE", "leak")
    monkeypatch.setenv("TERM", "vt100")
    code, out = run_script(
        'test -z "${COLDRUN_SECRET_PROBE:-}" || { echo leaked; exit 1; }\n'
        'test "$TERM" = vt100 || { echo "TERM=$TERM"; exit 2; }\n'
        'test "$PATH" = /usr/local/bin:/usr/bin:/bin || { echo "PATH=$PATH"; exit 3; }\n'
        'test "$(pwd)" = /work || { echo "pwd=$(pwd)"; exit 4; }\n'
        'test "$(hostname 2>/dev/null || cat /proc/sys/kernel/hostname)" = coldrun || exit 5'
    )
    assert code == 0, out


def test_no_capabilities_and_pid_namespace(run_script: RunScript) -> None:
    code, out = run_script(
        'grep -q "^CapEff:\\s*0\\+$" /proc/self/status '
        "|| { grep CapEff /proc/self/status; exit 1; }\n"
        'grep -q "^NoNewPrivs:\\s*1" /proc/self/status || { echo nnp off; exit 2; }\n'
        '[ "$(cat /proc/1/comm)" = bwrap ] || { echo "pid 1 is $(cat /proc/1/comm)"; exit 3; }'
    )
    assert code == 0, out


def test_rw_path_is_writable(run_script: RunScript, tmp_path: Path) -> None:
    out_dir = tmp_path / "loot"
    out_dir.mkdir()
    code, out = run_script(
        f"echo got > {out_dir}/file && test ! -e {tmp_path}/q", rw_paths=(out_dir,)
    )
    assert code == 0, out
    assert (out_dir / "file").read_text() == "got\n"


@pytest.fixture
def local_http() -> Iterator[Callable[[], int]]:
    """A hello server on the host loopback; returns its port."""

    class Hello(http.server.BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            self.send_response(200)
            self.send_header("Content-Length", "6")
            self.end_headers()
            self.wfile.write(b"hello\n")

        def log_message(self, *a: object) -> None:
            pass

    srv = http.server.HTTPServer(("127.0.0.1", 0), Hello)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield lambda: srv.server_address[1]
    srv.shutdown()


def test_allow_host_reaches_only_the_listed_destination(
    tmp_path: Path, local_http: Callable[[], int]
) -> None:
    if not shutil.which("curl") or not shutil.which("bash"):
        pytest.skip("curl and bash needed")
    port = local_http()
    script = tmp_path / "q" / "probe.sh"
    script.parent.mkdir()
    script.write_text(
        "#!/bin/bash\n"
        f"curl -sS --max-time 10 http://127.0.0.1:{port}/ok || exit 1\n"  # allowed: reachable
        f"code=$(curl -s -o /dev/null -w '%{{http_code}}' http://127.0.0.1:{port + 1}/)\n"
        '[ "$code" = 403 ] || { echo "other port: $code"; exit 2; }\n'  # other host: refused
        "code=$(curl -s -o /dev/null -w '%{http_code}' http://example.invalid/)\n"
        '[ "$code" = 403 ] || { echo "dns: $code"; exit 3; }\n'  # no DNS for others
        "test ! -e /etc/resolv.conf || exit 4\n"
        f"if timeout 3 bash -c 'exec 3<>/dev/tcp/127.0.0.1/{port}' 2>/dev/null; "
        "then echo direct connect worked; exit 5; fi\n"  # only the proxy path exists
    )
    scratch = tmp_path / "scratch"
    scratch.mkdir()
    pol = Policy(
        script=script, scratch=scratch, net=NetPolicy.ALLOW, allow_hosts=(f"127.0.0.1:{port}",)
    )
    out = tmp_path / "out.txt"
    with out.open("w") as fh, _redirect_stdout(fh):
        code = BwrapBackend().run(pol, ["/bin/bash", pol.guest_script])
    assert code == 0, out.read_text()
    assert out.read_text().startswith("hello")


class _redirect_stdout:  # noqa: N801 - tiny fd-level helper
    """Point fd 1 at a file so the sandboxed script's output can be read back."""

    def __init__(self, fh: object) -> None:
        self.fh = fh

    def __enter__(self) -> None:
        sys.stdout.flush()
        self.saved = os.dup(1)
        os.dup2(self.fh.fileno(), 1)  # type: ignore[attr-defined]

    def __exit__(self, *a: object) -> None:
        os.dup2(self.saved, 1)
        os.close(self.saved)


def test_listen_delivers_a_host_callback_inside(tmp_path: Path) -> None:
    free = socket.socket()
    free.bind(("127.0.0.1", 0))
    port = free.getsockname()[1]
    free.close()
    script = tmp_path / "q" / "catch.py"
    script.parent.mkdir()
    script.write_text(
        "import socket\n"
        "s = socket.socket()\n"
        f"s.bind(('127.0.0.1', {port}))\n"
        "s.listen(1)\n"
        "c, _ = s.accept()\n"
        "data = c.recv(100)\n"
        "c.sendall(b'ack ' + data)\n"
        "print('callback:', data.decode())\n"
    )
    scratch = tmp_path / "scratch"
    scratch.mkdir()
    pol = Policy(script=script, scratch=scratch, listen=(("127.0.0.1", port),))
    out = tmp_path / "out.txt"
    result: list[int] = []

    def run() -> None:
        with out.open("w") as fh, _redirect_stdout(fh):
            result.append(BwrapBackend().run(pol, ["/usr/bin/python3", pol.guest_script]))

    t = threading.Thread(target=run)
    t.start()
    reply = b""
    for _ in range(100):  # the script needs a moment to start listening inside
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=2) as c:
                c.sendall(b"shell")
                reply = c.recv(100)
            if reply:
                break
        except OSError:
            pass
        time.sleep(0.1)
    t.join(timeout=30)
    assert reply == b"ack shell"
    assert result == [0] and "callback: shell" in out.read_text()
