"""The sandbox must hold under Podman too: escape checks against a real rootless container."""

from __future__ import annotations

import http.server
import os
import shutil
import subprocess
import sys
import threading
from collections.abc import Callable, Iterator
from pathlib import Path

import pytest

from coldrun.sandbox import NetPolicy, PodmanBackend, Policy

pytestmark = [
    pytest.mark.sandbox,
    pytest.mark.skipif(shutil.which("podman") is None, reason="podman not installed"),
]
IMAGE = (
    "docker.io/library/python:3.12-slim"
    "@sha256:5e2bdb1b0d542d5039cffb8181c65930093949194a65c365dfb1b0fe13a4fa5b"
)
RunScript = Callable[..., tuple[int, str]]


@pytest.fixture
def run_script(tmp_path: Path) -> RunScript:
    """Write ``body`` as /work/probe.sh, run it in the image; return code and output."""

    def _run(body: str, **policy: object) -> tuple[int, str]:
        script = tmp_path / "q" / "probe.sh"
        script.parent.mkdir(exist_ok=True)
        script.write_text("#!/bin/sh\nset -u\n" + body + "\n")
        scratch = tmp_path / "scratch"
        scratch.mkdir(exist_ok=True)
        pol = Policy(script=script, scratch=scratch, image=IMAGE, **policy)  # type: ignore[arg-type]
        cmd = PodmanBackend().command(pol, ["/bin/sh", pol.guest_script])
        res = subprocess.run(  # noqa: S603 - argv built by the backend
            cmd, capture_output=True, text=True, check=False, timeout=300
        )
        return res.returncode, res.stdout + res.stderr

    return _run


def test_exit_code_passes_through(run_script: RunScript) -> None:
    assert run_script("exit 7")[0] == 7


def test_home_is_hidden_and_root_is_read_only(run_script: RunScript) -> None:
    home = Path.home()
    code, out = run_script(
        f'test "$HOME" = /work || {{ echo "HOME=$HOME"; exit 1; }}\n'
        f'test ! -e "{home}" || {{ echo host home visible; exit 2; }}\n'
        "if touch /etc/x 2>/dev/null; then echo root writable; exit 3; fi\n"
        "if touch /work/probe.sh 2>/dev/null; then echo script writable; exit 4; fi\n"
        "touch /work/out && touch /tmp/ok || exit 5"
    )
    assert code == 0, out


def test_no_capabilities_and_no_network(run_script: RunScript) -> None:
    code, out = run_script(
        "grep -q '^CapEff:[[:space:]]*0000000000000000' /proc/self/status || exit 1\n"
        "grep -q '^NoNewPrivs:[[:space:]]*1' /proc/self/status || exit 2\n"
        '[ "$(wc -l < /proc/net/route)" -eq 1 ] || { echo has routes; exit 3; }'
    )
    assert code == 0, out


def test_environment_is_scrubbed(run_script: RunScript, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("COLDRUN_CANARY", "must-not-leak")
    code, out = run_script('test -z "${COLDRUN_CANARY:-}" || exit 1')
    assert code == 0, out


@pytest.fixture
def local_http() -> Iterator[int]:
    class Hello(http.server.BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            self.send_response(200)
            self.send_header("Content-Length", "3")
            self.end_headers()
            self.wfile.write(b"ok\n")

        def log_message(self, *a: object) -> None:
            pass

    srv = http.server.HTTPServer(("127.0.0.1", 0), Hello)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield srv.server_address[1]
    srv.shutdown()


def test_allow_host_through_the_bridge_in_the_image(tmp_path: Path, local_http: int) -> None:
    script = tmp_path / "q" / "get.py"
    script.parent.mkdir()
    script.write_text(
        "import urllib.request\n"
        f"print(urllib.request.urlopen('http://127.0.0.1:{local_http}/').read().decode(), end='')\n"
        "try:\n"
        f"    urllib.request.urlopen('http://127.0.0.1:{local_http + 1}/')\n"
        "except Exception as e:\n"
        "    print('refused', getattr(e, 'code', e))\n"
    )
    scratch = tmp_path / "scratch"
    scratch.mkdir()
    pol = Policy(
        script=script,
        scratch=scratch,
        image=IMAGE,
        net=NetPolicy.ALLOW,
        allow_hosts=(f"127.0.0.1:{local_http}",),
    )
    out = tmp_path / "out.txt"
    with out.open("w") as fh:
        code = _run_capturing(pol, ["python", pol.guest_script], fh)
    assert code == 0, out.read_text()
    assert out.read_text().splitlines()[:2] == ["ok", "refused 403"]


def _run_capturing(pol: Policy, argv: list[str], fh: object) -> int:
    sys.stdout.flush()
    saved = os.dup(1)
    os.dup2(fh.fileno(), 1)  # type: ignore[attr-defined]
    try:
        return PodmanBackend().run(pol, argv)
    finally:
        os.dup2(saved, 1)
        os.close(saved)
