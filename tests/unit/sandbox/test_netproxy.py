"""The allowlist proxy and the in-sandbox bridge, over real sockets on localhost."""

from __future__ import annotations

import ast
import socket
import sys
import threading
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import pytest

from coldrun.sandbox import bridge, netproxy
from coldrun.sandbox.netproxy import AllowProxy, parse_hosts


class Hello(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        body = f"hello {self.path}".encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a: object) -> None:
        pass


@pytest.fixture
def upstream() -> Iterator[HTTPServer]:
    srv = HTTPServer(("127.0.0.1", 0), Hello)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield srv
    srv.shutdown()


@pytest.fixture
def proxy(tmp_path: Path, upstream: HTTPServer) -> Iterator[AllowProxy]:
    port = upstream.server_address[1]
    p = AllowProxy([f"127.0.0.1:{port}", "Example.COM"], tmp_path).start()
    yield p
    p.stop()


def unix_conn(path: Path) -> socket.socket:
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.connect(str(path))
    s.settimeout(5)
    return s


def test_parse_hosts() -> None:
    assert parse_hosts(["a.b:443", "C", " d:80 ", "[::1]:22"]) == {
        ("a.b", 443), ("c", None), ("d", 80), ("::1", 22)
    }  # fmt: skip
    with pytest.raises(ValueError, match="HOST"):
        parse_hosts([":80"])


def test_permits_is_exact_host_and_port(proxy: AllowProxy, upstream: HTTPServer) -> None:
    port = upstream.server_address[1]
    assert proxy.permits("127.0.0.1", port) and not proxy.permits("127.0.0.1", port + 1)
    assert proxy.permits("example.com", 80) and proxy.permits("EXAMPLE.com", 9999)
    assert not proxy.permits("sub.example.com", 80) and not proxy.permits("evil.test", 80)


def test_plain_http_is_forwarded_in_origin_form(proxy: AllowProxy, upstream: HTTPServer) -> None:
    port = upstream.server_address[1]
    with unix_conn(proxy.path) as s:
        s.sendall(f"GET http://127.0.0.1:{port}/x?y=1 HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n".encode())
        data = b""
        while chunk := s.recv(4096):
            data += chunk
    assert data.startswith(b"HTTP/1.0 200") and data.endswith(b"hello /x?y=1")


def test_connect_tunnels_to_allowed_host(proxy: AllowProxy, upstream: HTTPServer) -> None:
    port = upstream.server_address[1]
    with unix_conn(proxy.path) as s:
        s.sendall(f"CONNECT 127.0.0.1:{port} HTTP/1.1\r\n\r\n".encode())
        assert s.recv(100).startswith(b"HTTP/1.1 200")
        s.sendall(b"GET /t HTTP/1.0\r\n\r\n")
        data = b""
        while chunk := s.recv(4096):
            data += chunk
    assert data.endswith(b"hello /t")


@pytest.mark.parametrize(
    "request_line",
    [
        "CONNECT 127.0.0.1:1 HTTP/1.1",
        "GET http://evil.test/ HTTP/1.1",
        "CONNECT example.invalid HTTP/1.1",
    ],
)
def test_other_hosts_get_403_without_dns(proxy: AllowProxy, request_line: str) -> None:
    with unix_conn(proxy.path) as s:
        s.sendall(f"{request_line}\r\n\r\n".encode())
        assert s.recv(200).startswith(b"HTTP/1.1 403")


def test_junk_and_unreachable_upstream(tmp_path: Path, proxy: AllowProxy) -> None:
    with unix_conn(proxy.path) as s:
        s.sendall(b"garbage")
        s.shutdown(socket.SHUT_WR)
        assert s.recv(100).startswith(b"HTTP/1.1 400")
    dead = socket.socket()
    dead.bind(("127.0.0.1", 0))
    port = dead.getsockname()[1]
    dead.close()  # nothing listens here now
    (tmp_path / "d").mkdir()
    p = AllowProxy([f"127.0.0.1:{port}"], tmp_path / "d").start()
    try:
        with unix_conn(p.path) as s:
            s.sendall(f"CONNECT 127.0.0.1:{port} HTTP/1.1\r\n\r\n".encode())
            assert s.recv(100).startswith(b"HTTP/1.1 502")
    finally:
        p.stop()
    assert not p.path.exists()


def free_port() -> int:
    free = socket.socket()
    free.bind(("127.0.0.1", 0))
    port: int = free.getsockname()[1]
    free.close()
    return port


def test_bridge_exposes_socket_as_tcp_and_passes_exit_code(
    proxy: AllowProxy, upstream: HTTPServer, capfd: pytest.CaptureFixture[str]
) -> None:
    port = upstream.server_address[1]
    tcp_port = free_port()
    script = (
        "import http.client, sys\n"
        f"c = http.client.HTTPConnection('127.0.0.1', {tcp_port})\n"
        f"c.request('GET', 'http://127.0.0.1:{port}/b')\n"
        "r = c.getresponse()\n"
        "print(r.read().decode())\n"
        "sys.exit(7 if r.status == 200 else 1)\n"
    )
    # in-process, so the listener thread is covered; the script is a child like in the sandbox
    code = bridge.main(["--proxy", f"{tcp_port}:{proxy.path}", "--", sys.executable, "-c", script])
    assert code == 7
    assert "hello /b" in capfd.readouterr().out
    with pytest.raises(SystemExit):
        bridge.main(["--proxy", "1:x"])  # no command


def test_bridge_closes_clients_when_the_socket_is_gone(tmp_path: Path) -> None:
    tcp_port = free_port()
    code = bridge.main(["--proxy", f"{tcp_port}:{tmp_path / 'missing.sock'}", "--", "true"])
    assert code == 0
    with socket.create_connection(("127.0.0.1", tcp_port), timeout=5) as s:
        assert s.recv(10) == b""


def test_slow_client_and_dead_sockets(
    tmp_path: Path, proxy: AllowProxy, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(netproxy, "_HEAD_TIMEOUT", 0.2)
    with unix_conn(proxy.path) as s:
        assert s.recv(100).startswith(b"HTTP/1.1 400")  # never sent a request line
    a, b = socket.socketpair()
    a.close()
    b.close()
    netproxy.pump(a, b)  # both sides already closed: returns quietly


def test_bridge_forwards_an_inherited_listener_to_the_inside_port() -> None:
    inside_port = free_port()
    inside = socket.socket()
    inside.bind(("127.0.0.1", inside_port))  # stands in for the script's listener
    inside.listen(1)

    def answer() -> None:
        c, _ = inside.accept()
        with c:
            c.sendall(b"got " + c.recv(100))

    threading.Thread(target=answer, daemon=True).start()
    host = socket.socket()  # the socket the backend opens and hands over as an fd
    host.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    host.bind(("127.0.0.1", 0))
    host.listen(1)
    host_port = host.getsockname()[1]
    assert bridge.main(["--listen", f"{host.fileno()}:{inside_port}", "--", "true"]) == 0
    with socket.create_connection(("127.0.0.1", host_port), timeout=5) as c:
        c.sendall(b"callback")
        c.shutdown(socket.SHUT_WR)
        assert c.recv(100) == b"got callback"
    # nobody listening inside: the callback is dropped, the bridge keeps serving
    dead_port = free_port()
    host2 = socket.socket()
    host2.bind(("127.0.0.1", 0))
    host2.listen(1)
    assert bridge.main(["--listen", f"{host2.fileno()}:{dead_port}", "--", "true"]) == 0
    with socket.create_connection(("127.0.0.1", host2.getsockname()[1]), timeout=5) as c:
        assert c.recv(10) == b""


def test_bridge_pump_tolerates_closed_sockets() -> None:
    a, b = socket.socketpair()
    a.close()
    b.close()
    bridge._pump(a, b)  # both sides already closed: returns quietly


def test_bridge_stays_python2_parseable() -> None:
    # it runs on the Python 2.7 image too; these are the constructs Python 2 rejects
    src = Path(bridge.__file__).read_text()
    assert "from __future__ import annotations" not in src
    assert src.isascii()
    tree = ast.parse(src)
    assert not [n for n in ast.walk(tree) if isinstance(n, (ast.JoinedStr, ast.NamedExpr))]
    funcs = [n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef)]
    assert funcs and not [f for f in funcs if f.returns or any(a.annotation for a in f.args.args)]


@pytest.mark.parametrize("target", ["127.0.0.1:{port}", "evil.test:443", "junk"])
def test_clients_that_hang_up_early_are_handled_quietly(
    proxy: AllowProxy, upstream: HTTPServer, target: str
) -> None:
    # uv races several connections and drops the losers before the proxy answers
    ours, theirs = socket.socketpair()
    theirs.sendall(
        f"CONNECT {target.format(port=upstream.server_address[1])} HTTP/1.1\r\n\r\n".encode()
    )
    theirs.close()  # gone before the reply
    proxy._handle(ours)  # must not raise BrokenPipeError
