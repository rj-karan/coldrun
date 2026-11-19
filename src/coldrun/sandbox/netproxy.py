"""Host-side allowlist proxy for ``--net allow``.

The sandbox keeps its own empty network namespace. This proxy listens on a
unix socket that is bound into the sandbox, speaks HTTP ``CONNECT`` and plain
``http://`` forwarding, and connects only to the hosts the user named. Names
resolve here, on the host, so a script never gets DNS for anything else.
"""

from __future__ import annotations

import contextlib
import socket
import threading
from typing import TYPE_CHECKING
from urllib.parse import urlsplit

if TYPE_CHECKING:
    from collections.abc import Sequence
    from pathlib import Path

#: Where the sandbox reaches the proxy: the bridge listens here inside.
GUEST_PORT = 3128
_FORBIDDEN = (
    b"HTTP/1.1 403 Forbidden\r\nConnection: close\r\n\r\ncoldrun: host not in --allow-host\n"
)
_ESTABLISHED = b"HTTP/1.1 200 Connection established\r\n\r\n"
_BAD = b"HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n"
_MAX_HEAD = 65536
_HEAD_TIMEOUT = 20.0


def parse_hosts(specs: Sequence[str]) -> frozenset[tuple[str, int | None]]:
    """``HOST[:PORT]`` entries as ``(lowercase host, port or None)``."""
    out = set()
    for spec in specs:
        host, sep, port = spec.strip().rpartition(":")
        if not sep or not port.isdigit():
            host, port = spec.strip(), ""
        if not host:
            msg = f"--allow-host needs HOST[:PORT], got {spec!r}"
            raise ValueError(msg)
        out.add((host.lower().strip("[]"), int(port) if port else None))
    return frozenset(out)


class AllowProxy:
    """A tiny forward proxy that refuses every destination not on the list."""

    def __init__(self, hosts: Sequence[str], sock_dir: Path) -> None:
        self.allowed = parse_hosts(hosts)
        self.path = sock_dir / "proxy.sock"
        self._server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)

    def permits(self, host: str, port: int) -> bool:
        """True when ``host:port`` is on the list (a port-less entry means any port)."""
        host = host.lower().strip("[]")
        return (host, port) in self.allowed or (host, None) in self.allowed

    def start(self) -> AllowProxy:
        """Bind the socket and serve on a daemon thread."""
        self._server.bind(str(self.path))
        self._server.listen(16)
        threading.Thread(target=self._serve, daemon=True, name="coldrun-proxy").start()
        return self

    def stop(self) -> None:
        """Close the listener; in-flight connections finish on their own."""
        self._server.close()
        self.path.unlink(missing_ok=True)

    def _serve(self) -> None:
        while True:
            try:
                client, _ = self._server.accept()
            except OSError:  # pragma: no cover - stop() closed the listener; thread timing
                return
            threading.Thread(target=self._handle, args=(client,), daemon=True).start()

    def _handle(self, client: socket.socket) -> None:
        # a client hanging up mid-handshake is normal (uv races connections), not an error
        with client, contextlib.suppress(OSError):
            head = _read_head(client)
            if head is None:
                client.sendall(_BAD)
                return
            line, _, rest = head.partition(b"\r\n")
            method, _, target = line.decode("latin-1").partition(" ")
            target = target.rsplit(" ", 1)[0]
            if method == "CONNECT":
                host, _, port = target.rpartition(":")
                request = b""
            else:
                url = urlsplit(target)
                host, port = url.hostname or "", str(url.port or 80)
                origin = (url.path or "/") + (f"?{url.query}" if url.query else "")
                request = f"{method} {origin} HTTP/1.1\r\n".encode("latin-1") + rest
            if not host or not port.isdigit() or not self.permits(host, int(port)):
                client.sendall(_FORBIDDEN)
                return
            try:
                upstream = socket.create_connection((host, int(port)), timeout=20)
            except OSError:
                client.sendall(b"HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\n\r\n")
                return
            with upstream:
                upstream.settimeout(None)
                if request:
                    upstream.sendall(request)
                else:
                    client.sendall(_ESTABLISHED)
                pump(client, upstream)


def _read_head(sock: socket.socket) -> bytes | None:
    """The request line and headers, or ``None`` when the client sends junk."""
    sock.settimeout(_HEAD_TIMEOUT)
    buf = b""
    while b"\r\n\r\n" not in buf:
        try:
            chunk = sock.recv(4096)
        except OSError:
            return None
        if not chunk or len(buf) > _MAX_HEAD:
            return None
        buf += chunk
    sock.settimeout(None)
    return buf


def pump(a: socket.socket, b: socket.socket) -> None:
    """Copy bytes both ways until both sides have closed."""

    def one_way(src: socket.socket, dst: socket.socket) -> None:
        try:
            while chunk := src.recv(65536):
                dst.sendall(chunk)
        except OSError:
            pass
        finally:
            with contextlib.suppress(OSError):
                dst.shutdown(socket.SHUT_WR)

    t = threading.Thread(target=one_way, args=(b, a), daemon=True)
    t.start()
    one_way(a, b)
    t.join()
