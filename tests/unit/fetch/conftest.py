from __future__ import annotations

import http.server
import threading
from collections.abc import Iterator
from pathlib import Path
from typing import ClassVar

import pytest


class _Handler(http.server.BaseHTTPRequestHandler):
    """Serves a few fixed routes for the URL fetcher tests."""

    routes: ClassVar[dict[str, tuple[int, bytes, dict[str, str]]]] = {}

    def do_GET(self) -> None:
        status, body, headers = self.routes.get(self.path, (404, b"not found", {}))
        self.send_response(status)
        for k, v in headers.items():
            self.send_header(k, v)
        if "Content-Length" not in headers and status != 302:
            self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if status != 302:
            self.wfile.write(body)

    def log_message(self, *args: object) -> None:
        return


class Server:
    def __init__(self) -> None:
        self.httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
        self.port = self.httpd.server_address[1]
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()

    def url(self, path: str) -> str:
        return f"http://127.0.0.1:{self.port}{path}"

    def route(
        self, path: str, body: bytes, status: int = 200, headers: dict[str, str] | None = None
    ) -> str:
        _Handler.routes[path] = (status, body, headers or {})
        return self.url(path)

    def close(self) -> None:
        self.httpd.shutdown()
        self.httpd.server_close()
        _Handler.routes.clear()


@pytest.fixture
def server() -> Iterator[Server]:
    s = Server()
    yield s
    s.close()


@pytest.fixture
def qroot(tmp_path: Path) -> Path:
    return tmp_path / "quarantine"
