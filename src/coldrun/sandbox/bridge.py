"""Runs inside the sandbox: expose the host proxy's unix socket as a TCP port.

``python3 bridge.py PORT SOCKET -- COMMAND...`` listens on ``127.0.0.1:PORT``,
forwards each connection to ``SOCKET``, then runs ``COMMAND`` and exits with
its code. Only the standard library, because it runs on the host's
``/usr/bin/python3``, whatever its version. Enforcement stays on the host
side of the socket; this file only moves bytes.
"""

from __future__ import annotations

import contextlib
import socket
import subprocess
import sys
import threading


def _pump(src: socket.socket, dst: socket.socket) -> None:
    try:
        while chunk := src.recv(65536):
            dst.sendall(chunk)
    except OSError:  # pragma: no cover - a peer vanished mid-copy; same path as netproxy.pump
        pass
    finally:
        with contextlib.suppress(OSError):
            dst.shutdown(socket.SHUT_WR)


def _serve(listener: socket.socket, sock_path: str) -> None:
    while True:
        client, _ = listener.accept()
        upstream = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            upstream.connect(sock_path)
        except OSError:
            client.close()
            continue
        threading.Thread(target=_pump, args=(client, upstream), daemon=True).start()
        threading.Thread(target=_pump, args=(upstream, client), daemon=True).start()


def main(argv: list[str]) -> int:
    """Entry point; see the module docstring."""
    port, sock_path, dashes, *command = argv
    if dashes != "--" or not command:
        sys.stderr.write("usage: bridge.py PORT SOCKET -- COMMAND...\n")
        return 2
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", int(port)))
    listener.listen(32)
    threading.Thread(target=_serve, args=(listener, sock_path), daemon=True).start()
    return subprocess.call(command)  # noqa: S603 - the runner's argv, inside the sandbox


if __name__ == "__main__":  # pragma: no cover - exercised through main() in tests
    sys.exit(main(sys.argv[1:]))
