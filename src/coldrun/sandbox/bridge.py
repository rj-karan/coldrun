"""Runs inside the sandbox: the script's only doors to the outside.

``python3 bridge.py [--proxy PORT:SOCKET] [--listen FD:PORT ...] -- COMMAND...``

``--proxy`` listens on ``127.0.0.1:PORT`` and forwards each connection to the
host's allowlist proxy at ``SOCKET``. ``--listen`` accepts callbacks on a
listening socket the host opened and handed over as file descriptor ``FD``
(sockets keep working across the namespace switch) and connects each one to
whatever the script listens on at ``127.0.0.1:PORT``. Then it runs
``COMMAND`` and exits with its code.

Only the standard library, because it runs on the host's ``/usr/bin/python3``,
whatever its version. Enforcement stays on the host side; this file only
moves bytes.
"""

from __future__ import annotations

import argparse
import contextlib
import socket
import subprocess  # nosemgrep: gitlab.bandit.B404 -- runs the sandboxed command; argv list only
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


def _join(client: socket.socket, upstream: socket.socket) -> None:
    threading.Thread(target=_pump, args=(client, upstream), daemon=True).start()
    threading.Thread(target=_pump, args=(upstream, client), daemon=True).start()


def _serve_proxy(listener: socket.socket, sock_path: str) -> None:
    while True:
        client, _ = listener.accept()
        upstream = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            upstream.connect(sock_path)
        except OSError:
            client.close()
            continue
        _join(client, upstream)


def _serve_listen(listener: socket.socket, port: int) -> None:
    while True:
        client, _ = listener.accept()
        try:
            inside = socket.create_connection(("127.0.0.1", port), timeout=5)
        except OSError:  # the script is not listening (yet); the caller can retry
            client.close()
            continue
        inside.settimeout(None)
        _join(client, inside)


def main(argv: list[str]) -> int:
    """Entry point; see the module docstring."""
    parser = argparse.ArgumentParser(prog="bridge.py")
    parser.add_argument("--proxy", metavar="PORT:SOCKET")
    parser.add_argument("--listen", metavar="FD:PORT", action="append", default=[])
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args(argv)
    command = args.command[1:] if args.command[:1] == ["--"] else args.command
    if not command:
        parser.error("a command after -- is required")
    if args.proxy:
        port, _, sock_path = args.proxy.partition(":")
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind(("127.0.0.1", int(port)))
        listener.listen(32)
        threading.Thread(target=_serve_proxy, args=(listener, sock_path), daemon=True).start()
    for spec in args.listen:
        fd, _, port = spec.partition(":")
        inherited = socket.socket(fileno=int(fd))
        threading.Thread(target=_serve_listen, args=(inherited, int(port)), daemon=True).start()
    # nosemgrep: gitlab.bandit.B603 -- the runner's argv, already inside the sandbox
    return subprocess.call(command)  # noqa: S603


if __name__ == "__main__":  # pragma: no cover - exercised through main() in tests
    sys.exit(main(sys.argv[1:]))
