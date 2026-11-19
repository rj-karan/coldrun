"""Runs inside the sandbox: the script's only doors to the outside.

``python bridge.py [--proxy PORT:SOCKET] [--listen FD:PORT ...] -- COMMAND...``

``--proxy`` listens on ``127.0.0.1:PORT`` and forwards each connection to the
host's allowlist proxy at ``SOCKET``. ``--listen`` accepts callbacks on a
listening socket the host opened and handed over as file descriptor ``FD``
(sockets keep working across the namespace switch) and connects each one to
whatever the script listens on at ``127.0.0.1:PORT``. Then it runs
``COMMAND`` and exits with its code.

It runs on whatever Python the sandbox has: the host's ``python3`` under
bubblewrap, or the image's interpreter under Podman, Python 2.7 included. So
it is written in the subset both understand, with type comments instead of
annotations. Enforcement stays on the host side; this file only moves bytes.
"""

import argparse
import socket
import subprocess  # nosemgrep: gitlab.bandit.B404 -- runs the sandboxed command; argv list only
import sys
import threading


def _spawn(target, *args):
    # type: (object, object) -> None
    t = threading.Thread(target=target, args=args)  # type: ignore[arg-type]
    t.daemon = True  # Python 2 has no daemon= argument
    t.start()


def _pump(src, dst):
    # type: (socket.socket, socket.socket) -> None
    try:
        while True:
            chunk = src.recv(65536)
            if not chunk:
                break
            dst.sendall(chunk)
    except socket.error:  # pragma: no cover - a peer vanished mid-copy; same path as netproxy.pump
        pass
    finally:
        try:
            dst.shutdown(socket.SHUT_WR)
        except socket.error:
            pass


def _join(client, upstream):
    # type: (socket.socket, socket.socket) -> None
    _spawn(_pump, client, upstream)
    _spawn(_pump, upstream, client)


def _serve_proxy(listener, sock_path):
    # type: (socket.socket, str) -> None
    while True:
        client, _ = listener.accept()
        upstream = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            upstream.connect(sock_path)
        except socket.error:
            client.close()
            continue
        _join(client, upstream)


def _serve_listen(listener, port):
    # type: (socket.socket, int) -> None
    while True:
        client, _ = listener.accept()
        try:
            inside = socket.create_connection(("127.0.0.1", port), timeout=5)
        except socket.error:  # the script is not listening (yet); the caller can retry
            client.close()
            continue
        inside.settimeout(None)
        _join(client, inside)


def main(argv):
    # type: (list[str]) -> int
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
        _spawn(_serve_proxy, listener, sock_path)
    for spec in args.listen:
        fd, _, port = spec.partition(":")
        _spawn(_serve_listen, socket.socket(fileno=int(fd)), int(port))
    # nosemgrep: gitlab.bandit.B603 -- the runner's argv, already inside the sandbox
    return subprocess.call(command)  # noqa: S603


if __name__ == "__main__":  # pragma: no cover - exercised through main() in tests
    sys.exit(main(sys.argv[1:]))
