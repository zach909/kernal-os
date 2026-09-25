"""Runs *inside* a cell (a separate Linux kernel). Receives an app over vsock
and runs it with the same sandbox and the same zip-in-RAM loader as the host.

The vsock connection itself becomes the app's command channel, so the host
session talks to the app exactly as if it were local.

The host has already checked the app's seal with the owner's password before
sending it; the cell has no password material at all (a compromised cell
learns nothing that would let it seal or unlock anything).
"""

from __future__ import annotations

import json
import os
import socket
import sys

from . import loader
from .kapp import MAX_ARCHIVE, KApp, KAppError
from .sandbox import SandboxPolicy

MAX_HEADER = 4096


def _recv_exact(conn: socket.socket, n: int) -> bytes:
    buf = bytearray()
    while len(buf) < n:
        chunk = conn.recv(min(1 << 20, n - len(buf)))
        if not chunk:
            raise ConnectionError("host closed the connection")
        buf += chunk
    return bytes(buf)


def _recv_header(conn: socket.socket) -> dict:
    buf = bytearray()
    while not buf.endswith(b"\n"):
        c = conn.recv(1)
        if not c:
            raise ConnectionError("host closed the connection")
        buf += c
        if len(buf) > MAX_HEADER:
            raise ValueError("header too large")
    h = json.loads(buf)
    if h.get("cmd") != "load" or h.get("mode") not in ("tui", "graphical"):
        raise ValueError("bad load header")
    if not isinstance(h.get("size"), int) or not 0 < h["size"] <= MAX_ARCHIVE:
        raise ValueError("bad size")
    return h


def handle(conn: socket.socket, policy: SandboxPolicy):
    """Receive one app and start it. Returns the Popen."""
    h = _recv_header(conn)
    app = KApp(_recv_exact(conn, h["size"]))
    if app.manifest.name != h.get("name"):
        raise KAppError("app name does not match header")
    if "network" in app.manifest.permissions:
        # Cells have no network device at all; the permission can't be honoured.
        policy.allow_network = False
    p = loader.plan(app, conn.fileno(), h["mode"])
    return loader.launch(p, policy, log_path=None)


def serve(listener: socket.socket, policy_factory=SandboxPolicy, once: bool = False) -> None:
    while True:
        conn, _ = listener.accept()
        try:
            proc = handle(conn, policy_factory())
        except (OSError, ValueError, KAppError) as e:
            print(f"kos-cellagent: rejected app: {e}", file=sys.stderr)
            conn.close()
            if once:
                return
            continue
        conn.close()  # the app holds its own copy of the socket
        if once:
            proc.wait()
            return
        # reap finished apps without blocking new connections
        try:
            while os.waitpid(-1, os.WNOHANG)[0]:
                pass
        except ChildProcessError:
            pass


def main() -> None:
    port = int(os.environ.get("KOS_AGENT_PORT", "7000"))
    listener = socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM)
    listener.bind((socket.VMADDR_CID_ANY, port))
    listener.listen(8)
    print(f"kos-cellagent: listening on vsock port {port}", file=sys.stderr)
    serve(listener)


if __name__ == "__main__":
    main()
