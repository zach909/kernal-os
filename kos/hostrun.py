"""Runs a *foreign* program (from a .deb or an AppImage) inside the KOS sandbox.

The program does not speak the KOS protocol. This adapter does: it is the sandboxed
process, it starts the program as its child (the child inherits the sandbox - no
network, no files but its own tree and scratch, Landlock), and it turns the
program's text output into a page the OS can show, and the keys the OS sends into
the program's standard input.

Honest limits: the program's stdin/stdout are pipes, not a terminal, so line-oriented
programs work (command-line tools, scripts, many AppImages' ``--help``/``--version``),
full-screen curses programs do not; and a program that wants a graphical display has
nothing to connect to - KOS is not an X server. Those say so instead of failing silently.
"""

from __future__ import annotations

import json
import os
import re
import select
import signal
import socket
import subprocess
import sys
import time

MAX_OUTPUT = 1 << 20            # bytes read from the program in total
MAX_LINES = 600                 # lines kept on the page
_ANSI = re.compile(r"\x1b\[[0-9;?]*[ -/]*[@-~]|\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)|\x1b[@-Z\\-_]")
_CLEAR = re.compile(r"\x1b\[[0-9;]*[HJ]")
_GUI_HINTS = ("cannot open display", "could not connect to display", "no protocol specified",
              "unable to open display", "wayland", "xcb", "gtk-warning", "qt.qpa")


class Page:
    """A scrolling page of text built from a byte stream (CR, BS, tabs and ANSI handled)."""

    def __init__(self) -> None:
        self.lines: list[str] = [""]
        self.total = 0

    def feed(self, data: bytes) -> None:
        self.total += len(data)
        text = data.decode("utf-8", "replace")
        for piece in re.split(r"(\x1b\[[0-9;]*[HJ])", text):
            if _CLEAR.fullmatch(piece):
                if piece.endswith("J"):
                    self.lines = [""]
                continue
            piece = _ANSI.sub("", piece)
            for ch in piece:
                if ch == "\n":
                    self.lines.append("")
                elif ch == "\r":
                    self.lines[-1] = ""
                elif ch == "\b":
                    self.lines[-1] = self.lines[-1][:-1]
                elif ch == "\t":
                    self.lines[-1] += "    "
                elif ch >= " " and ch != "\x7f":
                    self.lines[-1] += ch
        del self.lines[:-MAX_LINES]


def child_env(app_dir: str, scratch: str, exec_scratch: bool) -> dict:
    """What the program sees: its own tree first, a private home, nothing of the owner's."""
    libs = []
    for rel in ("usr/lib", "lib", "usr/lib64", "lib64", "usr/local/lib"):
        base = os.path.join(app_dir, rel)
        if os.path.isdir(base):
            libs.append(base)
            try:
                libs += [os.path.join(base, d) for d in sorted(os.listdir(base))
                         if os.path.isdir(os.path.join(base, d)) and ("linux-gnu" in d or d.startswith("x86_64"))]
            except OSError:
                pass
    env = {"HOME": scratch, "TMPDIR": scratch, "LANG": "C.UTF-8", "TERM": "dumb", "NO_COLOR": "1",
           "PATH": ":".join([os.path.join(app_dir, "usr/bin"), os.path.join(app_dir, "bin"), "/usr/bin", "/bin"]),
           "XDG_DATA_DIRS": os.path.join(app_dir, "usr/share") + ":/usr/share",
           "XDG_CONFIG_HOME": os.path.join(scratch, "config"), "XDG_CACHE_HOME": os.path.join(scratch, "cache")}
    if libs:
        env["LD_LIBRARY_PATH"] = ":".join(libs)
    if exec_scratch:                                # AppImage: unpack into scratch and run from there, no FUSE
        env["APPIMAGE_EXTRACT_AND_RUN"] = "1"
        env["NO_CLEANUP"] = ""
    return env


def main() -> int:
    from kos.sdk import App

    app = App()
    mode = app.mode
    app_dir, scratch = os.environ["KOS_APP_DIR"], os.environ["KOS_CACHE_DIR"]
    entry = os.path.join(app_dir, os.environ["KOS_ENTRY"])
    args = json.loads(os.environ.get("KOS_ARGS", "[]"))
    name = os.environ.get("KOS_APP", "program")
    sock: socket.socket = app._sock
    page, typed, status = Page(), "", "starting"
    child = None
    code = None
    inbuf = b""
    t0 = time.monotonic()

    def draw() -> None:
        if mode != "tui":
            return
        rows = max(3, app.height - 2)
        shown = list(page.lines)
        if code is None and typed:
            shown[-1] = shown[-1] + typed
        body = shown[-rows:]
        app.screen(name, [ln[:max(8, app.width)] for ln in body],
                   status[:max(8, app.width)])

    try:
        child = subprocess.Popen([entry, *args], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                 stderr=subprocess.STDOUT, cwd=scratch,
                                 env=child_env(app_dir, scratch, bool(os.environ.get("KOS_EXEC_SCRATCH"))),
                                 start_new_session=True, close_fds=True)
        status = "running - type to send input, Enter sends, Esc stops it"
    except OSError as e:
        page.feed(f"could not start the program: {e}\n".encode())
        code = 127
        status = "could not start - Esc to close"
    os.set_blocking(child.stdout.fileno(), False) if child else None
    draw()
    quit_now = False
    while not quit_now:
        fds = [sock] + ([child.stdout] if child and code is None else [])
        ready, _, _ = select.select(fds, [], [], 0.25)
        dirty = False
        for r in ready:
            if r is sock:
                chunk = sock.recv(65536)
                if not chunk:
                    quit_now = True
                    break
                inbuf += chunk
            else:
                try:
                    data = os.read(child.stdout.fileno(), 65536)
                except BlockingIOError:
                    data = None
                if data == b"":
                    code = child.wait()
                elif data and page.total < MAX_OUTPUT:
                    page.feed(data)
                    dirty = True
        if child is not None and code is None and child.poll() is not None:
            for _ in range(8):                              # drain what the program wrote just before it ended
                try:
                    data = os.read(child.stdout.fileno(), 65536)
                except (BlockingIOError, OSError):
                    break
                if not data:
                    break
                page.feed(data)
            code = child.returncode
            dirty = True
        if code is not None and "exited" not in status and "could not" not in status:
            tail = "\n".join(page.lines[-20:]).lower()
            hint = "  (it wants a graphical display; KOS has none for it)" if any(h in tail for h in _GUI_HINTS) else ""
            status = f"exited with status {code}{hint} - Esc closes"
            dirty = True
            if mode == "cmd":
                break
        while b"\n" in inbuf:
            line, inbuf = inbuf.split(b"\n", 1)
            try:
                ev = json.loads(line)
            except ValueError:
                continue
            c = ev.get("cmd")
            if c == "hello":
                app.width, app.height = ev.get("width", app.width), ev.get("height", app.height)
                dirty = True
            elif c == "quit":
                quit_now = True
            elif c == "key":
                k = ev.get("key", "")
                if k == "escape":
                    quit_now = True
                elif code is None and child:
                    try:
                        if k == "enter":
                            child.stdin.write((typed + "\n").encode())
                            child.stdin.flush()
                            page.feed((typed + "\n").encode())
                            typed = ""
                        elif k == "backspace":
                            typed = typed[:-1]
                        elif len(k) == 1 and k >= " ":
                            typed += k
                    except (BrokenPipeError, OSError):
                        pass
                    dirty = True
        if dirty or (mode == "tui" and time.monotonic() - t0 < 0.1):
            draw()
        if mode == "cmd" and code is not None:
            break
    if child is not None and code is None:
        try:
            os.killpg(child.pid, signal.SIGKILL)
        except (ProcessLookupError, PermissionError):
            pass
    if mode != "tui":
        app.log("\n".join(page.lines)[-3000:])
    app.exit(code or 0)
    return 0


if __name__ == "__main__":
    sys.exit(main())
