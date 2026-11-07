"""The app side of a converted Debian program (copied into the .kapp as
``debshim.py``).

A Debian program writes to stdout and expects a terminal; a KOS app has stdin
and stdout on /dev/null and may only send validated commands. This shim bridges
the two: it runs the program from a sealed in-RAM file (never from disk), with
no stdin, a time limit and an output cap, and shows what it printed as a text
page. Nothing the program prints reaches the terminal directly.

Esc quits, r runs it again, up/down scrolls. The sandbox still applies to the
program: no files, no network, no new privileges.
"""

import fcntl
import json
import os
import select
import subprocess
import time

# Linux memfd sealing constants (Python exposes them only from 3.14).
F_ADD_SEALS = getattr(fcntl, "F_ADD_SEALS", 1033)
SEALS = (getattr(fcntl, "F_SEAL_SEAL", 0x1) | getattr(fcntl, "F_SEAL_SHRINK", 0x2)
         | getattr(fcntl, "F_SEAL_GROW", 0x4) | getattr(fcntl, "F_SEAL_WRITE", 0x8))

MAX_OUT = 64 << 10
TIMEOUT = 10.0


def sealed_memfd(label, data):
    fd = os.memfd_create(f"kos-deb:{label}", os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING)
    view = memoryview(data)
    while view:
        view = view[os.write(fd, view):]
    fcntl.fcntl(fd, F_ADD_SEALS, SEALS)
    return fd


def run_program(exe_bytes, argv, timeout=TIMEOUT, limit=MAX_OUT):
    """Run ``exe_bytes`` and return (exit_code, text, notes). Never raises for
    a misbehaving program: a hang is killed, endless output is cut off."""
    fd = sealed_memfd("exe", exe_bytes)
    notes = []
    try:
        p = subprocess.Popen(
            [os.path.basename(argv[0]) if argv else "prog", *argv[1:]],
            executable=f"/proc/self/fd/{fd}", pass_fds=[fd],
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            env={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8", "TERM": "dumb"}, cwd="/")
    finally:
        os.close(fd)
    out = bytearray()
    deadline = time.monotonic() + timeout
    try:
        while True:
            left = deadline - time.monotonic()
            if left <= 0:
                notes.append(f"stopped: ran longer than {timeout:g}s")
                p.kill()
                break
            ready, _, _ = select.select([p.stdout], [], [], min(left, 0.2))
            if ready:
                chunk = os.read(p.stdout.fileno(), 4096)
                if not chunk:
                    break
                out += chunk
                if len(out) > limit:
                    del out[limit:]
                    notes.append(f"stopped: printed more than {limit >> 10} KiB")
                    p.kill()
                    break
            elif p.poll() is not None:
                break
    finally:
        p.stdout.close()
        code = p.wait()
    return code, out.decode("utf-8", "replace"), notes


def main():
    from kos.sdk import App

    app = App()
    meta = json.loads(app.resource("deb.json"))
    exe = app.resource(meta["exe"])
    argv = [meta["exe"], *meta.get("argv", [])]
    title = f"{meta['package']} {meta['version']} (from Debian)"
    lines, top, ran = [], 0, False

    def run():
        code, text, notes = run_program(exe, argv)
        out = text.replace("\r", "").split("\n")
        return out + ["", f"[exit {code}]"] + [f"[{n}]" for n in notes]

    for ev in app.events():
        if ev.get("cmd") == "key":
            k = ev.get("key")
            if k == "escape":
                app.exit(0)
                return
            if k == "r":
                ran = False
            elif k == "up":
                top = max(0, top - 1)
            elif k == "down":
                top = min(max(0, len(lines) - 1), top + 1)
        if not ran:
            lines, top, ran = run(), 0, True
        rows = max(3, app.height - 3)
        app.screen(title, lines[top:top + rows],
                   status="Esc: quit | r: run again | up/down: scroll")
