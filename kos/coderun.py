"""A line of code is a command too.

Every line typed into the line shell is a command, whatever language it is
in. For human language that means one of KOS's own commands (``lang.py``).
For code it means: *run this line* - but never on the host. A code line runs
as a one-shot app, built in memory, under the same sandbox as every other
app (unprivileged user, no network, no files, no signals, namespaces,
Landlock), after a security scan and with your password, with a time limit.
Its output comes back as ``log`` commands over the usual protocol; the
private scratch directory is wiped when it ends.

Each line is its own app: nothing carries over to the next line.

Python runs as an app (the host interpreter, isolated mode). Every other
language is a row in ``runtimes.py``: its trusted interpreter is run directly
under the very same sandbox, in a private scratch directory, with the same time
limit and a cap on how much output it may produce. A language with no row, or
whose program is missing or untrusted, is still understood, scanned and logged -
it reports that and runs nothing.
"""

from __future__ import annotations

import io
import os
import select
import socket
import subprocess
import time
import zipfile
from pathlib import Path
from typing import Callable

from . import cache, loader, runtimes
from .auth import Authority
from .kapp import KApp
from .paths import Paths
from .protocol import Channel, ProtocolError, escape_text, validate_app_message
from .sandbox import SandboxPolicy
from .scan import scan_bytes


def _now_ms() -> int:
    """A monotonic clock in whole milliseconds (the OS keeps no decimals)."""
    return time.monotonic_ns() // 1_000_000


def _wait(files, ms: int) -> bool:
    """Wait up to ``ms`` whole milliseconds for any of ``files`` to be readable (or hung up)."""
    poller = select.poll()
    for f in files:
        poller.register(f, select.POLLIN | select.POLLHUP | select.POLLERR)
    return bool(poller.poll(max(0, ms)))

PYTHON_LIKE = {"python", "assignment", "code call", "comment"}
MAX_LINE_CODE = 4000
MAX_OUTPUT = 64 << 10           # bytes a foreign-language line may print before it is stopped
NO_RUNTIME = 66
TIMED_OUT = 124
OUTPUT_LIMIT = 123

_RUNNER = '''\
import contextlib, io, traceback
from kos.sdk import App


def main():
    app = App()
    for ev in app.events():          # wait for the OS's hello, then run exactly once
        break
    code = app.resource("line.py").decode()
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(buf):
        try:
            exec(compile(code, "<line>", "exec"), {"__name__": "__main__"})
        except BaseException:
            traceback.print_exc()
    app.log(buf.getvalue()[-3000:])
    app.exit(0)
'''

_MANIFEST = ('{"name": "codeline", "version": "1", "runtime": "python", "entry": "runner:main", '
             '"modes": ["cmd"], "description": "one line of code, run as a sandboxed app"}')


def build_kapp(code: str) -> KApp:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("manifest.json", _MANIFEST)
        z.writestr("runner.py", _RUNNER)
        z.writestr("line.py", code)
    return KApp(buf.getvalue())


def run_code(paths: Paths, get_authority: Callable[[], Authority], code: str, language: str, *,
             timeout: int = 10, out: Callable[[str], None] = print) -> int:
    """Run one code line as a sandboxed app. Returns an exit status."""
    if len(code) > MAX_LINE_CODE:
        raise ValueError("that line is too long to run")
    result = scan_bytes(code.encode(), label="<line>")
    if not result.clean:
        out(f"blocked by the security scan: {result.summary()}")
        return 3
    runnable = language in PYTHON_LIKE or runtimes.canonical(language) == "python"
    if runnable:
        try:
            compile(code, "<line>", "exec")
        except SyntaxError:
            runnable = False
    if not runnable:
        try:
            rt = runtimes.find(paths, language) if runtimes.canonical(language) != "python" else None
        except runtimes.LanguageError as e:
            out(f"refused: {e}")
            return NO_RUNTIME
        if rt is not None:
            return _run_foreign(paths, get_authority, rt, code, timeout, out)
        have = ", ".join(runtimes.available(paths))
        out(f"understood as {language} code, but there is no sandboxed {language} runtime here "
            f"(available: {have}; see 'kos runtimes') - nothing was run.")
        return NO_RUNTIME
    label = code if len(code) <= 40 else code[:37] + "..."
    with get_authority().authorize("code.run", label) as _grant:
        pass                                   # the password is the permission; nothing to derive
    app = build_kapp(code)
    paths.ensure()
    cache_dir = cache.alloc(paths, "codeline")
    policy = SandboxPolicy(weak=os.environ.get("KOS_DEV_WEAK_SANDBOX") == "1")
    policy.rw_dirs = [*policy.rw_dirs, str(cache_dir)]
    mine, theirs = socket.socketpair()
    proc = loader.launch(loader.plan(app, theirs.fileno(), "cmd", cache_dir), policy,
                         paths.logs.joinpath("codeline.log"))
    theirs.close()
    channel = Channel(mine)
    channel.send({"cmd": "hello", "mode": "cmd", "width": 80, "height": 24})
    code_out, deadline = 0, _now_ms() + timeout * 1000
    try:
        while True:
            left = deadline - _now_ms()
            if left <= 0:
                out(f"stopped: ran longer than {timeout:.0f}s")
                code_out = TIMED_OUT
                break
            _wait([channel], min(left, 250))
            try:
                for raw in channel.receive():
                    msg = validate_app_message(raw, "cmd")
                    if msg["cmd"] == "log" and msg["msg"]:
                        out(msg["msg"])
                    elif msg["cmd"] == "exit":
                        return code_out
            except ProtocolError as e:
                out(f"stopped: the code broke the protocol ({e})")
                return 125
            if channel.closed or proc.poll() is not None:
                break
    finally:
        channel.send({"cmd": "quit"})
        try:
            os.killpg(proc.pid, 9)
        except (ProcessLookupError, PermissionError):
            pass
        proc.wait()
        channel.close()
        cache.wipe(cache_dir)
    return code_out


def _text(raw: bytes) -> str:
    """Output of a program we do not trust: visible escapes for control and bidi characters,
    so it cannot move the cursor, clear the screen or pass for the OS's own prompt."""
    text = raw.decode("utf-8", "replace").replace("\t", "    ").replace("\r\n", "\n")
    return "\n".join(escape_text(line, 2000) for line in text.split("\n"))


def _run_foreign(paths: Paths, get_authority: Callable[[], Authority], rt: runtimes.Runtime,
                 code: str, timeout: int, out: Callable[[str], None]) -> int:
    """Run one line in another language: its trusted interpreter, directly, in the sandbox.
    Same order as Python: scan (done by the caller), then the password, then launch."""
    try:
        argv = rt.argv(code)
    except runtimes.LanguageError as e:
        out(f"refused: {e}")
        return NO_RUNTIME
    label = code if len(code) <= 40 else code[:37] + "..."
    with get_authority().authorize("code.run", f"{rt.name}: {label}") as _grant:
        pass
    paths.ensure()
    cache_dir = cache.alloc(paths, "codeline")
    policy = SandboxPolicy(weak=os.environ.get("KOS_DEV_WEAK_SANDBOX") == "1")
    policy.read_paths = sorted({*policy.read_paths, *rt.read_paths})
    policy.rw_dirs = [*policy.rw_dirs, str(cache_dir)]
    env = {"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8", "HOME": str(cache_dir), "TMPDIR": str(cache_dir),
           **dict(rt.env)}
    reader, writer = os.pipe()
    try:
        proc = subprocess.Popen(
            argv, executable=rt.exe, env=env, stdin=subprocess.DEVNULL, stdout=writer, stderr=writer,
            cwd=str(cache_dir), start_new_session=True, close_fds=True, preexec_fn=policy.preexec())
    except BaseException:
        os.close(reader)
        cache.wipe(cache_dir)
        raise
    finally:
        os.close(writer)
    status, buf, deadline = None, bytearray(), _now_ms() + timeout * 1000
    try:
        while True:
            left = deadline - _now_ms()
            if left <= 0:
                out(f"stopped: ran longer than {timeout:.0f}s")
                status = TIMED_OUT
                break
            ready = _wait([reader], min(left, 250))
            if not ready and proc.poll() is not None:
                break                              # done, and nothing left to read
            if ready:
                chunk = os.read(reader, 65536)
                if not chunk:                      # every writer closed: the program is done
                    break
                buf += chunk
                if len(buf) > MAX_OUTPUT:
                    del buf[MAX_OUTPUT:]
                    out(f"stopped: printed more than {MAX_OUTPUT >> 10} KiB")
                    status = OUTPUT_LIMIT
                    break
    finally:
        try:
            os.killpg(proc.pid, 9)                # also anything it started
        except (ProcessLookupError, PermissionError):
            pass
        proc.wait()
        os.close(reader)
        cache.wipe(cache_dir)
    text = _text(bytes(buf)).rstrip("\n")
    if text:
        out(text)
    return proc.returncode if status is None else status
