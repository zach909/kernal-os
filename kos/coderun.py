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

Python runs on the OS's own interpreter. C, C++, Go, Rust, JavaScript, Ruby, Perl and PHP run through ``compiler.py``: the line is
built (if the language is compiled) and run by the machine's own toolchain *inside* the same sandbox, in the same scratch directory.
A line in a language with no toolchain here is still a command - understood, scanned and logged - but it reports that and does nothing.
"""

from __future__ import annotations

import io
import json
import os
import select
import socket
import time
import zipfile
from pathlib import Path
from typing import Callable

from . import cache, compiler, loader
from .auth import Authority
from .kapp import KApp
from .paths import Paths
from .protocol import Channel, ProtocolError, validate_app_message
from .sandbox import SandboxPolicy
from .scan import scan_bytes

PYTHON_LIKE = {"python", "assignment", "code call", "comment"}
MAX_LINE_CODE = 4000
NO_RUNTIME = 66
TIMED_OUT = 124

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


def compiler_kapp(plan: "compiler.Plan") -> KApp:
    """The one-shot app that builds and runs a line of a compiled or foreign language (see ``compiler.py``)."""
    buf = io.BytesIO()
    cfg = {"filename": plan.filename, "build": plan.build, "run": plan.run, "env": plan.env, "build_limit": compiler.BUILD_LIMIT, "run_limit": compiler.RUN_LIMIT}
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("manifest.json", _MANIFEST)
        z.writestr("runner.py", compiler.RUNNER)
        z.writestr("plan.json", json.dumps(cfg))
        z.writestr("source", plan.source)
    return KApp(buf.getvalue())


def run_code(paths: Paths, get_authority: Callable[[], Authority], code: str, language: str, *,
             timeout: float = 10.0, out: Callable[[str], None] = print) -> int:
    """Run one code line as a sandboxed app. Returns an exit status."""
    if len(code) > MAX_LINE_CODE:
        raise ValueError("that line is too long to run")
    result = scan_bytes(code.encode(), label="<line>")
    if not result.clean:
        out(f"blocked by the security scan: {result.summary()}")
        return 3
    runnable = language in PYTHON_LIKE
    if runnable:
        try:
            compile(code, "<line>", "exec")
        except SyntaxError:
            runnable = False
    toolchain = None
    if not runnable:
        lang = compiler.canonical(language, code)
        try:
            if lang is None:
                raise compiler.CompilerError(f"understood as {language} code, but there is no {language} compiler or interpreter wired in")
            toolchain = compiler.plan(lang, code)
        except compiler.CompilerError as e:
            out(f"understood as {language} code, but it cannot run here: {e} - nothing was run.")
            return NO_RUNTIME
    label = code if len(code) <= 40 else code[:37] + "..."
    with get_authority().authorize("code.run", label) as _grant:
        pass                                   # the password is the permission; nothing to derive
    app = build_kapp(code) if toolchain is None else compiler_kapp(toolchain)
    paths.ensure()
    cache_dir = cache.alloc(paths, "codeline") if toolchain is None else cache.alloc_exec(paths, "codeline")
    policy = SandboxPolicy(weak=os.environ.get("KOS_DEV_WEAK_SANDBOX") == "1")
    policy.rw_dirs = [*policy.rw_dirs, str(cache_dir)]
    if toolchain is not None:                  # the toolchain is read and run, never written; what it builds runs from the scratch directory
        policy.read_paths = [*policy.read_paths, *toolchain.read_paths, str(cache_dir)]
        policy.max_memory = max(policy.max_memory, 32 << 30)           # rustc and go reserve far more address space than they use
        timeout = max(timeout, 60.0)
    mine, theirs = socket.socketpair()
    proc = loader.launch(loader.plan(app, theirs.fileno(), "cmd", cache_dir), policy,
                         paths.logs / "codeline.log")
    theirs.close()
    channel = Channel(mine)
    channel.send({"cmd": "hello", "mode": "cmd", "width": 80, "height": 24})
    code_out, deadline = 0, time.monotonic() + timeout
    try:
        while True:
            left = deadline - time.monotonic()
            if left <= 0:
                out(f"stopped: ran longer than {timeout:.0f}s")
                code_out = TIMED_OUT
                break
            select.select([channel], [], [], min(left, 0.25))
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
