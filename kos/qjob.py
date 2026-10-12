"""Run one quantum job through a driver app.

The same one-shot shape as running a line of code (``kos/coderun.py``): verify the driver app with the password, work out its
sandbox (network and device grants are asked for here, at this launch), start it in ``cmd`` mode, hand it the job as a
``launch`` message, and read one ``RESULT`` line back. The driver is the only thing that touches the hardware, and it can touch
only the device nodes named in its manifest that you just agreed to open. Time-limited; the driver is killed at the end.
"""

from __future__ import annotations

import json
import os
import select
import socket
import time
from pathlib import Path
from typing import Callable, Optional

from . import cache, loader
from .auth import Authority
from .paths import Paths
from .protocol import Channel, ProtocolError, validate_app_message
from .store import AppStore

MAX_PROGRAM = 64 << 10
MAX_SHOTS = 100_000


class JobError(Exception):
    pass


def check_job(job: dict) -> dict:
    prog = job.get("program")
    if not isinstance(prog, str) or not prog.strip() or len(prog) > MAX_PROGRAM or "\x00" in prog:
        raise JobError(f"a program is OpenQASM text of at most {MAX_PROGRAM >> 10} KiB")
    shots = job.get("shots", 1024)
    if isinstance(shots, bool) or not isinstance(shots, int) or not 1 <= shots <= MAX_SHOTS:
        raise JobError(f"shots is 1 to {MAX_SHOTS}")
    return {"op": "run", "program": prog, "shots": shots, "seed": job.get("seed"), "device": str(job.get("device", ""))[:80]}


def run_job(paths: Paths, authority: Authority, driver: str, job: dict, *, timeout: float = 30.0,
            confirm: Optional[Callable[[str], bool]] = None) -> dict:
    """Run ``job`` on the hardware (or emulator) the ``driver`` app serves. Returns the driver's result dict."""
    from .permit import PermitStore
    from .system import authorize_app_action
    job = check_job(job)
    PermitStore(paths).require(driver)
    store = AppStore(paths)
    with authority.authorize("app.open", driver) as grant:
        app = store.load_verified(driver, grant)
    if app.manifest.driver != "quantum":
        raise JobError(f"{driver} is not a quantum driver")
    if "cmd" not in app.manifest.modes:
        raise JobError(f"{driver} has no cmd mode")
    prompter = authority.prompter
    policy = authorize_app_action(driver, app, "cmd", authority, prompter)
    if app.manifest.devices and not policy.device_paths:
        raise JobError(f"{driver} needs a device node ({', '.join(app.manifest.devices)}) and none was found or allowed")
    paths.ensure()
    cache_dir = cache.alloc(paths, driver, ram=app.manifest.runtime in ("npm", "bundle"))
    loader.apply_to_policy(policy, app, cache_dir)
    if app.manifest.runtime not in ("npm", "bundle"):
        policy.rw_dirs = [*policy.rw_dirs, str(cache_dir)]
    mine, theirs = socket.socketpair()
    proc = loader.launch(loader.plan(app, theirs.fileno(), "cmd", cache_dir), policy, paths.logs / f"{driver}.log")
    theirs.close()
    channel = Channel(mine)
    channel.send({"cmd": "hello", "mode": "cmd", "width": 80, "height": 24})
    channel.send({"cmd": "launch", "command": "job", "line": json.dumps(job)})
    deadline = time.monotonic() + timeout
    result: Optional[dict] = None
    try:
        while result is None:
            left = deadline - time.monotonic()
            if left <= 0:
                raise JobError(f"the driver did not answer within {timeout:.0f}s")
            select.select([channel], [], [], min(left, 0.25))
            try:
                for raw in channel.receive():
                    msg = validate_app_message(raw, "cmd")
                    if msg["cmd"] == "log" and msg["msg"].startswith("RESULT "):
                        result = json.loads(msg["msg"][7:])
                    elif msg["cmd"] == "exit" and result is None:
                        raise JobError("the driver exited without a result")
            except (ProtocolError, ValueError) as e:
                raise JobError(f"the driver broke the protocol: {e}") from None
            if result is None and (channel.closed or proc.poll() is not None):
                raise JobError("the driver stopped before it answered")
    finally:
        channel.send({"cmd": "quit"})
        try:
            os.killpg(proc.pid, 9)
        except (ProcessLookupError, PermissionError):
            pass
        proc.wait()
        channel.close()
        cache.wipe(cache_dir)
    if not isinstance(result, dict):
        raise JobError("the driver's result was not an object")
    result["driver"] = driver
    result["emulated"] = bool(result.get("emulated", False))
    return result
