"""Run an app straight out of its zip, without unzipping anything to disk.

1. The verified zip bytes are copied into a ``memfd`` (an anonymous file that
   exists only in RAM) and the memfd is *sealed*: after sealing, the kernel
   refuses every write, shrink or grow, even from us. What runs is therefore
   byte-for-byte what the seal check approved - there is no window in which
   the file on disk could be swapped (no TOCTOU).
2. Python apps: the interpreter imports modules directly from the zip in the
   memfd (``zipimport`` on ``/proc/self/fd/N``).
   Native apps: the ELF entry is read from the zip into a second sealed memfd
   and executed with ``fexecve`` semantics (exec of ``/proc/self/fd/N``).
   Native apps must be statically linked.
   npm apps (``runtime: "npm"``): npm needs a real folder, so the verified zip
   is unpacked into a private directory on **tmpfs (RAM, never the disk)**,
   read-only to the app, with a separate writable scratch directory, and run as
   ``npm run <script>`` (or ``npx --no-install <tool>``) - offline, no install,
   inside the same sandbox. The whole directory is wiped when the app ends.
3. The app gets one inherited socket (``KOS_CHANNEL_FD``). Its stdin/stdout
   are ``/dev/null``: it cannot write to your terminal. Everything it wants to
   show goes through the session as validated commands.
"""

from __future__ import annotations

import fcntl
import os
import shutil
import subprocess
import sys
import tempfile
import weakref
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from .kapp import KApp, KAppError
from .sandbox import SandboxPolicy

SDK_DIR = str(Path(__file__).resolve().parent.parent)

_BOOTSTRAP = r"""
import sys, importlib
kapp, entry, sdk = sys.argv[1], sys.argv[2], sys.argv[3]
del sys.argv[1:4]
sys.path[:0] = [sdk, kapp]
mod, _, fn = entry.partition(":")
sys.exit(getattr(importlib.import_module(mod), fn or "main")())
"""


def sealed_memfd(label: str, data: bytes) -> int:
    fd = os.memfd_create(f"kos:{label}", os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING)
    try:
        view = memoryview(data)
        while view:
            n = os.write(fd, view)
            view = view[n:]
        fcntl.fcntl(fd, fcntl.F_ADD_SEALS,
                    fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_GROW | fcntl.F_SEAL_WRITE | fcntl.F_SEAL_SEAL)
        os.lseek(fd, 0, os.SEEK_SET)
    except BaseException:
        os.close(fd)
        raise
    return fd


@dataclass
class LaunchPlan:
    argv: list[str]
    executable: str
    env: dict[str, str]
    pass_fds: list[int]
    owned_fds: list[int] = field(default_factory=list)
    cwd: str = "/"
    stdin_fd: Optional[int] = None   # npm drops inherited fds >2, so its channel IS stdin
    rw_dirs: list[str] = field(default_factory=list)    # what the sandbox must allow this app to write
    ro_dirs: list[str] = field(default_factory=list)    # ... and to read (its unpacked code, node)
    temp_dir: Optional[Path] = None                     # scratch we created because the caller gave none

    def close(self) -> None:
        for fd in self.owned_fds:
            try:
                os.close(fd)
            except OSError:
                pass
        self.owned_fds.clear()


def npm_tools() -> tuple[str, str, str, str]:
    """(node, npm-cli.js, npx-cli.js, install prefix) of the Node.js on this machine."""
    node = shutil.which("node")
    if not node:
        raise KAppError("this app runs with npm, but Node.js is not installed on this machine")
    node = os.path.realpath(node)
    prefix = os.path.dirname(os.path.dirname(node))
    npm_dir = os.path.join(prefix, "lib", "node_modules", "npm", "bin")
    npm_cli, npx_cli = os.path.join(npm_dir, "npm-cli.js"), os.path.join(npm_dir, "npx-cli.js")
    if not (os.path.exists(npm_cli) and os.path.exists(npx_cli)):
        raise KAppError(f"npm was not found next to {node}")
    return node, npm_cli, npx_cli, prefix


def unpack(app: KApp, dest: Path) -> None:
    """Write the (already verified) archive into ``dest``, read-only. Names were
    validated by KApp (no absolute paths, no .., no symlinks, bounded size)."""
    dest.mkdir(parents=True, exist_ok=True)
    for name in app.names():
        if name.endswith("/"):
            continue
        target = dest / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(app.read(name))
        os.chmod(target, 0o555 if name.endswith((".sh", ".js", ".py")) or "/bin/" in name else 0o444)
    for root, dirs, _ in os.walk(dest, topdown=False):
        for d in dirs:
            os.chmod(os.path.join(root, d), 0o555)
    os.chmod(dest, 0o555)


def sandbox_dirs(app: KApp, cache_dir: Optional[Path]) -> tuple[list[str], list[str]]:
    """(directories the app may write, extra directories it may read) for this app."""
    if cache_dir is None:
        return [], []
    if app.manifest.runtime == "npm":
        return [str(Path(cache_dir) / "scratch")], [str(Path(cache_dir) / "app"), npm_tools()[3]]
    return [str(cache_dir)], []


def apply_to_policy(policy: SandboxPolicy, app: KApp, cache_dir: Optional[Path]) -> None:
    rw, ro = sandbox_dirs(app, cache_dir)
    policy.rw_dirs = [*policy.rw_dirs, *rw]
    policy.read_paths = [*policy.read_paths, *ro]
    if app.manifest.runtime == "npm":
        policy.max_memory = max(policy.max_memory, 64 << 30)   # V8 reserves address space it does not use


def _plan_npm(app: KApp, channel_fd: int, mode: str, cache_dir: Optional[Path]) -> LaunchPlan:
    m = app.manifest
    node, npm_cli, npx_cli, prefix = npm_tools()
    temp = None
    if cache_dir is None:                       # no scratch from the caller: make a RAM one
        shm = "/dev/shm" if os.access("/dev/shm", os.W_OK) else None
        temp = cache_dir = Path(tempfile.mkdtemp(prefix="kos-run-", dir=shm))
    base = Path(cache_dir)
    app_dir, scratch = base / "app", base / "scratch"
    scratch.mkdir(mode=0o700, exist_ok=True)
    unpack(app, app_dir)
    for rc in ("user.npmrc", "global.npmrc"):
        (scratch / rc).write_text("")
    if os.geteuid() == 0:                       # dev/test as root: the app runs as 'nobody'
        os.chmod(base, 0o755)
        for p in (scratch, *scratch.iterdir()):
            os.chown(p, 65534, 65534)
    sdk_js = os.path.join(SDK_DIR, "sdk", "js", "index.js")
    npm_env = {"npm_config_offline": "true", "npm_config_update_notifier": "false",
               "npm_config_audit": "false", "npm_config_fund": "false", "npm_config_progress": "false",
               "npm_config_loglevel": "error", "npm_config_cache": str(scratch / "npm-cache"),
               "npm_config_logs_dir": str(scratch / "npm-logs"),
               "npm_config_userconfig": str(scratch / "user.npmrc"),      # distinct, empty: npm refuses
               "npm_config_globalconfig": str(scratch / "global.npmrc")}  # to load one file twice
    env = {
        "KOS_CHANNEL_FD": "0", "KOS_APP": m.name, "KOS_MODE": mode,
        "KOS_APP_DIR": str(app_dir), "KOS_CACHE_DIR": str(scratch), "KOS_SDK_DIR": SDK_DIR,
        "KOS_SDK_JS": sdk_js, "KOS_PYTHON": os.path.realpath(sys.executable),
        "HOME": str(scratch), "TMPDIR": str(scratch), "LANG": "C.UTF-8",
        "PATH": f"{os.path.dirname(node)}:/usr/bin:/bin",
        "OPENSSL_CONF": os.devnull,                # node reads /etc/ssl/openssl.cnf at start; the sandbox says no
        "NODE_OPTIONS": "--max-old-space-size=384", **npm_env}
    if m.entry.startswith("npx:"):
        argv = [node, npx_cli, "--no-install", m.entry[4:]]
    else:
        argv = [node, npm_cli, "run", m.entry]
    return LaunchPlan(argv=argv, executable=node, env=env, pass_fds=[], cwd=str(app_dir),
                      stdin_fd=channel_fd, rw_dirs=[str(scratch)], ro_dirs=[str(app_dir), prefix],
                      temp_dir=temp)


def plan(app: KApp, channel_fd: int, mode: str, cache_dir: Optional[Path] = None) -> LaunchPlan:
    m = app.manifest
    if m.runtime == "npm":
        return _plan_npm(app, channel_fd, mode, cache_dir)
    kapp_fd = sealed_memfd(m.name, app.data)
    owned = [kapp_fd]
    env = {
        "KOS_CHANNEL_FD": str(channel_fd),
        "KOS_KAPP_FD": str(kapp_fd),
        "KOS_APP": m.name,
        "KOS_MODE": mode,
        "LANG": "C.UTF-8",
        "PATH": "/usr/bin:/bin",
    }
    if cache_dir is not None:
        env["KOS_CACHE_DIR"] = str(cache_dir)
    if m.runtime == "python":
        exe = os.path.realpath(sys.executable)
        argv = [exe, "-I", "-S", "-B", "-c", _BOOTSTRAP,
                f"/proc/self/fd/{kapp_fd}", m.entry, SDK_DIR]
    else:
        exe_fd = sealed_memfd(f"{m.name}-bin", app.read(m.entry))
        owned.append(exe_fd)
        exe = f"/proc/self/fd/{exe_fd}"
        argv = [m.name]
    return LaunchPlan(argv=argv, executable=exe, env=env,
                      pass_fds=[channel_fd, *owned], owned_fds=owned)


def launch(p: LaunchPlan, policy: SandboxPolicy, log_path: Optional[Path]) -> subprocess.Popen:
    policy.rw_dirs = [*policy.rw_dirs, *(d for d in p.rw_dirs if d not in policy.rw_dirs)]
    policy.read_paths = [*policy.read_paths, *(d for d in p.ro_dirs if d not in policy.read_paths)]
    if p.ro_dirs:
        policy.max_memory = max(policy.max_memory, 64 << 30)
    log = open(log_path, "ab") if log_path else subprocess.DEVNULL
    try:
        proc = subprocess.Popen(
            p.argv, executable=p.executable, env=p.env, pass_fds=p.pass_fds,
            stdin=p.stdin_fd if p.stdin_fd is not None else subprocess.DEVNULL,
            stdout=subprocess.DEVNULL, stderr=log,
            cwd=p.cwd, start_new_session=True, preexec_fn=policy.preexec())
        if p.temp_dir is not None:
            from . import cache
            weakref.finalize(proc, cache.wipe, p.temp_dir)
        return proc
    finally:
        if log is not subprocess.DEVNULL:
            log.close()
        p.close()
