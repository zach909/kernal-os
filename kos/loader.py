"""Run an app from a private folder - never from inside its zip.

1. The zip is checked against its seal first. Then **every runtime does the same**: the verified archive is unpacked into a fresh private directory
   (in RAM, ``/dev/shm``, whenever programs may run from there, so unpacked code never touches the disk; mode 0700), every file read-only, and the
   unpacked files are read back and compared with the archive before anything is started. The directory is wiped when the app ends.
2. Python apps: the interpreter imports modules from that folder. Native apps: the ELF entry is executed from it (statically linked).
   npm apps (``runtime: "npm"``): run as ``npm run <script>`` (or ``npx --no-install <tool>``) - offline, no install, inside the same sandbox, with a
   separate writable scratch directory next to the read-only code. Bundles (a program tree from a .deb or AppImage) likewise.
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

from . import cache
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
    big_address_space: bool = False                     # V8 and friends reserve far more address space than they use

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
        if app.manifest.runtime == "bundle":                 # a program tree keeps which files are executable
            os.chmod(target, 0o555 if app.mode_of(name) & 0o111 else 0o444)
        else:
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
    if app.manifest.runtime == "bundle":
        scratch = str(Path(cache_dir) / "scratch")
        return [scratch], [str(Path(cache_dir) / "app")] + ([scratch] if app.manifest.exec_scratch else [])
    return [str(cache_dir)], []


def apply_to_policy(policy: SandboxPolicy, app: KApp, cache_dir: Optional[Path], data_dir: Optional[Path] = None) -> None:
    rw, ro = sandbox_dirs(app, cache_dir)
    if data_dir is not None:                    # the app's own folder: persistent, writable by it alone
        policy.data_dir = str(data_dir)
        rw = [*rw, str(data_dir)]
    policy.rw_dirs = [*policy.rw_dirs, *rw]
    policy.read_paths = [*policy.read_paths, *ro]
    if app.manifest.runtime == "npm":
        policy.max_memory = max(policy.max_memory, 64 << 30)   # V8 reserves address space it does not use
    if app.manifest.runtime == "bundle":
        policy.max_memory = max(policy.max_memory, 16 << 30)


def _npm_env(scratch: Path) -> dict:
    return {"npm_config_offline": "true", "npm_config_update_notifier": "false",
            "npm_config_audit": "false", "npm_config_fund": "false", "npm_config_progress": "false",
            "npm_config_loglevel": "error", "npm_config_cache": str(scratch / "npm-cache"),
            "npm_config_logs_dir": str(scratch / "npm-logs"),
            "npm_config_userconfig": str(scratch / "user.npmrc"),      # distinct, empty: npm refuses
            "npm_config_globalconfig": str(scratch / "global.npmrc")}  # to load one file twice


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
    npm_env = _npm_env(scratch)
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
                      temp_dir=temp, big_address_space=True)


_HOST_BOOT_SH = ("import sys\nsdk = sys.argv[1]\ndel sys.argv[1:2]\nsys.path[:0] = [sdk]\n"
                 "from kos.hostrun import main\nsys.exit(main())\n")


def _plan_bundle(app: KApp, channel_fd: int, mode: str, cache_dir: Optional[Path]) -> LaunchPlan:
    """A foreign program tree (from a .deb or an AppImage). Like every app it starts with ``npm run start``:
    the tree is unpacked read-only into RAM, a tiny generated package.json's ``start`` script launches the
    adapter (kos/hostrun.py) inside the sandbox, and the adapter starts the program as its child (the child
    inherits the sandbox). The program's output becomes a text page; keys go to its stdin."""
    import json
    m = app.manifest
    node, npm_cli, _npx, prefix = npm_tools()
    temp = None
    if cache_dir is None:
        shm = "/dev/shm" if os.access("/dev/shm", os.W_OK) else None
        temp = cache_dir = Path(tempfile.mkdtemp(prefix="kos-run-", dir=shm))
    base = Path(cache_dir)
    app_dir, scratch, host = base / "app", base / "scratch", base / "host"
    scratch.mkdir(mode=0o700, exist_ok=True)
    unpack(app, app_dir)
    host.mkdir(exist_ok=True)
    (host / "package.json").write_text(json.dumps({
        "name": "kos-host", "version": "1.0.0", "private": True,
        "scripts": {"start": '"$KOS_PYTHON" -I -S -B -c "$KOS_HOST_BOOT" "$KOS_SDK_DIR"'}}))
    os.chmod(host / "package.json", 0o444)
    os.chmod(host, 0o555)
    for rc in ("user.npmrc", "global.npmrc"):
        (scratch / rc).write_text("")
    if os.geteuid() == 0:                       # dev/test as root: the app runs as 'nobody'
        os.chmod(base, 0o755)
        for p in (scratch, *scratch.iterdir()):
            os.chown(p, 65534, 65534)
    env = {"KOS_CHANNEL_FD": "0", "KOS_APP": m.name, "KOS_MODE": mode, "KOS_SDK_DIR": SDK_DIR,
           "KOS_PYTHON": os.path.realpath(sys.executable), "KOS_HOST_BOOT": _HOST_BOOT_SH,
           "KOS_APP_DIR": str(app_dir), "KOS_ENTRY": m.entry, "KOS_ARGS": json.dumps(list(m.args)),
           "KOS_CACHE_DIR": str(scratch), "KOS_EXEC_SCRATCH": "1" if m.exec_scratch else "",
           "HOME": str(scratch), "TMPDIR": str(scratch), "LANG": "C.UTF-8",
           "PATH": f"{os.path.dirname(node)}:/usr/bin:/bin", "OPENSSL_CONF": os.devnull,
           **_npm_env(scratch)}
    ro = [str(app_dir), str(host), prefix] + ([str(scratch)] if m.exec_scratch else [])
    return LaunchPlan(argv=[node, npm_cli, "run", "start"], executable=node, env=env, pass_fds=[],
                      cwd=str(host), stdin_fd=channel_fd, rw_dirs=[str(scratch)], ro_dirs=ro, temp_dir=temp, big_address_space=True)


def plan(app: KApp, channel_fd: int, mode: str, cache_dir: Optional[Path] = None) -> LaunchPlan:
    m = app.manifest
    if m.runtime == "npm":
        return _plan_npm(app, channel_fd, mode, cache_dir)
    if m.runtime == "bundle":
        return _plan_bundle(app, channel_fd, mode, cache_dir)
    return _plan_unpacked(app, channel_fd, mode, cache_dir)


def private_root(runtime_needs_exec: bool) -> Path:
    """A fresh private directory for one run's unpacked code: in RAM (/dev/shm) when programs may run from there, so unpacked code never
    touches the disk; mode 0700 (0755 only when developing as root, where the app runs as another user and must be able to reach it)."""
    shm = "/dev/shm" if os.access("/dev/shm", os.W_OK) and (not runtime_needs_exec or cache.shm_executable()) else None
    root = Path(tempfile.mkdtemp(prefix="kos-app-", dir=shm))
    os.chmod(root, 0o755 if os.geteuid() == 0 else 0o700)
    return root


def verify_unpacked(app: KApp, dest: Path) -> None:
    """The files on disk must be exactly the sealed archive's: read them back and compare, so nothing swapped in between is ever run."""
    for name in app.names():
        if not name.endswith("/") and (dest / name).read_bytes() != app.read(name):
            raise KAppError(f"{name} changed while it was being unpacked; not running {app.manifest.name}")


def _plan_unpacked(app: KApp, channel_fd: int, mode: str, cache_dir: Optional[Path]) -> LaunchPlan:
    """Python and native apps never run from inside their zip: the verified archive is unpacked into a private folder (read-only, in RAM when
    possible), checked against the archive, and run from there. The folder is wiped when the app ends."""
    m = app.manifest
    root = private_root(runtime_needs_exec=m.runtime == "native")
    app_dir = root / "app"
    try:
        unpack(app, app_dir)
        verify_unpacked(app, app_dir)
        env = {"KOS_CHANNEL_FD": str(channel_fd), "KOS_APP": m.name, "KOS_MODE": mode, "KOS_APP_DIR": str(app_dir),
               "LANG": "C.UTF-8", "PATH": "/usr/bin:/bin"}
        if cache_dir is not None:
            env["KOS_CACHE_DIR"] = str(cache_dir)
        if m.runtime == "python":
            argv = [os.path.realpath(sys.executable), "-I", "-S", "-B", "-c", _BOOTSTRAP, str(app_dir), m.entry, SDK_DIR]
            exe = argv[0]
        else:
            exe = str(app_dir / m.entry)
            os.chmod(exe, 0o555)
            argv = [m.name]
    except BaseException:
        cache.wipe(root)
        raise
    return LaunchPlan(argv=argv, executable=exe, env=env, pass_fds=[channel_fd], ro_dirs=[str(app_dir)], temp_dir=root)


def launch(p: LaunchPlan, policy: SandboxPolicy, log_path: Optional[Path]) -> subprocess.Popen:
    policy.rw_dirs = [*policy.rw_dirs, *(d for d in p.rw_dirs if d not in policy.rw_dirs)]
    policy.read_paths = [*policy.read_paths, *(d for d in p.ro_dirs if d not in policy.read_paths)]
    if p.big_address_space:
        policy.max_memory = max(policy.max_memory, 64 << 30)
    if policy.data_dir:
        p.env = {**p.env, "KOS_DATA_DIR": policy.data_dir}
    log = open(log_path, "ab") if log_path else subprocess.DEVNULL
    try:
        proc = subprocess.Popen(
            p.argv, executable=p.executable, env=p.env, pass_fds=p.pass_fds,
            stdin=p.stdin_fd if p.stdin_fd is not None else subprocess.DEVNULL,
            stdout=subprocess.DEVNULL, stderr=log,
            cwd=p.cwd, start_new_session=True, preexec_fn=policy.preexec())
        if p.temp_dir is not None:
            weakref.finalize(proc, cache.wipe, p.temp_dir)
        return proc
    finally:
        if log is not subprocess.DEVNULL:
            log.close()
        p.close()
