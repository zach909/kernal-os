"""kos-init: PID 1 of the real system (after the pre-boot environment has
unlocked the encrypted disk and switched to it).

What it does, in order:
  1. Mount the kernel pseudo-filesystems with restrictive options.
  2. Apply kernel hardening sysctls.
  3. Ask for the password again (second gate). First boot: choose one.
  4. Start the owner's shell, as an unprivileged user, on the console.
  5. When the shell exits, lock: back to the password prompt.

What it deliberately does NOT do: start any service, daemon, network, timer or
anything else on its own. There is no autostart list to edit, because there is
no autostart. Everything after boot is started by a person who typed the
password.
"""

from __future__ import annotations

import ctypes
import fcntl
import grp
import os
import signal
import subprocess
import sys
import termios
import time

from .auth import AuthError, Authority, AuthorizationDenied, PasswordStore
from .paths import Paths
from .prompt import TTYPrompter

_libc = ctypes.CDLL(None, use_errno=True)
MS_NOSUID, MS_NODEV, MS_NOEXEC = 2, 4, 8

MOUNTS = [
    ("proc", "/proc", "proc", MS_NOSUID | MS_NODEV | MS_NOEXEC, "hidepid=invisible"),
    ("sysfs", "/sys", "sysfs", MS_NOSUID | MS_NODEV | MS_NOEXEC, ""),
    ("devpts", "/dev/pts", "devpts", MS_NOSUID | MS_NOEXEC, "mode=0620,ptmxmode=0666"),
    ("tmpfs", "/dev/shm", "tmpfs", MS_NOSUID | MS_NODEV | MS_NOEXEC, "mode=1777"),
    ("tmpfs", "/run", "tmpfs", MS_NOSUID | MS_NODEV, "mode=0755"),
    ("tmpfs", "/tmp", "tmpfs", MS_NOSUID | MS_NODEV | MS_NOEXEC, "mode=1777"),
]

SYSCTLS = {
    "kernel/kptr_restrict": "2",
    "kernel/dmesg_restrict": "1",
    "kernel/perf_event_paranoid": "3",
    "kernel/unprivileged_bpf_disabled": "1",
    "kernel/kexec_load_disabled": "1",
    "kernel/sysrq": "0",
    "kernel/yama/ptrace_scope": "2",
    "net/core/bpf_jit_harden": "2",
    "fs/protected_symlinks": "1",
    "fs/protected_hardlinks": "1",
    "fs/protected_fifos": "2",
    "fs/protected_regular": "2",
    "fs/suid_dumpable": "0",
    "vm/unprivileged_userfaultfd": "0",
}

OWNER_UID = 1000
OWNER_GROUPS = ("video", "input", "kvm")
BANNER = r"""
  _  _____  ____
 | |/ / _ \/ ___|   security first:
 | ' / | | \___ \   nothing runs without your password.
 | . \ |_| |___) |
 |_|\_\___/|____/
"""


def mount_all() -> None:
    for src, target, fstype, flags, data in MOUNTS:
        os.makedirs(target, exist_ok=True)
        if os.path.ismount(target):
            continue
        if _libc.mount(src.encode(), target.encode(), fstype.encode(),
                       ctypes.c_ulong(flags), data.encode() or None) != 0:
            print(f"kos-init: mount {target} failed: {os.strerror(ctypes.get_errno())}")


def harden() -> None:
    for key, value in SYSCTLS.items():
        try:
            with open(f"/proc/sys/{key}", "w") as f:
                f.write(value)
        except OSError:
            pass  # not every kernel has every knob


def _owner_groups() -> list[int]:
    out = []
    for name in OWNER_GROUPS:
        try:
            out.append(grp.getgrnam(name).gr_gid)
        except KeyError:
            pass
    return out


def start_shell(console: str, as_root: bool = False) -> int:
    """`as_root` is the literal, deliberate reversal of "no root login
    exists": it's only ever True when the login a moment ago verified
    against the *admin* password specifically (see `login_loop` and
    `Grant.via_admin`), which itself only exists if someone with full
    owner access explicitly ran `kos admin setup`. The owner's own
    password can never land here as root."""
    shell = os.environ.get("KOS_SHELL", "/bin/sh")
    user = "root" if as_root else "owner"
    env = {"HOME": "/root" if as_root else "/home/owner", "USER": user,
           "TERM": os.environ.get("TERM", "linux"),
           "PATH": "/opt/kos/bin:/usr/local/bin:/usr/bin:/bin", "KOS_ROOT": "/",
           "LANG": "C.UTF-8"}
    groups = _owner_groups()

    def child_setup() -> None:
        os.setsid()
        fd = os.open(console, os.O_RDWR)
        fcntl.ioctl(fd, termios.TIOCSCTTY, 0)
        for std in (0, 1, 2):
            os.dup2(fd, std)
        if os.getuid() == 0 and not as_root:
            os.setgroups(groups)
            os.setresgid(OWNER_UID, OWNER_UID, OWNER_UID)
            os.setresuid(OWNER_UID, OWNER_UID, OWNER_UID)
        # as_root: already uid 0 (kos-init is PID 1); nothing to drop.

    proc = subprocess.Popen([shell, "-l"], env=env, cwd=env["HOME"] if os.path.isdir(env["HOME"])
                            else "/", preexec_fn=child_setup, close_fds=True)
    # PID 1 must reap every orphan, not just the shell.
    while True:
        try:
            pid, status = os.wait()
        except ChildProcessError:
            return 0
        if pid == proc.pid:
            return os.waitstatus_to_exitcode(status)


def login_loop(paths: Paths, console: str) -> None:
    prompter = TTYPrompter(console)
    store = PasswordStore(paths)
    if not store.exists():
        prompter.info(BANNER + "\nFirst boot. Choose the password that protects everything.")
        from .cli import _new_password
        store.create(_new_password(prompter)).wipe()
    authority = Authority(paths, prompter)
    while True:
        prompter.info(BANNER)
        try:
            grant = authority.authorize("session.login")
        except AuthorizationDenied:
            prompter.info("Locked.")
            time.sleep(2)
            continue
        except AuthError as e:
            prompter.info(f"auth error: {e}")
            time.sleep(5)
            continue
        as_root = grant.via_admin
        grant.close()
        if as_root:
            prompter.info("Unlocked as ADMIN - root shell. Exit the shell to lock.\n")
        else:
            prompter.info("Unlocked. Type 'run APP' or 'run graphical APP'. Exit the shell to lock.\n")
        start_shell(console, as_root=as_root)
        prompter.info("\nSession ended - locked.")


def main() -> None:
    if os.getpid() == 1:
        for sig in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP, signal.SIGTSTP):
            signal.signal(sig, signal.SIG_IGN)
        mount_all()
        harden()
    console = os.environ.get("KOS_CONSOLE", "/dev/console")
    paths = Paths.from_env()
    while True:
        try:
            login_loop(paths, console)
        except Exception as e:  # PID 1 must never exit: that panics the kernel
            print(f"kos-init: {e!r}; restarting login", file=sys.stderr)
            time.sleep(2)


if __name__ == "__main__":
    main()
