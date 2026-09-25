"""Process confinement for apps. Fails closed: if a protection cannot be
applied, the app does not start.

Layers, applied in the child between fork and exec:

1. Drop root: if the launcher is root, the app runs as ``nobody``.
2. ``PR_SET_NO_NEW_PRIVS``: setuid binaries cannot give the app privileges back.
3. New user + network + IPC + UTS namespaces. The network namespace is empty,
   so the app has no network at all unless it declared the ``network``
   permission *and* the owner typed the password to allow it.
4. Resource limits (no core dumps, bounded fds/memory).
5. Landlock: the app may read the language runtime and nothing else. It cannot
   read your files, cannot write anywhere, cannot signal processes outside its
   sandbox, and cannot reach abstract unix sockets outside it.

The app's only way to affect the world is the command channel to the session.
"""

from __future__ import annotations

import ctypes
import os
import resource
import sys
from dataclasses import dataclass, field
from pathlib import Path

_libc = ctypes.CDLL(None, use_errno=True)

CLONE_NEWNS = 0x00020000
CLONE_NEWUTS = 0x04000000
CLONE_NEWIPC = 0x08000000
CLONE_NEWUSER = 0x10000000
CLONE_NEWNET = 0x40000000
PR_SET_NO_NEW_PRIVS = 38

# Landlock syscall numbers are identical on every architecture.
SYS_landlock_create_ruleset = 444
SYS_landlock_add_rule = 445
SYS_landlock_restrict_self = 446
LANDLOCK_CREATE_RULESET_VERSION = 1
LANDLOCK_RULE_PATH_BENEATH = 1

FS_EXECUTE = 1 << 0
FS_WRITE_FILE = 1 << 1
FS_READ_FILE = 1 << 2
FS_READ_DIR = 1 << 3
FS_REFER = 1 << 13        # ABI 2
FS_TRUNCATE = 1 << 14     # ABI 3
FS_IOCTL_DEV = 1 << 15    # ABI 5
NET_BIND_TCP = 1 << 0     # ABI 4
NET_CONNECT_TCP = 1 << 1  # ABI 4
SCOPE_ABSTRACT_UNIX = 1 << 0  # ABI 6
SCOPE_SIGNAL = 1 << 1         # ABI 6

_FILE_ONLY_RIGHTS = FS_EXECUTE | FS_WRITE_FILE | FS_READ_FILE | FS_TRUNCATE | FS_IOCTL_DEV
MIN_LANDLOCK_ABI = 1


class SandboxError(RuntimeError):
    pass


class _RulesetAttr(ctypes.Structure):
    _fields_ = [("handled_access_fs", ctypes.c_uint64),
                ("handled_access_net", ctypes.c_uint64),
                ("scoped", ctypes.c_uint64)]


class _PathBeneathAttr(ctypes.Structure):
    _pack_ = 1
    _fields_ = [("allowed_access", ctypes.c_uint64), ("parent_fd", ctypes.c_int32)]


def _syscall(nr: int, *args) -> int:
    r = _libc.syscall(ctypes.c_long(nr), *args)
    if r < 0:
        e = ctypes.get_errno()
        raise OSError(e, os.strerror(e))
    return r


def landlock_abi() -> int:
    try:
        return _syscall(SYS_landlock_create_ruleset, None, ctypes.c_size_t(0),
                        ctypes.c_uint32(LANDLOCK_CREATE_RULESET_VERSION))
    except OSError:
        return 0


def _handled_fs(abi: int) -> int:
    rights = (1 << 13) - 1  # ABI 1: bits 0..12
    if abi >= 2:
        rights |= FS_REFER
    if abi >= 3:
        rights |= FS_TRUNCATE
    if abi >= 5:
        rights |= FS_IOCTL_DEV
    return rights


def default_read_paths() -> list[str]:
    """What an app needs to read: the language runtime and shared libraries."""
    paths = {"/usr", "/lib", "/lib64", "/bin", "/proc/self"}
    for p in (sys.prefix, sys.base_prefix, sys.exec_prefix,
              os.path.dirname(os.path.realpath(sys.executable))):
        paths.add(p)
    # The KOS SDK itself (the directory that contains the ``kos`` package).
    paths.add(str(Path(__file__).resolve().parent.parent))
    return sorted(p for p in paths if os.path.exists(p))


@dataclass
class SandboxPolicy:
    allow_network: bool = False
    read_paths: list[str] = field(default_factory=default_read_paths)
    rw_files: list[str] = field(default_factory=lambda: ["/dev/null"])
    ro_files: list[str] = field(default_factory=lambda: ["/dev/urandom"])
    max_open_files: int = 256
    max_memory: int = 4 << 30
    # Development escape hatch; never set on a real install.
    weak: bool = False

    def __post_init__(self) -> None:
        if self.allow_network:
            self.read_paths = self.read_paths + [p for p in (
                "/etc/resolv.conf", "/etc/hosts", "/etc/nsswitch.conf", "/etc/ssl",
                "/etc/pki", "/etc/ca-certificates") if os.path.exists(p)]

    def probe(self) -> int:
        """Called in the parent before launching; refuses if we can't confine."""
        abi = landlock_abi()
        if abi < MIN_LANDLOCK_ABI and not self.weak:
            raise SandboxError(
                "this kernel has no Landlock support; KOS refuses to run apps unconfined "
                "(enable CONFIG_SECURITY_LANDLOCK and add 'landlock' to lsm=)")
        return abi

    def preexec(self):
        """Return a function to run in the child after fork(), before exec()."""
        abi = self.probe()
        policy = self

        def apply() -> None:
            policy._drop_root()
            if _libc.prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0:
                raise SandboxError("no_new_privs failed")
            flags = CLONE_NEWUSER | CLONE_NEWIPC | CLONE_NEWUTS
            if not policy.allow_network:
                flags |= CLONE_NEWNET
            if _libc.unshare(flags) != 0 and not policy.weak:
                raise SandboxError(f"unshare failed: {os.strerror(ctypes.get_errno())}")
            os.umask(0o077)
            resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
            resource.setrlimit(resource.RLIMIT_NOFILE, (policy.max_open_files,) * 2)
            resource.setrlimit(resource.RLIMIT_AS, (policy.max_memory,) * 2)
            if abi:
                policy._landlock(abi)

        return apply

    @staticmethod
    def _drop_root() -> None:
        if os.geteuid() == 0:
            os.setgroups([])
            os.setresgid(65534, 65534, 65534)
            os.setresuid(65534, 65534, 65534)

    def _landlock(self, abi: int) -> None:
        handled = _handled_fs(abi)
        attr = _RulesetAttr(handled_access_fs=handled)
        size = 8
        if abi >= 4:
            attr.handled_access_net = 0 if self.allow_network else (NET_BIND_TCP | NET_CONNECT_TCP)
            size = 16
        if abi >= 6:
            attr.scoped = SCOPE_ABSTRACT_UNIX | SCOPE_SIGNAL
            size = 24
        ruleset = _syscall(SYS_landlock_create_ruleset, ctypes.byref(attr),
                           ctypes.c_size_t(size), ctypes.c_uint32(0))
        try:
            ro = FS_EXECUTE | FS_READ_FILE | FS_READ_DIR
            for p in self.read_paths:
                self._add_rule(ruleset, p, ro & handled)
            for p in self.ro_files:
                self._add_rule(ruleset, p, FS_READ_FILE)
            for p in self.rw_files:
                self._add_rule(ruleset, p, (FS_READ_FILE | FS_WRITE_FILE | FS_TRUNCATE) & handled)
            _syscall(SYS_landlock_restrict_self, ctypes.c_int(ruleset), ctypes.c_uint32(0))
        finally:
            os.close(ruleset)

    @staticmethod
    def _add_rule(ruleset: int, path: str, rights: int) -> None:
        try:
            fd = os.open(path, os.O_PATH | os.O_CLOEXEC)
        except OSError:
            return  # a missing optional path just stays inaccessible
        try:
            if not os.path.isdir(path):
                rights &= _FILE_ONLY_RIGHTS
            rule = _PathBeneathAttr(allowed_access=rights, parent_fd=fd)
            _syscall(SYS_landlock_add_rule, ctypes.c_int(ruleset),
                     ctypes.c_int(LANDLOCK_RULE_PATH_BENEATH), ctypes.byref(rule),
                     ctypes.c_uint32(0))
        finally:
            os.close(fd)


def report() -> dict:
    """Which protections this kernel supports (for ``kos doctor``)."""
    return {
        "landlock_abi": landlock_abi(),
        "user_namespaces": Path("/proc/self/ns/user").exists(),
        "kvm": os.path.exists("/dev/kvm"),
        "vhost_vsock": os.path.exists("/dev/vhost-vsock"),
        "framebuffer": os.path.exists("/dev/fb0"),
        "evdev": os.path.isdir("/dev/input"),
    }
