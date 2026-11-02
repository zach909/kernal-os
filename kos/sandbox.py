"""Process confinement for apps. Fails closed: if a protection cannot be
applied, the app does not start.

Layers, applied in the child between fork and exec:

1. Drop root: if the launcher is root, the app runs as ``nobody``.
2. ``PR_SET_NO_NEW_PRIVS``: setuid binaries cannot give the app privileges back.
3. New user + network + IPC + UTS namespaces. The network namespace is empty,
   so the app has no network at all unless it declared the ``network``
   permission *and* the owner typed the password to allow it.
4. Resource limits (no core dumps, bounded fds, memory and file size).
5. Landlock: the app may read the language runtime and nothing else. It cannot
   read your files, cannot write anywhere, cannot signal processes outside its
   sandbox, and cannot reach abstract unix sockets outside it.
6. seccomp (x86_64): a short denylist of syscalls that reach kernel code an app
   has no use for (bpf, perf, io_uring, the keyring, ptrace-style peeking).

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
FS_MAKE_DIR = 1 << 7
FS_MAKE_REG = 1 << 8
FS_REFER = 1 << 13        # ABI 2
FS_TRUNCATE = 1 << 14     # ABI 3
FS_IOCTL_DEV = 1 << 15    # ABI 5
NET_BIND_TCP = 1 << 0     # ABI 4
NET_CONNECT_TCP = 1 << 1  # ABI 4
SCOPE_ABSTRACT_UNIX = 1 << 0  # ABI 6
SCOPE_SIGNAL = 1 << 1         # ABI 6

_FILE_ONLY_RIGHTS = FS_EXECUTE | FS_WRITE_FILE | FS_READ_FILE | FS_TRUNCATE | FS_IOCTL_DEV
MIN_LANDLOCK_ABI = 1

# --- seccomp -----------------------------------------------------------------
# A short denylist, not an allowlist: it turns syscalls an app has no business
# making into a plain EPERM, so the app sees an ordinary error and keeps running.
# Only syscalls whose first gate is NOT already a capability check are listed
# (the app has no capabilities, so mount/reboot/kexec/... already fail by themselves).
# What is left are things that put kernel code in reach of an unprivileged caller
# (bpf, perf, io_uring, the keyring, userfaultfd) and cross-process peeking
# (ptrace, process_vm_*, kcmp; already refused today because every app has its own
# user namespace - this keeps it true if that ever changes), plus unshare/setns,
# which would otherwise only be refused because the app's uid is unmapped.
# Numbers: x86_64, from asm/unistd_64.h. Other architectures get no filter (their
# numbers differ and could not be tested here); `kos doctor` says so.
PR_SET_SECCOMP = 22
SECCOMP_MODE_FILTER = 2
SECCOMP_RET_ALLOW = 0x7FFF0000
SECCOMP_RET_ERRNO = 0x00050000
SECCOMP_RET_KILL_PROCESS = 0x80000000
AUDIT_ARCH_X86_64 = 0xC000003E
X32_SYSCALL_BIT = 0x40000000
SECCOMP_DENY_X86_64 = {
    "ptrace": 101, "process_vm_readv": 310, "process_vm_writev": 311, "kcmp": 312,
    "bpf": 321, "perf_event_open": 298, "userfaultfd": 323,
    "keyctl": 250, "add_key": 248, "request_key": 249,
    "io_uring_setup": 425, "io_uring_enter": 426, "io_uring_register": 427,
    "unshare": 272, "setns": 308,
}


class SandboxError(RuntimeError):
    pass


class _RulesetAttr(ctypes.Structure):
    _fields_ = [("handled_access_fs", ctypes.c_uint64),
                ("handled_access_net", ctypes.c_uint64),
                ("scoped", ctypes.c_uint64)]


class _PathBeneathAttr(ctypes.Structure):
    _pack_ = 1
    _fields_ = [("allowed_access", ctypes.c_uint64), ("parent_fd", ctypes.c_int32)]


class _SockFilter(ctypes.Structure):
    _fields_ = [("code", ctypes.c_uint16), ("jt", ctypes.c_uint8),
                ("jf", ctypes.c_uint8), ("k", ctypes.c_uint32)]


class _SockFprog(ctypes.Structure):
    _fields_ = [("len", ctypes.c_uint16), ("filter", ctypes.POINTER(_SockFilter))]


def seccomp_supported() -> bool:
    """Whether KOS has a seccomp filter for this machine's architecture."""
    return os.uname().machine == "x86_64"


def seccomp_program(deny: dict[str, int] = SECCOMP_DENY_X86_64) -> list[tuple[int, int, int, int]]:
    """The classic-BPF program as ``(code, jt, jf, k)`` rows:

        wrong architecture (i386 compat, ...)   -> kill the process
        x32 syscall numbers (nr >= 0x40000000)  -> EPERM   (else they dodge the list)
        nr in the denylist                      -> EPERM
        anything else                           -> allow
    """
    LD_W_ABS, JEQ_K, JGE_K, RET_K = 0x20, 0x15, 0x35, 0x06
    nrs = sorted(set(deny.values()))
    n = len(nrs)
    allow_at, deny_at = 5 + n, 5 + n + 1
    prog = [
        (LD_W_ABS, 0, 0, 4),                                   # 0: arch
        (JEQ_K, 1, 0, AUDIT_ARCH_X86_64),                      # 1: ours? skip the kill
        (RET_K, 0, 0, SECCOMP_RET_KILL_PROCESS),               # 2
        (LD_W_ABS, 0, 0, 0),                                   # 3: syscall number
        (JGE_K, deny_at - 5, 0, X32_SYSCALL_BIT),              # 4: x32 range
    ]
    for i, nr in enumerate(nrs):                               # 5 .. 5+n-1
        prog.append((JEQ_K, deny_at - (5 + i + 1), 0, nr))
    prog.append((RET_K, 0, 0, SECCOMP_RET_ALLOW))              # allow_at
    prog.append((RET_K, 0, 0, SECCOMP_RET_ERRNO | 1))          # deny_at: EPERM
    assert len(prog) == deny_at + 1 and all(0 <= r[1] <= 255 for r in prog)
    return prog


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
    # Directories the app may create files in - e.g. its per-run cache,
    # wiped by whoever launched it the moment the app's process ends.
    rw_dirs: list[str] = field(default_factory=list)
    ro_files: list[str] = field(default_factory=lambda: ["/dev/urandom"])
    max_open_files: int = 256
    # Address-space cap. A deliberately heavy app (every suite module, SQLite, threads,
    # a 50 MiB buffer) peaks near 200 MB, so 1 GiB is ~5x headroom; it was 4 GiB.
    max_memory: int = 1 << 30
    # Largest single file an app may write (its cache directory is the only place it can).
    max_file_size: int = 64 << 20
    seccomp: bool = True
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
            resource.setrlimit(resource.RLIMIT_FSIZE, (policy.max_file_size,) * 2)
            if abi:
                policy._landlock(abi)
            if policy.seccomp and seccomp_supported():
                policy._seccomp()       # last: it forbids syscalls the steps above needed

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
            rw_dir_rights = (FS_READ_FILE | FS_WRITE_FILE | FS_TRUNCATE | FS_READ_DIR
                            | FS_MAKE_REG | FS_MAKE_DIR) & handled
            for p in self.rw_dirs:
                self._add_rule(ruleset, p, rw_dir_rights)
            _syscall(SYS_landlock_restrict_self, ctypes.c_int(ruleset), ctypes.c_uint32(0))
        finally:
            os.close(ruleset)

    def _seccomp(self) -> None:
        rows = seccomp_program()
        filters = (_SockFilter * len(rows))(*(_SockFilter(*r) for r in rows))
        prog = _SockFprog(len(rows), ctypes.cast(filters, ctypes.POINTER(_SockFilter)))
        if _libc.prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, ctypes.byref(prog), 0, 0) != 0 \
                and not self.weak:
            raise SandboxError(f"seccomp filter failed: {os.strerror(ctypes.get_errno())}")

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
        "seccomp_filter": seccomp_supported(),
        "user_namespaces": Path("/proc/self/ns/user").exists(),
        "kvm": os.path.exists("/dev/kvm"),
        "vhost_vsock": os.path.exists("/dev/vhost-vsock"),
        "framebuffer": os.path.exists("/dev/fb0"),
        "evdev": os.path.isdir("/dev/input"),
    }
