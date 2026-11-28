# The KOS kernel

KOS does not run on a stock kernel. `kernel/` holds a patch for Linux **6.12.116** that adds one
Linux Security Module, `security/kos`, and the scripts that build and test it. This page is what the
module does, what it does not, and how to work on it.

## What it is for

An app is a process the KOS core has *confined*. The kernel module makes three promises about a
confined process that no userspace code can break, because the process cannot reach the code that
keeps them:

1. **It makes no connection** - connect, bind, listen, or send to an address - that the owner has not
   allowed with a rule naming that app, that protocol, that direction, that IP address and that port.
2. **It touches no hardware** - it cannot open any device node but `null`, `zero`, `full`, `random`
   and `urandom`, and cannot create one.
3. **It cannot reach into other processes or the kernel's debugging interfaces** - `ptrace`, `bpf`,
   `perf_event_open` are refused.

Every allowed and every denied connection attempt is written to a log the core copies into the
audit log (`kos audit`).

## Who is who

| | how | what it may do |
|---|---|---|
| **the core** | PID 1 calls `prctl(KOS_PR_CLAIM_CORE)` once per boot (nobody else can; a second claim fails) | confine children, write rules, read the log; inherited by what init starts for the owner |
| **an app** | the core calls `prctl(KOS_PR_CONFINE, id)` in the child, before it runs any app code | nothing above; confinement is one way, inherited by every child and across `exec`, and clears the core flag |
| **everything else** | not claimed, not confined | untouched - the module does nothing to it |

The last row is the important limit: **the module only governs confined processes.** The OS's own
connections, processes outside the sandbox, and anything inside a kernel cell (its guest kernel does
not have the module) are not covered. `docs/ARCHITECTURE.md` and the README gaps table say this too.

## The interface (`/sys/kernel/security/kos/`)

| file | who | what |
|---|---|---|
| `status` | anyone | `kos-lsm 1`, `core=claimed|unclaimed`, `rules=N`, `logged=N`, `dropped=N` |
| `rules` | core only | write one rule per `write()`; read back the live rules |
| `log` | core only | read drains the connection log |

A rule is one line, typed out: `allow APP tcp|udp connect|listen ADDR PORT`, the same with `revoke`,
or `revoke-app APP`. An address is an IPv4 or IPv6 literal - no names (resolving one is a connection),
no ranges, no wildcards, no port 0 (`10.0.0.0/8`, `127.0.0.1x`, `*` and `localhost` are refused; a
test for each exists, one was a real bug). The kernel parses with `in4_pton`/`in6_pton` and insists
the whole word was used: those functions treat any unknown character as the end of the address when
no delimiter is given.

The kernel looks at the **address's own family**, not the socket's, because the kernel does:
an `AF_INET` address on an IPv6 UDP socket is an IPv4 destination, and `AF_UNSPEC` in a datagram send
still carries one. Both are checked (see `kos_socket_sendmsg`), and the boot test tries both.

The log is a ring of 256 lines. If the core does not read it in time the oldest lines are
overwritten; `dropped=N` counts them and the core writes that into the audit log.

## Build, test

```
kernel/build.sh                 # -> build/kernel/bzImage  (full hardened config; ~15 min on 4 cores)
kernel/test/run.sh              # boots a minimal build under QEMU and runs 96 checks (~2 min, no KVM)
KOS_KERNEL_TEST=1 python3 -m unittest tests.test_kernel     # the same, from the suite
```

`build.sh` downloads `linux-$(cat kernel/KERNEL_VERSION).tar.xz` from cdn.kernel.org, **refuses it
unless its SHA-256 equals `kernel/KERNEL_SHA256`**, applies `kernel/patches/*.patch`, merges
`kernel/kos.config` onto `defconfig`, and fails if any option in `kos.config` is missing from the
final `.config`. That last check exists because Kconfig drops options silently, and it found three
hardening lines in the existing config that had never taken effect (`IO_URING` and
`X86_VSYSCALL_EMULATION` can only be switched off with `CONFIG_EXPERT=y`; `DEBUG_FS` was pulled back by
`BLK_DEV_IO_TRACE`) and one renamed option (`MITIGATION_PAGE_TABLE_ISOLATION`).

`kernel/test/kos_lsm_test.c` runs as PID 1 in the test kernel. Each refusal is paired with the
allowance that proves the rule said no (a connect refused with `EACCES`, then the same connect
succeeding once the core allowed it). It also runs on the full hardened build, where it reports
`bpf() does not exist in this kernel` instead of assuming it does.

## Working on the patch

- The module is out of tree and uses `LSM_ID_KOS` = 114, which is not registered upstream.
- **`include/linux/lsm_count.h` must count the module.** Without that line the LSM framework runs out of
  static-call slots and drops the module without a word; the first boot test showed exactly that.
- A new Linux version needs the patch rebased. Change `KERNEL_VERSION` and `KERNEL_SHA256` together;
  `tests/test_kernel.py` fails if the patch header names another version, or if the patch touches
  any file beyond the seven an LSM needs.
- The shipped command line (`kernel/cmdline.txt`) sets `kos.require_kernel=1` and lists `kos` in `lsm=`.

## What is not tested

Real hardware; KVM; any CPU but x86_64; the module stacked with SELinux or AppArmor (neither is
configured); several threads confined at different times (confinement is per task and is applied in a
single-threaded child before `exec`, as `SandboxPolicy.preexec` does); and a kernel cell's guest.
