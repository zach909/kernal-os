---
name: kos-kernel
description: How KOS uses the Linux kernel - KOS ships its own patched kernel (the security module in kernel/patches), the sandbox that confines apps (Landlock, namespaces, no_new_privs, the KOS module), kernel cells (KVM micro-VMs over vsock), and the kernel-protection checks the administrator keyboard depends on. Use when changing or debugging kernel/, sandbox.py, kos/kernel.py, kos/firewall.py, cells, the System Information app, or anything that runs code on behalf of an app in kernal-os.
---

# KOS kernel layer

**KOS has its own kernel.** `kernel/patches/0001-kos-lsm.patch` adds a Linux Security
Module (`security/kos`) to Linux 6.12.116; `kernel/build.sh` fetches the pinned source,
refuses it unless the SHA-256 matches, applies the patches, merges `kernel/kos.config`
and fails if any option in it did not stick. Read `docs/KERNEL.md` before changing it.
The core's side is small: `kos/kernel.py` (claim the core, confine, rules, log) and
`kos/firewall.py` (the owner's rules, sealed; applied at launch, revoked at exit).

Rules for this layer:
- **A kernel change needs the boot test**: `kernel/test/run.sh` (about 2 minutes, no KVM).
  It boots the patched kernel under QEMU with `kernel/test/kos_lsm_test.c` as PID 1. Every
  refusal in it is paired with the allowance that proves the rule said no. It found real
  bugs (an address parser that accepted `10.0.0.0/8` as a host, the LSM silently dropped
  by the framework for lack of a slot in `lsm_count.h`). Add a check for what you add.
- **Fail closed.** `kos.require_kernel=1` (on the signed command line) means no app runs
  without the module; `SandboxPolicy.probe` and `init.kernel_gate` enforce it.
- **Default deny.** A rule names one app, protocol, direction, IP address and port; never
  a name (resolving one is a connection), never a range or `0`. `kernel.check_rule` and the
  kernel both refuse; neither trusts the other.
- **The kernel only covers confined tasks.** Say so wherever you describe it: the OS's own
  connections, processes outside the sandbox, and kernel cells are not covered (README).
- **It cannot tell encrypted from plain traffic.** Do not claim the firewall enforces rule 4.

**This does:** confines each app with the Linux kernel (Landlock,
namespaces) and runs risky work in its own kernel cell, refusing to start if
a protection can't be applied.

**So the AI:** never weakens a layer to make a test pass, makes any new
privilege a password-gated action asked for at the moment of use, and
compares test failures to a baseline taken before the change.

The OS sits between app commands and the kernel. An app never makes a kernel
decision for itself: it is confined, and its only way out is the command channel.

## The sandbox (`kos/sandbox.py`) - fails closed

Applied in the child between fork and exec. If any protection cannot be
applied, **the app does not start**.

1. drop root (run as `nobody`)
2. `PR_SET_NO_NEW_PRIVS`
3. new user + network + IPC + UTS namespaces - the network namespace is empty
4. resource limits (no core dumps, bounded fds/memory)
5. Landlock: read the language runtime and one private per-run cache directory,
   nothing else; no signals or abstract unix sockets outside the sandbox

`kos doctor` reports what this kernel supports (`report()` in `sandbox.py`).
A short seccomp denylist follows Landlock on x86_64 (`kos doctor` says if it is missing). On the KOS kernel the module's confinement is applied first of all, before any of the above.

Network: an empty namespace by default; the `network` permission plus a password removes it and
the Landlock TCP filter. **On the KOS kernel that no longer means every host:** the module denies
every connection of a confined app unless the owner's firewall has a rule for exactly that app,
protocol, direction, IP address and port. On a stock kernel the permission still gives every host
and port - the README gaps table says so.

## Cells (`kos/cells.py`, `kos/cellagent.py`)

A cell is a separate Linux kernel: a KVM micro-VM pinned to its own cores, no
disk, no NIC, vsock only, holding no password material. The host talks to it
with the *same command protocol* as a local app, so session code does not care
where an app runs. Starting or stopping one is an `Authority` action.

## Kernel as a dependency (`kos/requires.py`, `kos/admin.py`)

`requires` is a dependency, not an action. Unlocking requires the elevated
administrator keyboard, which requires the kernel: `kernel_gaps()` (Landlock +
user namespaces) is re-checked on every use, so a kernel that cannot enforce
what KOS promises means the computer does not unlock.

## Rules that apply here

- Never add a code path that runs app code unconfined "just for dev" without it
  being explicit and loud (`KOS_DEV_WEAK_SANDBOX` is the existing, labelled one).
- A new privilege an app can get is a new `Authority` action, asked for at the
  moment of use, and logged.
- Do not weaken a layer to make a test pass. This container has Landlock ABI 7
  and user namespaces, but no KVM.

## Testing

`TestSandboxedRun`, `TestCodeIsACommand`, `TestDesktopSessions` run real
sandboxed processes and should all pass where Landlock and user namespaces
exist. Memfd sealing needs `F_ADD_SEALS`, which Python exposes only from 3.14;
`kos/loader.py` uses the Linux constant (1033) as a fallback. If a sandboxed
test fails, find the cause before blaming the machine.
