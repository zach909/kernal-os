---
name: kos-kernel
description: How KOS uses the Linux kernel - the sandbox that confines apps (Landlock, namespaces, no_new_privs), kernel cells (KVM micro-VMs over vsock), and the kernel-protection checks the administrator keyboard depends on. Use when changing or debugging sandbox.py, cells, kos doctor, or anything that runs code on behalf of an app in kernal-os.
---

# KOS kernel layer

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
Known gap: no seccomp filter yet (Landlock + namespaces only).

Network today: empty namespace by default; the `network` permission plus a
password removes both the namespace and the Landlock TCP filter, which gives the
app every host and port. That is the open gap against rule 3 in `kos-rules`.

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
sandboxed processes; about 14 tests already fail in a container without KVM or
a working sandboxed run. Take a baseline before your change and diff after.
