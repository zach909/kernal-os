---
name: kos-hardware
description: Which KOS code is allowed to touch hardware - the screen (/dev/fb0), input devices (/dev/input evdev), KVM and vsock, and the administrator keyboard - and how to work on it without hardware. Use when changing anything that opens a device file, reads real input, draws to a real display, or starts a cell in kernal-os.
---

# KOS hardware layer

**This does:** is the only code allowed to open the screen, input devices,
KVM and the administrator keyboard.

**So the AI:** adds no unprompted device open, closes every exclusive grab,
keeps hardware out of the sandbox, and says plainly which hardware paths were
tested with fakes and which were never exercised.

Only the OS touches hardware. Apps get commands, never devices.

| Hardware | Opened by | Notes |
|---|---|---|
| Display `/dev/fb0` | `FbdevBackend` in `kos/display.py` | only on a real console VT; falls back to the terminal backend |
| Mouse / keyboard `/dev/input` | `EvdevDevices` in `kos/devices.py` | opened with `EVIOCGRAB` (exclusive); mouse not opened until booted |
| Administrator keyboard | `kos/admin.py` (`open_admin_devices`, `AdminPrompter`) | grabs the keyboards; refuses if another process holds one |
| `/dev/kvm`, `/dev/vhost-vsock` | `kos/cells.py` | kernel cells |

`kos doctor` shows which of these exist on the machine.

## Rules that apply here

- Opening a device is gated by the password (device boot) or by the booted
  administrator keyboard lease. Do not add an unprompted open.
- Always release: devices are exclusive grabs. Close them in `finally`.
- No hardware path may be reachable from inside the sandbox. If you pass an fd
  or path into an app, you have broken the pipeline.
- A WEAK lease (`KOS_DEV_ADMIN_WEAK=1`, dev only) means the keyboard is *not*
  exclusive and the prompt falls back to the TTY. Never treat that as the
  hardware-backed path in a test or a claim.

## Working without hardware

This container has **no** KVM, vhost-vsock, framebuffer or evdev. So:

- Use `HeadlessBackend` (display), `ScriptedDevices` / `EvdevTranslator`
  (input) and `ScriptedPrompter` (passwords). The admin tests use fakes.
- Do not claim a hardware path works because a fake passed. Say what ran and
  what did not: for example "the evdev translation is tested; opening a real
  `/dev/input` device was not exercised".
- `qemu_argv` is tested as a command line only; no VM is started.
