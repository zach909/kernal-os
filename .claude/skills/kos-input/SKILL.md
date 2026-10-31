---
name: kos-input
description: How clicks, pointer movement and keys reach a KOS app - the input layer between hardware devices and app commands, including booting the mouse and keyboard with the password. Use when changing or debugging mouse, keyboard, button clicks, evdev, device booting, Ctrl-C handling or the right-click App Library in kernal-os.
---

# KOS input (the button clicker layer)

**This does:** reads the mouse and keyboard itself and hands the app a
command (`key`, `pointer`, `button`, `scroll`), only after the owner booted
that device with the password.

**So the AI:** never passes a device or raw event into the sandbox, makes a
new input a validated command tied to a booted device, keeps Ctrl-C and
right-click with the OS, and tests with scripted devices.

A click is never delivered to an app as a device. The OS reads the device and
sends the app a **command**: `key`, `pointer`, `button`, `scroll`.

```
mouse/keyboard --> devices.py (OS only) --> session.py route() --> app (as a command)
```

## Where things are

| Piece | File |
|---|---|
| Terminal and evdev devices, key translation | `kos/devices.py` |
| Key parser for terminals | `kos/term.py` |
| Routing, booting, overlay, Ctrl-C | `kos/session.py` |
| Command shapes the app receives | `kos/protocol.py` |

## Booting a device

- Order is mouse, then keyboard (`BOOT_ORDER`), each needing the password,
  each asked in the trusted overlay: "Boot mouse for APP?".
- **Mouse:** until booted, the OS does not open it at all. After booting it is
  opened with `EVIOCGRAB`, so KOS is its exclusive reader; nothing else on the
  system can read it.
- **Keyboard:** the OS has to read it anyway (that is how you type the
  password). "Booting" it means *starting to forward keys to the app*. Until
  then keystrokes reach only the OS prompt.
- **Ctrl-C is reserved by the OS in every mode.** An app can never trap you.
- **Right mouse** is consumed by `Session.route` when `right_click_to` is set
  (the App Library). It is never forwarded to the app.
- While a trusted prompt is up, the app gets nothing.

## Rules that apply here

- An app never opens `/dev/input` or any device. Do not add a path that passes
  a device fd, or raw events, into the sandbox.
- New input = new command shape: validate it, document it in `protocol.py`,
  and decide which booted device it needs.
- Booting a device is an `Authority.authorize` action (`device.mouse`,
  `device.keyboard`). Carrying booted devices over (desktop `preboot`) must
  stay OS-driven, never app-driven.
- Encryption: the input channel is plain JSON today (see `kos-rules`).

## Testing without hardware

`ScriptedDevices` feeds scripted events; `EvdevTranslator` can be tested with
`INPUT_EVENT` structs (see `TestDisplayAndInput`, `TestDesktopSessions`). This
container has no `/dev/input`.
