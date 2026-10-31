---
name: kos-command-protocol
description: The KOS command protocol - every message between an app and the OS, how app messages are validated, and how an app asks the OS for system functions with request. Use when adding or changing a command, a request action, a manifest permission, or the Channel in kernal-os, or when an app and the OS disagree.
---

# KOS command protocol (app commands)

Everything is a command. Newline-delimited JSON over a socket
(`Channel` in `kos/protocol.py`). The module docstring is the spec; keep it in
step with the code.

```
OS -> app   hello, key, pointer, button, scroll, device, apps, result, quit
app -> OS   screen, frame, log, request, exit
```

`request` is how an app does anything beyond drawing: `apps`, `open`, `focus`,
`close`. The OS honours it only if **all** of these are true:

1. the app's manifest has the `system` permission (set from the *verified*
   manifest into the instance record at open time, never from the app);
2. the app was permitted to run (`kos permit`);
3. for anything that starts or stops something, the owner types the password
   in the OS's own overlay.

## Every app message is hostile

`validate_app_message` size-limits, schema-checks and sanitizes. An unknown
command, wrong type, out-of-range number, or bad name is a `ProtocolError`.
Names must match the same regexes the store uses.

## Adding a command or request

1. Add the shape to the docstring and to `validate_app_message`
   (request handling is inside it), with bounds.
2. Decide the privilege: which manifest permission, which `Authority` action
   (add it to `ACTIONS` in `kos/auth.py`), and where the password is asked.
3. Handle it in the OS (`session.py` `_on_request`, `system.py`), not in the app.
4. Tests: accepted shape, every rejection, and that an app without the
   permission is told no (`TestRequestProtocol`, `TestSystemBridge`).
5. Update the README gaps table if it changes what is covered.

## Rules that apply here

- Apps ask; the OS decides. Never let an app message name a file path, device,
  host, or command line that the OS then runs without validation.
- Never copy app-supplied text into agent-facing output (skills, logs an agent
  reads) outside an inert data block. See `kos/skillmaker.py`.
- Encryption: the channel is plain JSON today. The exposed parts are the broker
  socket (`kos open` / `attach`, any process running as the owner) and cell
  vsock. Do not write a cipher; the standard library has no authenticated
  encryption. Adding a dependency is the owner's decision (see `kos-rules`).
