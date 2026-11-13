---
name: kos-command-protocol
description: The KOS command protocol - every message between an app and the OS, how app messages are validated, and how an app asks the OS for system functions with request. Use when adding or changing a command, a request action, a manifest permission, or the Channel in kernal-os, or when an app and the OS disagree.
---

# KOS command protocol (app commands)

**This does:** carries every message between an app and the OS, treats each
app message as hostile, and lets an app only *ask* the OS for system things.

**So the AI:** adds a new command to the spec and the validator with bounds,
picks the permission and password it needs, handles it in the OS and never in
the app, and writes a test for the accepted shape and every rejection.

Everything is a command. Newline-delimited JSON over a socket
(`Channel` in `kos/protocol.py`). The module docstring is the spec; keep it in
step with the code.

```
OS -> app   hello, key, pointer, button, scroll, device, apps, result, quit
app -> OS   screen, frame, log, request, vault, service, exit
OS -> app   hello, key, pointer, button, scroll, device, apps, result, answer, quit
app -> OS   screen, frame, log, request, exit
```

`request` is how an app does anything beyond drawing: `ask` (the AI; needs the `ai`
permission, not `system`; the OS answers with an `answer` message of plain-text lines),
`apps`, `open`, `focus`,
`close`. The OS honours it only if **all** of these are true:

1. the program's manifest has the `system` permission (every request) or
   `ask:ACTION` for that one request (`ASK_ACTIONS` in `kos/kapp.py`), set from
   the *verified* manifest into the instance record at open time (`system`,
   `asks`), never from the app. `SystemBridge(allowed=...)` refuses the rest
   before any password and audits it as `bridge.ask`. Permissions belong to a
   *program* (`backup.add`), never to the app folder that holds it, and are
   never inherited from or by a sibling;
2. the app was permitted to run (`kos permit`);
3. for anything that starts or stops something, the owner types the password
   in the OS's own overlay.

`service` is how an app asks the OS for one of its own functions (the audit log, the
security check, the firewall, a directory listing ...): `{"cmd":"service","id":N,"name":
"audit.tail","args":{..}}`, answered by `{"cmd":"service","id":N,"ok":..,"detail":..,"data":{..}}`.
`kos/servicespec.py` is the whole list and the schema of each; `kos/services.py` is the
implementations behind one door, `ServiceHost.call`. The manifest permission is
`service:GROUP`, never available to an extension or a mod. The password is asked inside
the handler, in the OS's own prompt, before it reads anything.

## Every app message is hostile

`validate_app_message` size-limits, schema-checks and sanitizes. An unknown
command, wrong type, out-of-range number, or bad name is a `ProtocolError`.
Names must match the same regexes the store uses.

## Adding a service (the usual way to give an app a new OS function)

1. Add a `Spec` to `SPECS` in `kos/servicespec.py` with the tightest argument types
   (`path`, `name`, `num(lo, hi)`, `one_of`, `flag`, `text(max)`); an argument called
   `name` or `host` is fine, the callers take their own parameters positional-only.
2. Add the handler in `kos/services.py` with `@service("group.name")`. Its parameters
   must be exactly the spec's arguments (a test checks). Call `ctx.authority.authorize(
   ACTION, target)` **before** reading anything private; add the action to `ACTIONS`.
   Raise `ServiceError` for a refusal the app may show.
3. Everything you return is scrubbed and size-bounded by the host; still return only
   what the app needs.
4. Tests in `tests/test_services.py`: the hostile arguments, the refusal with no
   permission (and that no password is asked), a wrong password returning no data, and
   the success. If a screen uses it, a `FakeHost` test in `tests/test_system_apps.py`.
5. A refusal that can happen before the password (a bad address, a flagged file) must
   happen before it, and the test asserts the prompter was never asked.

## Adding a command or request

1. Add the shape to the docstring and to `validate_app_message`
   (request handling is inside it), with bounds.
2. Decide the privilege: which manifest permission (a new askable action goes in
   `ASK_ACTIONS`; actions that touch other apps stay inside `system`), which `Authority` action
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
