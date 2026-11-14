# devices

A group of apps for **linked devices**. This folder has no `manifest.json`, so **the group itself has no
permissions**; each app below has its own manifest and asks only for what it needs.

| program | folder | asks the OS for |
|---|---|---|
| `devices.list` | `list/` | `service:link` (shows this device and the linked ones) |
| `devices.pair` | `pair/` | `service:link` (name this device once, then link another) |
| `devices.scope` | `scope/` | `service:link` (pause a linked device, or let it ask again) |
| `devices.unlink` | `unlink/` | `service:link` (remove one; works with the other device off) |

```
kos pack apps/devices -o dist/devices      # one .kapp per app
kos install dist/devices                   # each asks for the password
kos permit devices.pair                    # one app at a time
run devices.pair
```

## What a link means

Linking is done **in person**: both screens show the same 6-digit code, and the owner types the password on
**each** device. A man in the middle gets a different code on each side. No account, no cloud, nothing running
in the background.

A link grants **every permission**: a linked device may *ask* the other for any action, except the few that
would let one device take over the other for good (change the password, link or unlink devices, log in, the
administrator keyboard, boot input devices). Asking is not getting: **the device that owns the resource still
types its own password** (once per action and target per connection; every time for writing, running code,
installing, firewall and grants). Every request is audited on the device that receives it.

What it does **not** do: it cannot make a phone that is not KOS follow any of this. A non-KOS device is a
remote party holding a key (see `docs/MESH.md`). The wire format is in `docs/SYNC.md`.
