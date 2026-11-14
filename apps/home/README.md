# home

A group of apps for a smart home of devices that run KOS. This folder has no `manifest.json`, so
**the group itself has no permissions**; each app has its own manifest and asks for one thing.

| app | folder | permission | job |
|---|---|---|---|
| `home.devices` | `devices/` | `owns:home` | overview of every paired device (read-only screen) |
| `home.pair` | `pair/` | `uses:home` | adds one device; cannot control or remove |
| `home.control` | `control/` | `uses:home` | on/off and level; cannot add or remove |

They never call each other. They share one folder, `home`, and the owner decides who may touch it:

```
kos pack apps/home -o dist/home
kos install dist/home                       # each asks for the password
kos permit home.devices                     # one app at a time
kos grant home.pair    space:home --level write
kos grant home.control space:home --level write
run home.devices
```

None has `network`, `system` or any device access.

**What this is not (yet): it does not reach any device.** Control records what you *asked for* in the
`home` folder. KOS has no device-to-device link (`docs/MESH.md` is design only), so nothing carries the
request to another machine and nothing reports a device's real state back. When that link exists it
should be another app (a device-side agent), never a new command between these three.
