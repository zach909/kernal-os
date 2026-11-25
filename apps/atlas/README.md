# atlas

A map of **anything**. Not a picture map: a map you can put any data into, where redundant data collapses and
the data worth keeping is kept. The unit is a *mark*: what kind of thing, where (in whatever space makes sense),
when, how much, and what it is about. A depth pixel, a whiff of gas, a sound's direction, a temperature, a file,
a note, a download, random bytes, how many people liked a video: all marks. See `docs/ATLAS.md`.

This folder has no `manifest.json`, so **the group itself has no permissions**; each app has its own manifest and
asks for one thing. They never call each other. They share one folder, `atlas`, and the owner decides who may
touch it.

| app | folder | asks for | job |
|---|---|---|---|
| `atlas.find` | `find/` | `owns:atlas` | ask the map: words, `/about`, `/similar`, `/near`, `/stats`. Owns the folder. Read-only. |
| `atlas.map` | `map/` | `uses:atlas` | a top-down picture of one space, pan and zoom. Read-only. |
| `atlas.scan` | `scan/` | `uses:atlas`, `service:camera` | two or more cameras: depth from how much their views differ, then who moved |
| `atlas.sense` | `sense/` | `uses:atlas`, `service:sensor` | smell, heat, humidity, pressure, light: one sweep of every sensor |
| `atlas.place` | `place/` | `uses:atlas` | say where each sensor and camera is (without this a sensor is "nowhere") |
| `atlas.files` | `files/` | `uses:atlas`, `service:files` | map a folder: every file gets a place, links and a fingerprint; any file, text or not |
| `atlas.put` | `put/` | `uses:atlas`, `service:clock` | put anything you type in the map |
| `atlas.digest` | `digest/` | `uses:atlas` | make the map smaller and smarter: surfaces, routines, sources, themes, trends, duplicates |

```
kos pack apps/atlas -o dist/atlas
kos install dist/atlas                       # each asks for the password
kos permit atlas.find                        # one app at a time
kos grant atlas.map    space:atlas --level read
kos grant atlas.scan   space:atlas --level write
kos grant atlas.sense  space:atlas --level write
kos grant atlas.place  space:atlas --level write
kos grant atlas.files  space:atlas --level write
kos grant atlas.put    space:atlas --level write
kos grant atlas.digest space:atlas --level write
run atlas.find
```

Each folder holds a byte-identical copy of `suite/atlas_core.py` (an app's code lives in its own folder). Change
the master and run `python3 -m suite.atlas_sync`; `tests/test_atlas_apps.py` fails if a copy differs.

**What this is not.** It does not recognise anything: it records that something person-sized moved at a place and a
time, never who. Nothing here runs by itself: every capture, sweep and walk is one bounded call, started by you
with your password. See the README gaps table for what was and was not tested (no real camera or sensor was used).
