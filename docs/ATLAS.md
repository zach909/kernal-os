# Atlas: a map of anything

**The idea: put data in space.** A place is a way of deciding what is *the same thing* and what is *near*. Put every
observation where it belongs and the repetition lands on itself and collapses into one thing that remembers how often
it was seen; what is seen again and again stays, what was seen once and never again goes; and a map of many things at
once shows what no one thing could say (a surface, a routine, where a smell comes from, which files are about the same
subject).

It is not about pictures. A picture is one kind of thing you can put in. So is a smell, a sound, a temperature, a touch,
a file, a note, a download, random bytes, or *how many people liked a video*.

## The mark

Everything on the map is a **mark**: whole numbers and short text, nothing else.

| field | what | example |
|---|---|---|
| `k` | kind of thing | `sight`, `smell`, `heat`, `file`, `data`, `likes`, `event`, `region`, `trend` ... |
| `s` | the space it is in | `world` (millimetres), `files` (a folder's layout), `mind` (where text/bytes land), anything you name |
| `p` | where, `[x, y, z]` whole numbers, or nothing | `[1200, 3400, 900]`, `null` |
| `t` | when, whole seconds | `1763900000` |
| `v` | how much, a whole number, in unit `u` | `23500` `mC`; `900` `likes` |
| `n` | how many observations it adds up | `1`, `50` |
| `l` `r` `o` | label, what it belongs to, an "other" (link target or fingerprint) | `"coffee"`, `"video:cats"` |

A mark with no place is still on the map: "900 likes on `video:cats`" belongs to the video, not to a spot. **Anything
that shares a `r` is about the same thing**, so a video's frames, its title, its likes and the smell near it can be asked
for together (`/about video:cats`). No decimals anywhere: a reading that is not a whole number is not a mark.

## Position from comparing

The one idea behind every locating function: **comparing sensors tells you where.**

* **Two cameras.** The nearer a thing is, the *more* its two views differ. That difference (the disparity `d`, in
  pixels) gives the distance: `Z = focal length x spacing / d`. Far things barely move between the views; near things
  jump. Several cameras give several opinions; they vote, and one that disagrees is outvoted, never averaged in.
* **Several noses, thermometers, microphones, radios.** The nearer the source, the stronger the reading. The map tries
  every point on a grid for the one where `(reading - floor) x distance^power` comes out the same for every sensor, and
  refines it. With the strength of the source unknown, two places fit equally (one near, one further out): it returns
  both (`at` and `alt`).
* **Two microphones.** How much sooner the sound reaches one: a bearing, front and back not told apart.

## Anything, in space

`ingest(name, bytes)` takes literally anything. Text is placed by its words; any other bytes by sampled 4-byte patterns
(chosen by their *content*, not their position, so a copy with something added at the front still matches). Each gets a
64-bit fingerprint where similar things differ in few bits. Exact copies and near-copies (about 90% alike or more) land
on the same spot and **fold into one mark** that keeps the total count and the newest time:

> nothing is lost but the repetition: the sum of `n` is the same before and after.

It does not understand what it ingests. "car" and "automobile" are not near; a photo is placed by its bytes, not by what
is in the picture; random bytes get a place and are never refused.

## Making the whole better than the parts (`consolidate`)

| from | the map works out |
|---|---|
| old raw depth cells | **surfaces and objects**: floor-like, wall-like, horizontal, object, with sizes; the cells are forgotten |
| cells seen once and never part of anything | dropped as **noise** |
| movement events at a place and a time of day, on several days | a **routine** |
| three or more sensors that agree | a **source**: where the smell, sound or heat comes from |
| files that use the same words | a **theme**, placed at the middle of its members |
| files many others point at | a **hub** |
| files of the same size and the same words | **twins** |
| any quantity read four or more times | a **trend**: rising, falling, or a spike (a flat series then a jump) |
| near-duplicate data | one mark that keeps the count |

Digestion is idempotent (doing it twice changes nothing), recomputes what it derives instead of adding it up again,
and every write is atomic per chunk: chunks that gain marks are written first, so a failed write leaves a duplicate,
never a hole (tested by failing every possible write). When a chunk is full the least corroborated marks go first, not
the oldest: a cell seen fifty times is probably real, a speck seen once probably noise.

## Where it runs

* **KOS** (`apps/atlas/*`): eight sandboxed apps sharing the `atlas` folder; the OS reads the hardware for them through
  services (`camera.capture`, `sensor.sweep`, `files.walk`, `clock.now`), each after a password typed in the OS's own
  prompt. KOS has no background services by design, so **every capture is one bounded call started by you.**
* **NeuroClaw / OpenBrain** (`atlas/` in that repository): the same core, a command line, and a tool description an
  agent can use.

## What it is not

* **It does not recognise anyone.** It records that something person-sized moved at a place and a time. Who it was
  needs stored images and a model that names people, which is a different and much more sensitive thing; it is not here.
* **Nothing here has touched a real camera or sensor.** Everything is tested against scenes whose answer is known and
  against fake drivers.
* **Stored in clear** inside the shared folder (the README's rule 8 gap).
* Cameras must be rectified and told their spacing; yaw only; planes are found along the map's own axes only; a flat or
  repeating surface gets no depth; a single point source is assumed.

See the README gaps table for the full list and `tests/test_atlas_core.py` for each claim, next to the case built to break it.
