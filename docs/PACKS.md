# Writing a pack app

A *pack* is one module, `kos/office/pack_<group>.py`, that exports `ENTRIES`: the apps of one group
(`kos/office/packs.py` lists the groups; `docs/REQUESTED2.txt` lists which titles belong to which). Built by
`bin/suite build DIR`; the launcher for a pack app is `entry(name, pack)`, which imports only that module.

## The contract

1. **Touch only your own two files**: `kos/office/pack_<group>.py` and `tests/test_pack_<group>.py`. Do not edit
   `catalog.py`, `gen.py`, `packs.py`, `ui.py`, `docs/` or other packs. If you need a helper, put it in your module.
2. **Entries**: `from .packkit import app, none`. `app(title, make, scope, note, ...)` where
   `make(host, entry)` returns a `kos.office.ui.Screen`; `none(title, reason)` for an item that cannot be built.
   The `title` must be exactly the title in `docs/REQUESTED2.txt`; one entry per title, no extras, no missing.
3. **Light.** Python standard library only. Import only `kos.office.ui`, `.records`, `.specs`, `.search`, `.sheet`,
   `.packkit` (and the standard library). **Never import `kos.office.catalog`, `.workbench`, `.extras`, `.tools`**
   (they pull in the whole suite). Small and plain beats clever: reuse `RecordList`/`Spec` (see `specs.py`: `R(...)`,
   `fields(...)`) for register-style apps instead of writing screens. Nothing runs in the background. Bound every
   input and every stored item (a size cap) and every loop.
4. **KOS rules** (`.claude/skills/kos-rules`): no sockets, no `urllib`, no subprocess, no files outside the vault
   (`host.get/put/keys/delete` only), no `eval`/`exec`/`compile`/`pickle` of anything a user typed (use the sheet
   formula parser in `sheet.py`, or your own small parser). No `network=True` unless the app truly cannot work
   without it, and then say so in the note. Do not store secrets in clear text in the vault; do not invent a cipher.
5. **Honest scope.** `full` = does the job it is named for as a single-user local app. `partial` = a real useful part;
   the note (> 20 characters) says plainly what is missing. `none` = not built; the note says why and, if
   an OS command or another app covers it, which. Never claim hardware, network, audio, camera or other-machine
   access. Do not pad: a small real app beats a large fake one.
6. **The agent is automatic.** Every app gets the built-in agent on Ctrl-N from `launch.py`. Do not add one.
7. **Keys.** The app must survive any key sequence. Ctrl-Q quits, Esc backs out; do not use Ctrl-N.
   Do not use the screen's `raise`; return `("push", Message(...))` style actions or flash a message.

## Tests (`tests/test_pack_<group>.py`)

For every app that does computation: (a) exact expected results from known vectors, not "it runs";
(b) hostile and malformed input (empty, huge, control characters, wrong types) is refused or bounded, never a crash;
(c) one `FakeHost` run through the screen (see `kos.office.ui.FakeHost`) proving it draws and saves to the vault.
Run only your file: `python3 -m unittest tests.test_pack_<group>`. `tests/test_packs.py` (owned by the integrator)
checks titles, notes, manifests and a key battery over every app; run it too, but ignore failures about *other* packs.
Do not run the whole suite and do not run git.
