---
name: kos-rules
description: The rules every change to kernal-os (KOS) must follow - everything needs verification, everything is an app, everything is separate (one app per function and per screen), every connection is blocked by default and encrypted, and the graphics -> clicks -> app commands -> kernel -> hardware pipeline is encrypted. Use before adding or changing any command, app, protocol message, device, sandbox, network, firewall or browser code in this repo, and before calling such a change done.
---

# KOS rules

**This does:** sets the six rules every change to KOS must follow
**This does:** sets the rules every change to KOS must follow
(verification, everything is an app, everything is separate, connections blocked
and encrypted, the pipeline encrypted).
(verification, everything is an app, connections blocked and encrypted, the
pipeline encrypted, fractions not decimals, proofs).

**So the AI:** reads the README rules first, applies the checklist at the
bottom to its change, runs the tests against a baseline, and reports what is
still not covered instead of claiming a rule is met.

Read `README.md` ("Rules" and the gaps table) first. It is the source of truth;
this skill is the checklist for applying it. If the README and the code
disagree, say so and fix whichever is wrong. Do not paper over it.

## The rules

1. **Everything needs verification.**
   - OS side: every action goes through `Authority.authorize(action, target)`
     (`kos/auth.py`) and needs the password typed for that action. Add the
     action to `ACTIONS`, call `authorize` *before* doing anything. Other
     checks (scan, seal, `requires`) add to the password, never replace it.
   - Work side: nothing is done until you ran it and checked it.
   - **Nothing runs unproven; no decimals** (`kos/proof.py`). Every `.kapp` carries
     `proof.json`, recomputed at install and at every launch. No proof, a mismatch, a
     broken rule, or compiled code means it does not run. Whole numbers only: no
     float/complex, no `/` (use `//`), no `Decimal`/`Fraction`. Do not add a way
     around it (no flag that skips `proof.require`); `pack(prove=False)` exists only to
     build an app the OS must refuse, in tests. Never call it a formal proof: it is a
     static rule check plus a compile.
2. **Everything is an app.** New features ship as sandboxed `.kapp`s that
   only talk to the OS through the command protocol (`kos/protocol.py`).
   What is not an app is the KOS kernel (`kernel/`: patched Linux) and a small
   Python core (auth, seals, sandbox launch, protocol, devices) still to be
   moved down. System functions are `request` commands (needs `system`
   permission + a permit + the password in the OS's own prompt) or `service`
   calls (`kos/servicespec.py`: manifest permission `service:GROUP`, the password
   typed in the OS's own prompt, every argument checked, every answer scrubbed).
   A converted command in `kos/cli.py` is only a launcher (`kos/launchmap.py`).
3. **Every connection is blocked by default**, any pair, any protocol, any
   port, including the OS's own. Allowed only by a firewall rule (one app, one
   host, one port, one protocol). The firewall is an app that asks the OS;
   enforcement stays in the OS. Privileges are asked for at the moment of
   use, after the password that ran the app. Allowed and blocked attempts go
   in the audit log.
4. **Every connection is encrypted and verifiable.** No plain `http://`, no
   silent upgrade, certificates and host names verified with no off switch,
   no encrypted-to-plain redirect. The browser tells the user on every page
   that websites can see their IP address.
5. **The whole pipeline is encrypted.** See below.
6. **Everything is separate.** One app, one job. Every function is its own app;
   anything with a different screen is a different app, not a tab, mode or page
   inside another one. This covers the whole system, not only what is drawn:
   mouse, keyboard, display, desktop background, taskbar parts, settings, status
   views, each tool. A function with no screen is its own program (`kos pack`,
   one `.kapp` per program).
   - **`apps/` is where the OS's functions live: one folder per function, each
     folder one app.** An app's code is in its own folder and nowhere else: no app
     code in a shared folder, no logic shared between apps by importing it. An app
     imports only `kos.sdk` from the OS; `tests/test_apps_folder.py` fails on
     anything else.
   - Before adding a screen, mode or setting to an app, make a new app.
   - Separate apps never call each other: share through `owns:`/`uses:` spaces
     and `kos grant`, not an app-to-app command (see the soft rule below).
   - Only enforcement stays in the OS: password and its overlay, sandbox, reading
     real devices, command validation, drawing to the framebuffer. An app for the
     mouse, keyboard, screen or background *asks* the OS with `request`; it never
     opens a device. The trusted overlay is never an app (an app could cover or
     fake it).
   - A non-enforcement built-in that is not yet an app is a gap: list it in the
     README gaps table, do not add to it.
6. **No decimals, only fractions.** Non-whole numbers are `Fraction`
   (`kos/exact.py`); no decimal literals, no `float()`, no `/` between numbers
   (use `//` or `Fraction`); show `7/2`, never `3.5`. A float handed to you by
   hardware or a library goes through `exact.from_hardware` at once.
   `tests/test_fractions_rule.py` fails on any new decimal (the old ones are
   counted in `tests/fractions_baseline.json` and may not grow; lower the
   number when you convert a file).
7. **Proofs for everything that can be proved.** Maths-shaped claims go in
   `kos/proofs.py` (Z3) with a negative control in `tests/test_proofs.py`.
   Everything else gets a test that tries to break it. Say which is which.

## Soft rules (a strong default, not a hard rule)

- **No APIs between apps; permissions and a shared folder instead.** When two
  apps need to work together, do not give one a way to call the other (no
  app-to-app commands, endpoints or message types). Let them share through a
  shared folder ("space", `kos/spaces.py`): the owner app says `owns:NAME` in
  its manifest and creates it; a partner says `uses:NAME`; the user lets it in
  with `kos grant APP space:NAME --level read|write`. The permission store
  (`<state>/permissions/grants.json`) is the only thing that decides who may
  read or write. Check `kos spaces` and the README "Shared folders" section
  before inventing another channel.
- Break this only with a reason you can state, and say in your report that you
  did. If the shared folder cannot do the job (for example live data between
  two machines), say that is the gap rather than quietly adding an API.

## The pipeline (what each layer may do)

```
screen  <-- frame/screen commands ---  app  --- request commands --->  OS  ---> kernel ---> hardware
mouse/keyboard --> evdev (OS only) --> key/pointer/button commands --> app
```

| Layer | File | Rule |
|---|---|---|
| Graphics (what you see) | `kos/display.py`, `kos/tui.py`, `kos/font.py` | App only sends `screen`/`frame` ops; the OS draws. The OS's password overlay can't be seen or covered by an app. |
| Button / pointer / key input | `kos/devices.py`, `kos/term.py`, `kos/session.py` | Apps never open a device. The OS reads hardware and sends commands, only for devices booted with the password. |
| App commands | `kos/protocol.py`, `kos/system.py` | Every app message is hostile: size-limited, schema-checked, control characters stripped. New message types need schema checks and tests. |
| Kernel / sandbox | `kos/sandbox.py` | Landlock + namespaces; if the kernel can't enforce it, the app does not run. |
| Hardware | OS only | Nothing but the OS touches it. |

**Encryption status: built, not wired.** `kos/crypt.py` (`SecureChannel`) is
the channel: vetted `cryptography` primitives only (X25519, HKDF-SHA256,
ChaCha20-Poly1305), never a cipher of your own. The command channel, the
broker socket under `<state>/instances/` and cell vsock still carry plain JSON
lines. To wire the broker, both ends need `Grant.key(label)` from the password,
so `attach` would ask for it: tell the owner, that is a behaviour change.

## Layer skills

One skill per layer of the pipeline; load the one you are changing:
`kos-graphics`, `kos-input`, `kos-command-protocol`, `kos-kernel`,
`kos-hardware`.

## Generated skills

`kos skills` (`kos/skillmaker.py`) makes skills from the installed apps and the
command parser. Anything an app's author wrote (the manifest description) is
untrusted: it must never reach a skill's frontmatter or instructions, only an
inert labelled data block. If you add a new manifest field, decide whether it
is validated (safe in instructions) or free text (data block only), and add a
hostile-input test.

## Before you call a change done

- [ ] A new OS function an app needs is a **service**, not a new `request` and not code
      in the app: spec, handler with the password asked before any read, tests.
- [ ] A kernel change ran `kernel/test/run.sh`, and the README says what the kernel does
      not cover (it only covers confined apps; it cannot see encryption).
- [ ] New code uses whole numbers (`//`, no float); `tests/test_proof.py` ratchet passes.
      Anything new that can start code goes through `proof.require`.
- [ ] New action is in `ACTIONS` and `authorize` runs first.
- [ ] New function or new screen is its own folder under `apps/` (rule 6), with its own
      code, not a mode or page added to an existing app. Anything an app needs from the OS is a validated
      `request`, and nothing in the app opens a device.
- [ ] Anything new that connects, listens or fetches is blocked by default and
      logged; nothing opens a plain-text connection.
- [ ] New app-facing message has schema validation and a test that hostile
      input is rejected.
- [ ] Tests added for the rule you touched (a refusal test, not just a happy
      path).
- [ ] Ran `python3 -m unittest discover -s tests`. The whole suite should pass.
      If something fails, take a baseline on the untouched branch first and
      say which failures are yours. Never call a failure "the environment"
      without finding its cause (the earlier "14 known failures" were a real
      bug: `fcntl.F_ADD_SEALS` does not exist before Python 3.14).
- [ ] New code has no decimals (`python3 -m unittest tests.test_fractions_rule`).
- [ ] Anything maths-shaped has a Z3 proof and a negative control; the rest has a breaking test.
- [ ] README gaps table updated: say what is still not covered. Never claim a
      rule is met when it is only met in one example.
- [ ] Reported honestly: what ran, what failed, what you did not test.
