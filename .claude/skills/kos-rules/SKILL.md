---
name: kos-rules
description: The rules every change to kernal-os (KOS) must follow - everything needs verification, everything is an app, every connection is blocked by default and encrypted, and the graphics -> clicks -> app commands -> kernel -> hardware pipeline is encrypted. Use before adding or changing any command, app, protocol message, device, sandbox, network, firewall or browser code in this repo, and before calling such a change done.
---

# KOS rules

**This does:** sets the four rules every change to KOS must follow
(verification, everything is an app, connections blocked and encrypted, the
pipeline encrypted).

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

**Encryption status: not done yet.** The command channel is plain
newline-delimited JSON over a socket (`Channel` in `kos/protocol.py`). The
parties that really need it are the ones that are not just parent and child on
one kernel: the broker socket under `<state>/instances/` (any process running
as the owner can connect and `attach`), and cell vsock. Do not invent a cipher
or use one from memory. The standard library has no authenticated encryption;
adding a vetted library (for example `cryptography`) is a decision for the
owner. Ask before adding a dependency.

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
- [ ] New action is in `ACTIONS` and `authorize` runs first.
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
- [ ] README gaps table updated: say what is still not covered. Never claim a
      rule is met when it is only met in one example.
- [ ] Reported honestly: what ran, what failed, what you did not test.
