# KOS idea feed

A running backlog, not a spec. When something here gets built, it moves to
"shipped"; nothing gets deleted, so this stays the record of where the
project has been and where it's going.

Add to this file freely - that's the point of it. It's the one place ideas
land instead of getting lost in chat.

## Backlog - not started yet

- **npm/Node apps as `.kapp`s.** Today a `.kapp` app is either Python
  (imported straight from the zip) or a static native binary (run from a
  sealed memfd). Node can't import straight from a zip the way Python can,
  so this needs its own small loader: unpack `node_modules` into a
  read-only, sealed tmpfs (still never touching the real disk) instead of a
  single memfd, then run Node against it inside the same sandbox.
- **A real windowing desktop.** `kos boot desktop` today is a plain
  numbered list you pick one app from - it hands you off to one attached
  app at a time. A real next step: tile multiple open apps' graphical
  frames on one screen at once, each still only receiving mouse/keyboard
  input while it has focus, still gated by its own device boot.
- **Per-app permission prompts beyond network.** The only extra permission
  an app can ask for today is `network`. Candidates: a clipboard
  permission (there isn't one yet - apps can't touch it at all), a
  "share one specific file/folder with me" permission, a persistent
  per-app storage permission (a sealed directory an app can actually
  write to across runs - today the sandbox gives it nowhere to save
  state).
- **Signed app publishers.** `kos update` refuses downgrades but doesn't
  check *who* built the newer version. An optional publisher signature on
  top of the install seal would let `kos install` show "signed by X" and
  updates require the same signer.
- **Seccomp filter on top of Landlock.** The sandbox is Landlock +
  namespaces + rlimits today. A tight seccomp-bpf allowlist would cut the
  syscall surface further, especially for native (non-Python) apps.
- **A rotating command log per open instance.** `kos activity`/`kos audit`
  cover installs, runs, device boots. An opened app's live command traffic
  isn't recorded anywhere unless you `attach` in `cmd` mode and watch it.
  A "last N commands" ring buffer per instance would make debugging a
  backgrounded app possible without attaching.
- **Rust port of the security core.** Already written down in
  `ARCHITECTURE.md` as a known gap: Python can't guarantee a password or
  derived key is wiped from every copy the interpreter makes.
  `kos/auth.py`, `kos/secret.py` and `kos/kapp.py`'s sealing are the
  highest-value pieces to port first.
- **Cells with their own disk.** Cells are diskless/netless by design
  today (nothing in a cell can hold password material or reach the
  network). A cell that mounts one specific, chosen, read-only sealed
  volume - so it can run something that needs real data without handing
  it the whole host - is a natural extension once something needs it.
- **A real boot-tested image.** The initramfs, `kos-init`, and the image
  builder are all written but have only run in a container with no VM
  support. First real target: boot the produced image in QEMU with OVMF
  and confirm the two password gates and `run hello` actually work.

## Shipped

- **`open`/`ps`/`attach`/`close`, `boot desktop`, `cmd` mode, zip `cd`
  (`ls`/`cat`/`explore`), `kos activity`.** Multiple apps can run at once
  in the background under a small per-instance broker; `attach` connects
  your terminal to one (Ctrl-C detaches, doesn't kill it); there's no
  multi-app desktop view unless you explicitly `boot desktop`; a third
  mode (`cmd`) exposes the raw device-command stream with no drawing at
  all; `kos ls`/`kos cat`/`kos explore` walk real directories and zip
  files as one tree without ever extracting anything; and `kos activity`
  merges "what's open right now" with "what recently happened" into one
  feed.
- **`kos update` (no downgrades), `kos view`, the `web` text browser.**
- **The first version:** password-gated pre-boot + login, `.kapp` apps
  kept zipped and sealed and run from a sandboxed memfd, mouse/keyboard
  "booting" with a trusted OS-drawn password overlay, TUI and graphical
  modes, KVM kernel cells.

## Where the password is required right now

Matches how the rest of KOS already worked before this round: a password is
asked for anything that *starts, stops, changes, or reveals the contents of*
something (`open`, `close`, `boot desktop`, `cat`/`view`, `install`,
`update`, `remove`, `run`, booting a device). Plain listings don't ask
(`ps`, `ls`, `list`, `doctor`, `audit`, `activity`) - same as `kos list` and
`kos audit` always have. `attach` doesn't ask again either: it's
reconnecting your terminal to something already authorized when it was
opened, though every device still has to be re-booted with the password for
that terminal.

## Open questions (need your call, not mine)

- npm/Node support - confirmed want, or was "kernel and NPM" pointing at
  something else?
- Is the password-gating line above right, or do you want it stricter (e.g.
  `ps`/`ls`/`activity` gated too)? Easy to change either way; wanted to
  flag the choice rather than just make it silently.
