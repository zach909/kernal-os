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
- **Per-app permission prompts for specific resources.** `kos permit`
  (shipped) is a yes/no "may this app run at all" gate. What's still
  missing is finer-grained resource permissions the way `network` already
  works: a clipboard permission (there isn't one yet), a "share this one
  file/folder with me" permission, beyond the general per-run cache every
  app already gets now.
- **Signed app publishers.** `kos update`/`kos update all` refuse
  downgrades and scan everything, but don't check *who* built the newer
  version. An optional publisher signature on top of the install seal
  would let `kos install` show "signed by X" and updates require the same
  signer.
- **Seccomp filter on top of Landlock.** The sandbox is Landlock +
  namespaces + rlimits today. A tight seccomp-bpf allowlist would cut the
  syscall surface further, especially for native (non-Python) apps.
- **A rotating command log per open instance.** `kos activity`/`kos audit`
  cover installs, runs, device boots, scans, permits, optimize runs. An
  opened app's live command traffic still isn't recorded anywhere unless
  you `attach` in `cmd` mode and watch it. A "last N commands" ring buffer
  per instance would make debugging a backgrounded app possible without
  attaching.
- **A signature feed for the scanner.** `kos/scan.py` is deliberately
  described as a small, honest, hand-written rule set, not a full
  antivirus. A pluggable, updatable signature source (still scanned
  through the same recursion, still gated the same way) would be the
  natural next step if this needs to catch more than the heuristics do.
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
- **`kos cp`/`kos write`, alongside `kos mv`.** The three-password
  move/optimize/scan pipeline covers moving something; a copy or a
  from-scratch write through the same pipeline doesn't exist yet.
- **fanotify-based, mount-wide protection.** `kos scan protect` enforces
  with plain file mode, which is real but directory-scoped and only
  binding on non-root processes. A `FAN_OPEN_PERM`-based enforcer would let
  the kernel itself hold an open *pending* until KOS has scanned the file's
  content, which is a stronger and more general mechanism than a mode bit -
  worth it if directory-level locking turns out not to be enough.

## Shipped

- **Autonomous action, without ever storing the password.** `kos autonomy
  grant ACTION TARGET --for N --uses M` needs the real password once, to
  mint a temporary permission - never the password itself, which is never
  written to disk. `kos close ID --token GRANT` (also `cell.start`/`stop`,
  `app.permit`/`revoke`, `scan.watch`'s start, `boot desktop`) can then
  redeem it later with zero password and zero terminal, proven end-to-end
  with a real subprocess given `stdin=DEVNULL` - genuinely no way to type
  anything, and it still worked. The permanent limit, not a gap to close
  later: a redeemed grant's `.key()` always raises, so it can never derive
  `kapp-seal` or any other master-key material - meaning it structurally
  cannot install, update, run, open, or optimize anything, no matter what
  the allowlist is ever extended to include. 10 tests cover issuance
  requiring the real password, the allowlist rejecting everything else,
  successful redemption, the key-derivation refusal, use-count exhaustion,
  expiry, wrong action/target, a tampered grant file's HMAC failing, and
  revocation.
- **`kos control`/`kos attach` no longer share one broker slot, `kos scan
  watch --background`, `kos mv` for whole directories.** `kos control` now
  has its own door into the broker (`Broker.control_sock_path`), so sending
  a control command no longer bumps a live `kos attach` off its connection
  - verified by holding an attach open, sending a control command, and
  confirming the attach both survived and saw the reply. `kos scan watch
  DIR --background` runs the exact same watch loop (including protected-
  directory unlock/relock) detached, with `kos scan jobs`/`kos scan stop
  ID` to manage it - the same fork+daemonize+registry pattern `kos open`
  already used for apps. `kos mv` moving a whole directory tree, not just
  one file, turned out to already work (`shutil.move` and the scan step's
  recursive walk both already handled it) - confirmed by test rather than
  needing new code.
- **`kos scan protect`/`unprotect`, `kos control`, `kos mv`.** A protected
  directory is locked (mode 0500 - no write for anyone) the instant you
  protect it and stays that way except while a `kos scan watch` covering it
  is actively running, which is what "needs the password to start, but
  blocks the move if you don't let it start" turned into: enforced by the
  kernel's own permission check, not just observed after the fact - a
  flagged file dropped in while unlocked is quarantined immediately, not
  just reported. Verified for real: a non-root write into a protected
  directory is refused, the same write succeeds the moment the watch is
  running, and the directory relocks the instant the watch stops, by any
  path (Ctrl-C, error, or otherwise). `kos control ID mouse|keyboard ...`
  sends the exact same commands a real boot + physical input would, gated
  by the exact same password, once per invocation, with no batching that
  would let one password authorize an unbounded stream of later input -
  the honest alternative to a literal per-keystroke prompt, which is not
  just impractical but logically impossible (entering a password is itself
  a sequence of keystrokes). `kos mv SRC DST` is a three-step pipeline -
  move, then `optimize`, then scan the destination - each step its own
  password prompt; declining any step stops the whole thing right there,
  and whatever already happened before that point is never undone.
- **The security scanner, install/update quarantine, `kos scan watch`,
  `kos permit`, per-run cache wiped on exit, `kos update all`,
  `kos optimize`.** Every install and update is scanned (EICAR +
  heuristics, recursing into zips without extracting) before the password
  is even asked; a flagged file is quarantined, never installed. Starting
  `kos scan watch DIR` needs the password, like starting a kernel cell,
  and from then on scans every file written there until you stop it -
  resolving the tension between "scan everything on write" and "nothing
  acts without the password" the same way cells already did. `kos permit
  NAME` is a separate, persistent "may this app run at all" grant that
  never replaces the per-run password. Every run gets a private writable
  cache directory, securely wiped the instant its process ends. `kos
  update all --from DIR` updates every installed app with a newer,
  clean `.kapp` in a directory. `kos optimize` recompresses installed
  apps (re-sealed at the new bytes), prunes dead background-app records
  and old quarantine files, and trims the audit log. The `web` browser
  now scans every page it fetches and shows the result in its status
  line.
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

A password is asked for anything that *starts, stops, changes, or reveals
the contents of* something: `open`, `close`, `boot desktop`, `cat`/`view`,
`install`, `update`(`all`), `remove`, `run`, `permit`(`--revoke`),
`optimize`, starting `scan watch`, booting a device. Plain listings don't
ask (`ps`, `ls`, `list`, `doctor`, `audit`, `activity`, `permit --list`,
`scan file`) - `scan file` is read-only in the same sense `kos list` is,
even though it's a security check, because it changes nothing and reveals
only whether a file matches a known-bad pattern, not new private content.
`attach` doesn't ask again either: it's reconnecting your terminal to
something already authorized when it was opened, though every device still
has to be re-booted with the password for that terminal. This line was
flagged as an open question last round and heard no objection, so it's the
standing rule now - reopen it any time.

## Open questions (need your call, not mine)

- npm/Node support - confirmed want, or was "kernel and NPM" pointing at
  something else?
