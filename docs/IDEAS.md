# KOS idea feed

A running backlog, not a spec. When something here gets built, it moves to
"shipped"; nothing gets deleted, so this stays the record of where the
project has been and where it's going.

Add to this file freely - that's the point of it. It's the one place ideas
land instead of getting lost in chat.

## Backlog - not started yet

- **`--privileged-token` for `run`/`open`/`update`.** Only `install` and
  `optimize` accept one today. The other three each have extra live logic
  (network-permission prompts, `PermitStore` checks, `update all`'s
  directory scan) that needs its own careful pass to stay correct under
  the token path, not just the same quick plumbing `install`/`optimize`
  got.
- **Multiple named admin keyslots.** Right now there's exactly one; a
  second `kos admin setup` refuses. Independently-named, independently-
  revocable admins would need the keyslot storage to become a small list.
- **Local device mesh.** Paired KOS machines, encrypted peer links, handoff, then camera and tether sharing. Design and four open owner decisions are in `docs/MESH.md`; no code yet. Blocked on a crypto dependency and the firmware-gate question.
- **Backup follow-ups.** Encrypt blob bodies with a password-derived key
  instead of relying on LUKS2 + 0700 (needs a streaming AEAD; stdlib has none,
  so this wants the Rust port first). Restore a whole folder/snapshot in one
  password rather than per item. A "share this folder with the app" permission
  (see the per-resource permissions item below) so the `backup` app could be
  handed a folder instead of asking the OS to read a path. Garbage-collect
  orphan bodies after a crash between index write and blob delete.
- **Per-run caches on tmpfs.** An app's cache is scratch that is wiped when it ends. Putting it in RAM would mean
  zero SSD writes for it and no overwrite-and-fsync wipe at all (data is gone at power-off), at the price of RAM
  (it would need its own size cap). Not done: it changes `appdirs`/`cache`/`registry` layout and the wipe's
  guarantees.
- **seccomp for aarch64, and an allowlist.** The filter is an x86_64 denylist; other architectures run with
  Landlock + namespaces only. Needs that architecture's syscall numbers verified on real hardware.
- **Something outside the audit log that remembers its length.** A log cut short at the very end is not
  detected. A counter/anchor in a TPM or on another machine would close it.
- **Event-driven foreground session loop.** It wakes 4x/s while an app is in front of you; a pidfd plus a
  deadline-only timeout would remove that, but it is the trusted password overlay's loop.
- **Bind run permits to the app's hash.** `kos security` now lists grants for apps that are gone and permits that
  were never pinned to a `declared` list; binding to the sealed hash (already a backlog item below) would make
  them impossible.

- **More shared spaces.** The mechanism exists (`owns:`/`uses:`, `kos grant`); only `contacts`, `calendar` and
  `tasks` are wired. Candidates: the mail client and server sharing mailboxes, cloud storage and file sync,
  and calendar automation writing to `calendar`.
- **Grants that survive a reinstall safely.** Grants are by app name. Binding them to the app's sealed hash
  (and asking again when the hash changes) would stop a replaced app inheriting access.
- **`kos remove --purge`.** Removing an app keeps its `data/` (user data should not die by accident); an
  explicit purge that also deletes it and its grants would be the intentional way to wipe an app.
- **Seal the vault with a key.** Vault items are clear text on the LUKS volume. Derive a per-app key at launch
  (the password is available then) and keep it in the session, so items are sealed like `.kapp`s.
- **Audio / video / camera channel.** Conferencing, voice calling, speech recognition, text-to-speech, scanning
  and capture need device commands in the protocol (booted with the password like mouse and keyboard).
- **SMTP/IMAP/HTTP broker.** The mail server cannot listen on a port from inside the sandbox. A broker that owns
  the socket and forwards validated messages as commands would allow it.
- **Real charts.** Data apps draw text bars; a `chart` draw op in graphical mode would not need new trust.
- **Run-on-demand schedules.** Automation apps keep a schedule field but nothing fires it (no background
  services, by design). A password-started, bounded "run these at these times" session, like `kos scan watch`.

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

## Backlog - from the addresses / extensions / layers round

- **Route the rest through the layers.** `layers.traverse` covers using an app (open, run, close, switch,
  extend). Install, update, remove, permit, grant, device boots and `scan watch` still have their own gates; each
  would need a gui question ("is there a button?" - the file picker / the installer row) and an app question.
- **Live extension reload.** Contributions are read when a host starts or is attached. A `kos extend` while the
  host is attached could be pushed as a fresh `extensions` command, still only to that host.
- **More contribution types.** Only `entries` and `colors.accent` exist. Candidates that stay data: keymaps,
  a menu of requests the host may offer, a `background` color once a host uses it.
- **Per-entry approval for mods.** `app.mod` approves the whole add-on; showing the owner the entries and colors in
  the password prompt ("pin Hello, Browser; accent #c2410c") would make the decision more informed.
- **A `go` verb for the line shell.** `kos go` exists, and in the line shell a lone `kos://...` line or
  `open kos://...` opens the address, but `go` itself is not in the multilingual lexicon yet.
- **Sealed delivery.** Seal the pin record with a key derived at `kos extend` time so delivery can verify more
  than a sha256 without holding the password.
- **`kos aios` and the layers.** If AI OS requests should be forced through gui, app and kernel in KOS (not only
  in the NeuroClaw engine), `kos aios` is the thing to wire in; today it is deliberately a pass-through.

## Backlog - from the line-shell / desktop / admin round

- **Admin keyboard as its own privileged process.** Today the lease is a
  signed file; a root-owned broker over `SO_PEERCRED` would make it
  tamper-proof against code running as the owner (same fix as the
  `auth.json` gap in ARCHITECTURE.md).
- **Boot-test the exclusive keyboard.** `EVIOCGRAB` capture in
  `kos write` and the graphical desktop have not run on real hardware.
- **A real compositor for the desktop.** One app on screen at a time today;
  tiling several apps' frames (see the older "real windowing desktop" item)
  would let the taskbar be a bar *over* apps instead of a home screen.
- **Per-request permissions.** `system` is all-or-nothing; split it into
  list / open / close / focus so a clock app can list without being able to open.
- **More verbs and languages for the line shell**, and verb-last languages
  (Japanese, Turkish). A user-extensible lexicon file, still data-only.
- **More sandboxed runtimes for code lines** (JavaScript, shell), and an
  optional persistent per-session scope so `x = 5` then `print(x)` works.
- **Fewer desktop passwords.** Five at start is the honest cost of "nothing
  without the password"; a single desktop grant covering the two system apps
  is possible if that is too noisy.

## Shipped

- **Admin keyslot + root login + privileged autonomy.** `kos admin setup`
  (owner password only) adds a second password that unlocks the *same*
  master key (LUKS-style keyslots), off by default. Logging in with it at
  the console gives a root shell instead of the owner's - the deliberate,
  gated reversal of "no root login exists." `kos autonomy grant-privileged`
  needs that admin password specifically and mints a grant that genuinely
  can install/run/optimize unattended, because it carries the real seal
  key - unlike a normal grant, whose `.key()` always raises. Verified
  end-to-end over a real pty and a genuinely stdin-less subprocess: admin
  setup, owner correctly refused from minting a privileged grant, admin
  successfully mints one, and a fully unattended `kos install` succeeds
  with zero password prompts. 12 tests cover the crypto (owner and admin
  unlock to the identical master), the owner-only actions
  (`admin.remove`/`auth.change`) refusing even a valid admin password, and
  a real gap caught and fixed during development: a privileged grant
  minted for one app name could not be redeemed to install a different one
  just because the same grant id was reused, since the target for
  `app.install` isn't known until the file is parsed. **The admin keyslot
  itself only ever lasts until the next reboot** - it lives on `/run`
  (tmpfs), which `kos-init` mounts fresh and empty on every boot, so root
  access and privileged autonomy are re-decided every session rather than
  a standing account on disk (already-issued privileged grants are
  unaffected - they carry their own seal key and keep working for their
  own remaining duration independent of whether the admin account that
  minted them still exists).
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
- **Backup, as a KOS app (`kos backup`, `examples/backup`).** The Universal
  Backup System's core idea - content-addressed dedup - brought in under KOS's
  rules. Engine in `kos/backup.py`: bodies stored once per SHA-256, scanned
  before they are stored, index HMAC-sealed, bodies re-hashed on read, every
  action password-gated, restore through the guarded write and never
  overwriting. The `backup` app is a `system`-permission front-end: a sandboxed
  app can't read files or keep state, so it asks the OS. Deliberately *not*
  brought over: the HTTP server, user accounts/JWTs, cloud-provider connectors,
  the browser extension and the mock ad-earnings ledger - they conflict with
  "no background services, no network without your password" and were never
  backup logic.
- **Addresses, extensions, mods, and the three layers.** `kos go kos://web/example.com` opens an app the way
  a browser opens a site (`open` and `run` take addresses too; the app is told the path). Two kinds of app, both
  ordinary `.kapp`s: an **extension** adds to an ordinary app, a **mod** modifies a system app, as validated data
  the owner switches on with `kos extend` (password, pinned to the exact build). Every way of using an app - open,
  run, close, switch, extend - passes through one door, `layers.traverse`: the graphical button clicker, then app
  commands, then kernel commands, each audited, a refusal stopping the rest (so no password for an unpermitted
  app). See ARCHITECTURE.md for the table and the gaps.

- **Line shell, desktop of apps, administrator keyboard.** Every line is a
  command in the user's own language, and code is a command too (run sandboxed,
  never on the host); `requires` (unlock requires the keyboard requires the
  kernel; a write owes a scan and optimize afterwards); the taskbar
  and App Library are ordinary apps that *ask* the OS via `request`, with the
  right mouse as the App Library; the unlock password boots a kernel-gated
  administrator keyboard whose guarded `kos write` needs a clean security
  scan and a disk optimize.

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
`optimize`, starting `scan watch`, booting a device, and every `backup`
action (`add`, `list`, `remove`, `restore` - listing too, since file names are
private; restore asks twice: once to read the vault, once for the guarded write). Plain listings don't
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
