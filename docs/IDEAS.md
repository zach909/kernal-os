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
- **`kos scan watch` as a background instance.** Right now it only runs in
  the foreground of the terminal that started it. Giving it the same
  `kos open`/broker treatment as apps - start it, walk away, `kos ps`
  shows it, `kos close` stops it - would match how everything else
  long-running in KOS already works.
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

## Backlog - from the line-shell / desktop / admin round

- **Admin keyboard as its own privileged process.** Today the lease is a
  signed file; a root-owned broker over `SO_PEERCRED` would make it
  tamper-proof against code running as the owner (same fix as the
  `auth.json` gap in ARCHITECTURE.md).
- **Boot-test the exclusive keyboard.** `EVIOCGRAB` capture in
  `kos write` and the graphical desktop have not run on real hardware.
- **Damage-rectangle compositing.** The compositor (`kos/shell.py`) caches each layer's glass but repaints all
  layer content on every compose. A damage-rect pass (repaint only what changed) would let larger screens and many
  busy apps stay smooth in pure Python; a C/Rust blur would let it use real-time effects.
- **Smooth type everywhere.** `stext` (TrueType, anti-aliased) is used by the menubar, dock, search, window titles,
  widgets and icon labels; the window *contents* of the other apps are still text pages (drawn in a smooth monospace).
  Moving them to native graphical layouts with proportional type is the next visual step. Kerning, hinting and
  OpenType (CFF) outlines are missing from `kos/ttf.py`.
- **The 3D stack.** The look of the whole interface as layered cards in space: the graphical interface in front, the terminal view visible beneath it when
  you look down, and the button-by-button view behind. Today the four looks are switched, and the tilt only shears the front frame.
- **Verify the multiples on hardware.** Seats (per-device evdev state), several framebuffers, and a second display's hot-plug are exercised only with scripted
  devices and headless outputs. Per-seat passwords/sudo windows, window move between displays by drag with per-display scale, and a taskbar per display are not done.
- **Real quantum drivers.** The device layer finds hardware and grants a driver one device node; the first vendor driver (and a real device to test it on) is the
  missing half. Same for photonic and Majorana-based devices, which have no common interface - each needs its own driver written to the OpenQASM job protocol.
- **A graphical display for converted programs.** `.deb`/AppImage programs run text-only. A nested X/Wayland server rendered into a window would let GUI AppImages run.
- **Damage-rectangle compositing and a native blur.** Repaints are ~20 ms; most of that is re-rasterizing text and shapes in pure Python for every layer.
- **A compiler.** Code lines in languages other than Python are understood but not run. Which language, and whether to drive a host compiler in the sandbox or write
  one, is undecided.
- **Dock polish.** Hover magnification beyond a small lift, labels on hover, drag-to-reorder pinned apps, and
  auto-hide (the layer exists to hide, but nothing triggers it yet).
- **Verify `native-desktop/` on a live X11 session.** It was written without an X server: config syntax for polybar,
  picom, plank and rofi is unverified against real versions; add CI with Xvfb + the real programs.
- **Per-request permissions.** `system` is all-or-nothing; split it into
  list / open / close / focus so a clock app can list without being able to open.
- **More verbs and languages for the line shell**, and verb-last languages
  (Japanese, Turkish). A user-extensible lexicon file, still data-only.
- **Encrypt backups before they leave the machine.** Needs a vetted crypto
  library (stdlib has no AEAD); until then "private" is only GitHub's access control.
- **Restore a whole folder** in one guarded step (today: one file per password).
- **More sandboxed runtimes for code lines** (JavaScript, shell), and an
  optional persistent per-session scope so `x = 5` then `print(x)` works.
- **Fewer desktop passwords.** Five at start is the honest cost of "nothing
  without the password"; a single desktop grant covering the two system apps
  is possible if that is too noisy.

- **Publisher signatures for sources.** `kapps.json` is trusted as far as TLS and your choice of
  source go; signed indexes (a key you pin per source) would let `updates` prove who built a version.
- **Run npm apps from a sealed in-RAM filesystem** instead of an unpacked tmpfs copy, and give
  cells a Node.js so they can run them.
- **Automatic update checks on your schedule**, still ending in a password prompt before anything installs.

## Shipped

- **npm runtime, eight OS-service apps, provenance + updates.** Every app starts with
  `npm run start` (unpacked into RAM, read-only, same sandbox); processes, memory, filesystem,
  devices, network, isolation, health and resources are separate apps over real `/proc` and `/sys`
  data; the Updates app shows where everything came from and installs newer versions from your
  sources (hash-checked, scanned, permission-diff held back).

- **Line shell, desktop of apps, administrator keyboard.** Every line is a
  command in the user's own language, and code is a command too (run sandboxed,
  never on the host); `requires` (unlock requires the keyboard requires the
  kernel; a write owes a scan and optimize afterwards); the built-in apps (menubar, dock,
  app library, file viewer, file editor, backup + private-GitHub push, settings,
  security, terminal); the taskbar
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
