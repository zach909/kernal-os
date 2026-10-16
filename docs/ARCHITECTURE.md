# KOS architecture and threat model

## Trust chain
1. UEFI Secure Boot verifies one signed Unified Kernel Image (kernel +
   pre-boot initramfs + command line). Tampering with the pre-boot prompt
   (an "evil maid" password logger) breaks the signature.
2. The pre-boot environment unlocks LUKS2 (Argon2id). There is no rescue
   shell. The volume key lives in the kernel keyring only.
3. `kos-init` mounts pseudo-filesystems restrictively, applies sysctls, asks
   for the password again, then runs the owner's shell as uid 1000. No root
   login exists.
4. Every action after that goes through `Authority.authorize(action, target)`.

## Keys
`master = scrypt(password, salt)`. Stored: salt, params, `HMAC(master,
"verifier")`. Derived: `HMAC(master, "kapp-seal")` seals apps. The master key
exists only in mlock'd memory for the duration of one action.

## App lifecycle
install: validate zip → **scan** (`kos/scan.py`; a flagged zip is quarantined
and the password is never asked) → password → seal → store zip unchanged.
run: permit check (`kos/permit.py`; refused before the password too) →
password → verify seal *before* parsing → sealed memfd → sandboxed process
(nobody, no_new_privs, user/net/ipc/uts namespaces, rlimits, Landlock
fs+net+signal scoping, one private writable cache dir) → only a command
socket to the OS. The cache dir is securely wiped (`kos/cache.py`) the
instant the process ends, by whichever of `run`'s `_run_session` or the
`open` broker's `_shutdown` owns that process.
update: same name, strictly newer version, scanned, password, re-seal.
`kos update all --from DIR` runs that same path against every installed app.

## Line shell (`kos/lang.py`, `kos/coderun.py`)
Every line is a command. Human language becomes one structured argv for
`kos.cli.main` - no shell string anywhere, so `;`, `|`, `&&` and `$()` have
nothing to attach to. Code is a command too (`kos exec`), but is never run on
the host: it is scanned, needs `code.run` (the password), and runs as an
in-memory one-shot `.kapp` under the normal sandbox with a timeout and a
wiped cache dir. Only Python has a runtime in the sandbox; other languages
report that and run nothing. Everything the shell can start still passes
through the same `Authority.authorize` gates.

## Requires (`kos/requires.py`)
One table, `RULES`, is the policy. `before` is resolved by `Requirements.ensure`
(depth-first, cycle-checked, the failing chain is the error message; a
provider may *boot* what is missing). `after` is an obligation: `Ledger.owe`
writes it to `owed.json` the moment the trigger happens, `Ledger.done` strikes
steps off, and an unreadable ledger blocks rather than frees. Unlock requires
admin keyboard requires kernel; `file.write` requires the keyboard before and
scan + optimize after.

## Administrator keyboard (`kos/admin.py`)
`session.login` (or `admin.boot`) grant -> `AdminKeyboard.boot`: `kernel_gaps()`
(Landlock + user namespaces) and a keyboard probe, then `admin-lease.json`
signed with `HMAC(master, "admin-keyboard")`, bound to `boot_id`, 8 h TTL.
`require_booted()` (no password) refuses early; `verify()` (needs a password
grant) checks the signature. Locking deletes the lease.
`write_file`: `ensure("file.write")` -> ledger must be clear -> `authorize` ->
`verify` -> atomic write -> `owe` -> scan the file on disk (quarantine if
flagged) -> `optimize(grant=...)` -> strike off. The password is read through
`AdminPrompter` over `EvdevDevices`, which grabs the keyboards (`EVIOCGRAB`)
and refuses if another process already holds one.
Gap: no separate privileged process; the lease is tamper-evident, not
tamper-proof against code running as the owner. A flagged file exists on disk
briefly (between write and scan) because the scan is an obligation *after*.

## Everything is an app (`kos/system.py`, `kos/desktop.py`)
Apps send `{"cmd":"request",...}` (schema-checked in `protocol.py`). The OS
honours it only if the *instance record* (written by the OS at open time
from the verified manifest) has `system: true`; `open`/`close` additionally
need the password via the session overlay; `focus` is an attach. The right
mouse button is consumed by `Session.route` when `right_click_to` is set -
it is never forwarded. `Desktop` is a small state machine over instance ids;
devices booted in the first session are re-enabled (not re-authorized) in the
following ones via `preboot`.
Gap: the desktop's first-session password also covers every later app it
switches to for *devices*; opening an app still always asks.

## Compositor and the interface apps (`kos/shell.py`, `kos/fbgfx.py`, `kos/ttf.py`)
`kos boot desktop` runs one `Shell` that owns the screen and the input devices. Each interface part (wallpaper,
menubar, dock, icons, search, widget handler, widgets) and each window is a **layer** backed by a separate
sandboxed app instance. Apps send the same schema-checked `frame` ops as any graphical app (`rect`, `line`,
`text`, `stext` for smooth type, and `poly` for anti-aliased filled shapes - the pointer is drawn with it); the shell validates them, rasterizes into a per-layer surface clipped to the
layer's rect, and composites by z-order. Glass (frost = downsampled blur, tint, sheen, bevel, shadow, rounded
corners) is applied by the OS *around* what an app draws, cached per layer and invalidated only when something
beneath it changes. Window chrome (traffic lights, title bar) is drawn by the OS, so an app cannot fake it.
Trust: apps have no screen, device or file access; `resize` and `layout` need the extra manifest permission
`shell` (the dock uses it to size itself - the OS keeps it centered; the search box to grow its result list),
everything else needs `system` and a password in the OS's own overlay (`SessionPrompter`, drawn last, never
routed to an app). One boot password authorizes the whole interface set (`Authority.authorize_batch`).
Smooth text: `ttf.py` parses TrueType `glyf` outlines, flattens the quadratics and computes exact area coverage
(the accumulation-buffer method), caching per (glyph, size). The `hello` event carries the advance table so an
app can measure text it cannot rasterize. Limits: no kerning, no hinting, no CFF/OpenType outlines, overlapping
contours are clamped; falls back to the pixel font if no system face exists.
Gap: layers repaint their content on every compose (only the glass is cached); fine at 1280x720 in pure
Python (a full compose is ~0.5 s cold, a one-widget change ~55 ms) but a large screen with many busy apps will
want a damage-rectangle pass. Pointer events go to the topmost layer under the pointer; there is no keyboard
focus ring or accessibility tree yet.

## Native desktop kit (`native-desktop/`)
Not part of the trust base: a per-user configuration kit for a stock Linux X11 session (polybar, plank, picom,
rofi, GTK, fontconfig) that reproduces the same layout and accent. `kos-desktop apply` records the first-seen
state of every file it touches in a baseline that later runs never overwrite, so `revert` is exact however many
times you applied. It never uses root outside the package step, never replaces your window manager, and refuses
on Wayland. It could not be exercised against a live X server in the development environment.

## Password layers and the sudo window (`kos/auth.py`)
Every action belongs to one of four layers (`LAYER_OF`): interface, app, command, kernel. `Authority.authorize` first asks `_shortcut`: the interface layer
may be set to "off" (`Policy`, a kernel-layer change; those grants carry no key, so nothing can be sealed with them), and a live **sudo window** may cover
the interface/app/command layers. The window is a module-level object holding the master key in locked memory (`SecretBytes`) with a monotonic deadline:
in-process only, never written, bounded to 60 minutes, closed by `sudo off`. `NEVER_REMEMBERED` (permissions, password change, sources, pushes, KOS updates,
mods, cells, the policy itself, the window) always prompts, and the kernel layer cannot be named in a window. Gap: inside a window, a permitted app with the
`system` permission can trigger remembered actions without a prompt; the prompt is still the OS's own, and every use is audited as `granted-sudo`.

## Looks, controls, the pointer and effects (`kos/looks.py`, `kos/shell.py`)
Apps declare controls with invisible `hit` ops; `Shell.controls()` gathers them with the window frames the OS draws, and `activate()` presses one by sending
the click an equivalent pointer would. That one list drives the terminal look, Tab/Enter in every look, and the `[Label]` text look. The pointer and the click
effects are apps in overlay layers: the shell moves their small layers (centered on the pointer or the click), never routes them input, sends them `cursor`
and `click` events (permission `pointer`) and, while they ask for it (permission `animate`), 24 `anim` events a second. The composed base frame is cached by
a signature of every layer's revision/rect/visibility, so overlays and the pointer repaint a copy of a cached frame; the glass of each layer is cached as before.
The 3D tilt shears that frame (rows and 16 px strips). Gap: no per-pixel perspective; layers still repaint their content on every base rebuild.

## Foreign programs: the bundle runtime (`kos/convert.py`, `kos/hostrun.py`)
`kos convert` turns a `.deb` or an AppImage into a `runtime: "bundle"` app: a program tree. `loader._plan_bundle` unpacks it read-only into RAM, writes a tiny
`package.json` whose `start` script launches `kos/hostrun.py` (a Python adapter, inside the sandbox) via `npm run start`, and the adapter starts the program as
its child - the child inherits Landlock, the empty network namespace and no_new_privs. AppImages additionally get their private scratch directory marked
executable (`exec_scratch`) because their runtime unpacks there; the sandbox now also allows symlinks in scratch. The converter never executes anything,
drops setuid bits, resolves symlinks inside the package only, ignores maintainer scripts, scans the result and refuses a flagged one.

## The 3D look: blocks (`kos/blocks.py`, `kos/shell.py`)
`Shell._layer_blocks` makes one `Block` per shown layer: its front texture (`_front_texture`: glass layers painted over the wallpaper and given a
rounded alpha mask; layers with no glass painted over black and over white to recover transparency), its height (`BLOCK_HEIGHT`, windows by size) and
`z_back` = the highest block beneath it that overlaps it (windows rest on panels, not on each other; they stack by a small step). `blocks.render` draws
the wallpaper as a plane larger than the screen, then each block farthest first: for every face it tests the outward normal against the camera,
projects the four corners, and `fill_face` walks the scanlines, computing texture coordinates from the inverse homography (exact at the ends of 8-pixel
spans, linear between), halving the texture when the face is small. The top face is `matrix_texture` (drawn from the block's own words, animated by
`Shell._matrix_t`, which only ticks while a top face can be seen), the back is `controls_texture`. `Shell.cam` is yaw/pitch; `orbit()` changes it, Alt+arrows
and the middle-button drag call it; `_flat` unprojects a pointer position through the nearest block's inverse homography so `_route` hit-tests on flat
coordinates while the cursor is drawn where the pointer really is. `Framebuffer.apply(extrude=True)` gives text depth in this look. Gap: speed
(cached per scene and camera, ~0.3-1 s a frame), no arbitrary meshes, no emoji font.

## Scoped capabilities and the ledger (`kos/capabilities.py`, `kos/services.py`)
`capabilities.ACTION_SCOPE` maps every OS request to one scope; a manifest holds `system:<scope>` permissions (`Manifest.scopes`; the bare `system` is
`{"*"}` and fits no mod slot). `SystemBridge(scopes=...)` checks every request before dispatch, `Layer.allows(action)` gates the shell's own handlers and
what is pushed to an app (window list: `apps`; notifications: `notify`; links: `links`), `mods.CEILING` is written in scopes. `services.actions_used`
reads an app's source for the requests it makes, so the test that each built-in manifest equals the scopes its code needs cannot be fooled by an
understated manifest. `kos services` prints `services.CORE` (what must stay outside the app model, and what each piece cannot do) and the app ledger.

## Immersive looks and neural intents (`kos/looks.py`, `kos/shell.py`, `kos/protocol.py`)
`looks.IMMERSIVE = (vr, mr, neural)`. `Shell.set_look` refuses them unless `authorized=True`, which only `Shell.authorize_immersive` (the
`look.immersive` action: interface layer, in `NEVER_REMEMBERED`, not in `KEYLESS`) gives; the saved layout never restores them. `render_stereo`
shifts every layer's rect by `eye * depth * u` (plus a head-turn term from the pointer), composes each eye once (cached on the base signature and the
quantised yaw), restores the rects, paints the pointer per eye (never cached) and squeezes each eye to half width. Mixed reality is the same with the
wallpaper layer's `blit` pixels as the backdrop (`has_passthrough`). The neural look is the normal frame plus the focus ring and a card; `_neural_step`
advances the scan on a dwell timer; `Shell.intent` accepts one of `protocol.INTENTS` from a layer whose app holds the `neural` permission - which a
manifest may only have with `"driver": "neural"` - and only while the look is on, rate limited. The `blit` op (raw RGB, <= 96000 px, scaled up to 32x) is
how a camera driver's frames reach the screen. Gap: no real headset, camera or neural device was available; drivers for them are to be written against
this contract.

## App folders and encryption (`kos/paths.py`, `kos/loader.py`, `kos/vault.py`, `kos/encryption.py`)
`Paths.data_dir(name)` makes `<state>/appdata/NAME` (0700). `loader.apply_to_policy(..., data_dir)` adds it to the Landlock write set and records it on the
policy; `loader.launch` passes `KOS_DATA_DIR`. `vault` seals a file with AES-256-GCM in 1 MiB chunks (nonce = random prefix + counter, AAD = chunk index +
last-flag) under `HMAC(grant key, salt)`; `Offsite.push` seals before git ever sees the file. `encryption.check` reads /proc and /sys (injectable, so
tests can use a pretend machine) and `encryption.harden` sets the core limit to 0 and clears PR_SET_DUMPABLE at the start of every `kos` command.

## System mods (`kos/mods.py`)
Slots, ceilings and the enabled set live in `<state>/mods.json`. `desktop.boot_core` asks `mods.core_names` which app to run for each slot; the shell tracks
`Layer.slot`, so everything that used to look up "dock" or "search" by app name works for a mod filling that slot. A widget mod is a new widget slot.

## Seats, desktops, instances, displays (`kos/shell.py`, `kos/devices.py`, `kos/display.py`)
`Shell.seats` holds one `Seat` per pointer/keyboard pair (position, drag, focus, text-box owner, button state). `route()` sets `Shell._seat` for the
duration of an event and `focus`, `pointer`, `drag`, `key_target`, `down` are properties over it, so the existing handlers run per seat unchanged; the union of
every seat's focus decides which windows draw as focused. Evdev gives each device its own `EvdevTranslator` and tags its events with the seat. Layers carry `ws`
(None = every desktop); `shown()` is the one visibility test used for painting, hit-testing, controls and the text look, and the desktop number is part of the base
frame's signature. `open_window(new=, background=)` starts a fresh instance or opens minimized; the opener adopts an instance no window shows yet. Several outputs
are a `MultiBackend`: the shell composes the full width, lays the panel, dock, sidebar and new windows out on the primary output, centres the password prompt there
and `show()` cuts the frame into one slice per output. Gap: one password prompt at a time; one sudo window per process; seats and displays unverified on hardware.

## Self-heal and auto-update (`kos/heal.py`, `kos/autoupdate.py`, `kos/osupdate.py`)
Live healing is in the shell (`remove(expected=False)` -> `_schedule_heal` -> `_run_heal`): backoff, a restarter that reuses a still-running instance or starts a new
one through the normal authority, give-up and fall-back-to-built-in. `heal.quick` (password-free, safe at every boot) quarantines corrupt preference files and wipes
stale scratch; `heal.repair` verifies every seal with one batch grant and reinstalls built-ins. Nothing widens a permission. Auto-update separates *due* (policy +
clock), *can run unattended* (a live sudo window covering the app and command layers) and *what is only listed* (KOS core: kernel-layer; OS: root). Gap: the OS can
only be listed - applying it needs root KOS does not hold.

## Hardware device layer (`kos/qdev.py`, `kos/qjob.py`, `kos/sandbox.py`) - generic; quantum is one optional driver kind
The manifest keys `devices` (up to four `/dev/...` globs) and `driver` (`quantum`) describe a driver. `authorize_app_action` resolves the globs to existing nodes, asks,
requires the password (`app.device`, never remembered) and passes the nodes as `SandboxPolicy.device_paths`, which Landlock opens for read, write and ioctl on exactly
those files. `qjob.run_job` is the one-shot runner (same shape as `coderun`): verify the driver, grant, launch in `cmd` mode, send the job, read one `RESULT` line,
kill it. Detection (`qdev.detect`) only reads names and never opens a device. Gap: no vendor driver exists in this repository and no real device was tested.

## Built-in apps, backups, off-site (`kos/sysinfo.py`, `kos/backup.py`, `kos/offsite.py`)
More `request`s on the same bridge: `info`, `ls`, `view` (password), `scan`,
`optimize`/`settle` (password), `permit`/`revoke` (password), `line` (the line
shell; code lines go to `coderun`), `save`/`restore` (the guarded write),
`backup`/`backups`/`push`/`remote`. `view` returns `lossy` when what is shown
would not round-trip (truncated, tabs, CRLF, long lines, non-UTF-8); the editor
refuses to save those. `backup.create` writes a zip under `<state>/backups`
(KOS state: not writable through `kos write`), owes a scan (`requires.RULES`),
quarantines a flagged backup. `Offsite.push` needs a github.com-only remote the
*user* set, probes it anonymously (`git ls-remote`, credentials/prompts/global
config disabled) and refuses a publicly readable one, twice (before and after
the password), then commits the zip to a local mirror and pushes it using the
user's own git credentials. Gap: not encrypted; the probe cannot distinguish a
private repo from a missing one.

## npm runtime (`kos/loader.py`)
`runtime: "npm"`: `loader._plan_npm` unpacks the verified archive into
`/dev/shm/kos-<uid>/<app>-<rand>/app` (files 0444/0555) next to a writable
`scratch` (HOME, TMPDIR, npm cache/logs); the sandbox gets scratch as its only
writable directory and `app` + the Node prefix as read-only. Command:
`node <prefix>/lib/node_modules/npm/bin/npm-cli.js run <entry>` (or `npx-cli.js
--no-install TOOL`) with `npm_config_offline`, no update notifier/audit/fund, distinct
empty user/global npmrc files (npm refuses to load one file twice), `OPENSSL_CONF=/dev/null`
(node reads `/etc/ssl/openssl.cnf` at start; the sandbox says no) and a 64 GiB address-space
limit (V8 reserves address space it never touches). **npm closes inherited fds above 2**, so
the command channel of an npm app is its **stdin** (`KOS_CHANNEL_FD=0`). Gap: the code is
unpacked (RAM only) rather than run from a sealed memfd; npm startup costs ~0.25 s.

## OS facts and control (`kos/osinfo.py`, `kos/proctl.py`, `kos/fschange.py`)
Eight read-only readers over `/proc` and `/sys` (`sys` request; roots are parameters so
parsers are tested against fixtures). Acting needs the password: `process.signal` /
`process.renice` (same-uid only, never PID 1 / KOS / its ancestors, four signals, nice can only
rise), `file.change` (also `requires` the admin keyboard; never KOS state; delete = recoverable
trash that `optimize` empties after 30 days; chmod refuses setuid/setgid), `net.check` (the
only thing that touches the outside). `ticks` is a manifest permission recorded on the instance;
`Session` then sends `{"cmd":"tick"}` once a second.

## Provenance and updates (`kos/provenance.py`, `kos/sources.py`)
`provenance.json` is written by `AppStore._install` for every install/update (source, location,
sha256, via, history); an entry whose sha256 no longer matches the installed app reads "changed
since recorded". `Sources.check` (password) fetches each source's index (https only, bounded,
no credentials in URLs, redirects may not downgrade), picks the highest version per app and caches
the report; `install` re-downloads, **verifies the advertised sha256**, checks the file's manifest
is the app/version the index promised, holds back added permissions, then `AppStore.update`
(scan/quarantine, no downgrade, seal). `core_update` is `git fetch` + `merge --ff-only @{u}` and
refuses a dirty or diverged checkout. Gap: an https source is trusted for its index as much as
TLS and your choice of source allow - there is no publisher signature yet.

## Scanning
`kos/scan.py` is static and heuristic: the EICAR test string plus a short
list of hand-written regex rules (reverse shells, obfuscated
`eval(base64...)`, hardcoded credential-file reads, fork bombs,
`curl | sh`). It recurses into zip members (including nested zips) without
ever extracting them - the same "never unzip" rule as everywhere else.
It is wired in at two points:
* **install/update** - synchronous, scanned before the password prompt.
* **`kos scan watch DIR`** - an inotify-based watcher (`kos/watch.py`) that
  scans every file written under given directories, *started* with the
  password (same pattern as `cell.start`) and running only until you stop
  it. This is the resolution to a real tension: an always-on background
  scanner would itself be exactly the kind of autonomous action the whole
  system is built to forbid, so the privileged act is starting the watch,
  not each scan it performs afterward.
Out of scope for one file: a maintained signature feed. What's here is real
static analysis of a small, documented rule set, not a placeholder.

## Command protocol
See `kos/protocol.py`. All app output is schema-checked and stripped of control
characters (no terminal escape injection). Input reaches the app only for
devices booted with the password; while a secure prompt is up the app gets
nothing.

## Multi-kernel
Today: KVM micro-VMs pinned to dedicated cores, no disk, no NIC, vsock only.
The cell holds no password material. Future: Linux's proposed out-of-tree
"multikernel" work (independent kernels on partitioned CPUs/memory without a
hypervisor) as a bare-metal backend.

## Known gaps
* Python userland: secrets may be copied by the interpreter → Rust port.
* A process running as the owner outside KOS could read `auth.json` and guess
  passwords offline (at scrypt cost). Fix: root-owned verifier + tiny setuid-free
  broker over SO_PEERCRED.
* No seccomp filter yet; Landlock + namespaces only.
* Updates are checked for version order but not for publisher signature yet.
* Background apps (`kos open`): the broker's Unix socket path is under
  `<state>/instances/`, which must fit in `sizeof(sockaddr_un.sun_path)`
  (108 bytes on Linux) - fine under the real `/var/lib/kos` root, but a very
  deeply nested `KOS_ROOT` in development can exceed it.
* While nobody is `attach`ed to a `kos open`ed app, its output is read and
  dropped by the broker rather than buffered, so a burst of output with no
  one attached is lost rather than replayed on the next attach.
* `kos scan watch` runs in the foreground of the terminal that started it
  (there is no `kos open`-style background form of it yet); it stops with
  Ctrl-C or when that terminal closes.
* The scanner's rule set is hand-written and small; it will not catch
  everything a real signature-feed-backed antivirus would, and it is
  regex-based, so a determined obfuscator can evade it. It is a real first
  layer, not a complete one.
* `kos optimize`'s recompression only ever produces byte-identical content
  when unzipped (`KApp(new_data)` is constructed and would raise before
  anything is written back otherwise) and re-derives the seal from the
  password at the same step, so a recompressed app never goes stale
  relative to its own seal - but it does mean `kos optimize` needs the
  password, same as any other action that changes what's on disk.
