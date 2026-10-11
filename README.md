# kernal-os (KOS)

A security-first operating system built on the Linux kernel. One rule runs
through everything: **nothing happens without your password.** There are no
background services, no cached logins, no autostart, and no way to feed a
password in from a script.

## How it works

```
power on
  └─ pre-boot environment (initramfs "sub-OS", signed with the kernel)
       asks for password → unlocks LUKS2 disk (key stays in kernel RAM) → hands over
  └─ kos-init (PID 1)
       asks for password again → unlocks the session AND boots the elevated
       administrator keyboard (same password, no second prompt) → starts your
       line shell. Starts nothing else. Ever.
  └─ you type, in any language:  run hello   /   abre hello   /   运行 hello
                                   write notes.txt hi   /   desktop
     (every line is a command - human language runs a KOS command, code runs sandboxed)
  └─ run hello                       → password → app opens as a text page
                run graphical hello  → password → app opens graphically
                   "Boot mouse?"     → y → password → mouse now sends commands to the app
                   "Boot keyboard?"  → y → password → keys now go to the app
```

| Idea | How it's built |
|---|---|
| Password on everything | `kos/auth.py`: scrypt-derived master key; every action (`app.run`, `device.mouse`, `file.view`, ...) needs the password typed for *that* action. All decisions go to an audit log (`kos audit`). |
| Apps are zip files that are never unzipped | `kos/kapp.py`, `kos/loader.py`: the zip is stored as-is, sealed with a password-derived key. At run time it's copied into a sealed in-RAM file (memfd) and run from there. A modified zip refuses to run. |
| Mouse/keyboard are "booted" | `kos/devices.py`, `kos/session.py`: apps never touch devices. The OS reads them and sends **commands** (`key`, `pointer`, `button`) to the app; the app answers with commands (`screen`, `frame`) that the OS checks and draws. Password prompts are an OS overlay the app can't see or cover. Ctrl-C always quits. |
| Everything goes through the security system | Apps run as `nobody` under Landlock + namespaces (`kos/sandbox.py`): no reading your files, no writing, no network unless you allow it with your password. If the kernel can't enforce this, apps don't start. |
| Multi-kernel in parallel | `kos/cells.py`: a *cell* is a separate Linux kernel (KVM micro-VM) pinned to its own CPU cores. `run hello --cell c1` runs the app inside it over the same command protocol. |
| Virus scanning | `kos/scan.py`: a static/heuristic scanner (EICAR + hand-written rules for reverse shells, obfuscated `eval`, credential-file reads, fork bombs, curl-pipe-shell, ...) that recurses into zips without extracting them. Every `install` and `update` is scanned *before* the password prompt; a flagged file is quarantined, never installed. `kos scan watch DIR` scans every file written under a directory - started with your password, like a cell, so it's bounded and visible, not a silent background daemon. |
| Apps need permission to run | `kos/permit.py`: a persistent grant, separate from the password - `kos permit NAME` decides an app is allowed to run *at all*, once. It never replaces the password: `run`/`open` still ask for it on every single launch regardless. |
| Per-app cache, wiped on exit | `kos/cache.py`: each run gets one private, writable scratch directory inside its sandbox (the sandbox previously allowed *no* writable directory at all). The moment that app's process ends - clean exit, `kos close`, anything - the directory is overwritten and deleted. |
| Every line is a command | `kos/lang.py`, `kos/coderun.py`: a line of human language (en/es/fr/de/pt/it/ru/zh/ja) becomes exactly one structured `kos` command - never a shell string. A line of **code is a command too**: *run this line* - but never on the host. It is scanned, needs your password, and runs as a one-shot app in the usual sandbox (no files, no network, time limit, nothing carries over to the next line). `kos do WORDS...` runs one line; `kos line` is the shell; login starts it instead of `/bin/sh`. |
| The OS is made of apps | `kos/desktop.py`, `kos/system.py`, `examples/system/`: the **taskbar** and the **App Library** are ordinary sandboxed apps. They never touch the screen or other apps - they *ask* the OS with a `request` command (needs the `system` permission in the manifest + a permit; opening/closing needs your password in the OS's own prompt). The **right mouse button is the App Library**, handled by the OS from any app. |
| Elevated administrator keyboard + **requires** | `kos/admin.py`, `kos/requires.py`: *requires* is a dependency, not an action. **Unlocking requires the elevated administrator keyboard, which requires the kernel**: the unlock password boots the keyboard (a lease signed with a password-derived key, bound to this boot) and if the kernel protections are missing the computer simply does not unlock. **Writing a file requires a security scan and a disk optimize afterwards**: the write is recorded on a ledger as owing both, they are done in order under the same password, and anything left owed (a crash, a failed step) survives restarts and blocks the next write until `kos settle`. |
| Disk optimization | `kos optimize` (`kos/optimize.py`): recompresses installed apps to the smallest lossless size and re-seals them at the new bytes, prunes dead background-app records, trims the audit log - all under one password. |

## Commands

```
kos setup                  choose your password
kos install app.kapp       install (kept zipped, sealed)
kos update app.kapp        update to a NEWER version (downgrades refused)
kos remove NAME / kos list
run [graphical|cmd] NAME   run in the foreground: text page, graphical, or raw command stream
kos open [graphical|cmd] NAME   open in the background, return immediately
kos ps                     apps opened with 'kos open'
kos attach ID               connect your terminal to one (Ctrl-C detaches, doesn't kill it)
kos close ID                actually stop one
kos desktop install         pack, scan, install + permit every interface app (one password)
kos boot desktop            the desktop: a compositor over separate apps (--classic: the older one-app-at-a-time mode)
kos desktop shot OUT.png    boot it headless and save a picture (--size WxH --open a,b --search TEXT)
kos ls PATH / kos cat PATH  browse/view real dirs and zips, never extracted
kos explore [PATH]          interactively cd/ls/cat, straight into zip files
kos activity                one feed: what's open + recent password decisions
kos view FILE               view a file (password first)
kos permit NAME             give an app permission to run (password still needed every run)
kos scan file PATH          scan a file/zip right now (no password needed)
kos scan watch DIR...       scan every file written here until Ctrl-C (password to start)
kos update all --from DIR   update every installed app that's newer in DIR, all scanned first
kos optimize                 recompress apps, prune dead state, reclaim disk space
kos admin [status|boot|lock] the elevated administrator keyboard (boots at login)
kos write PATH --text T      write a file (needs the admin keyboard); owes a scan + optimize afterwards
kos owed / kos settle        what earlier writes still owe / do it now
kos backup [PATH]            back a file/folder up (no PATH lists backups); scanned when made
kos restore BACKUP MEMBER DEST   put one file back (guarded write)
kos offsite remote [URL]     YOUR private GitHub repository for backups (github.com only)
kos offsite push BACKUP      push a backup there (refused if the repo is publicly readable)
kos exec --code LINE         run one line of code as a sandboxed command
kos do WORDS...              one line of human language, run as one command
kos line [--explain]         the line shell: every line you type is a command
kos cell start NAME --kernel K --initrd I --cpus 2,3
kos doctor                  which kernel protections this machine has
kos audit                   every password decision
```

Three ways to run an app: `run NAME` (a text page), `run graphical NAME`
(pixels), `run cmd NAME` (no drawing at all - the raw stream of commands the
OS is sending the app and the app is sending back, for scripting or for
seeing exactly what crosses the wire).

Several apps can be open at once: `kos open` launches one in the background
and hands your shell straight back. `kos ps` lists what's open, `kos attach
ID` connects your terminal/mouse/keyboard to one of them (each device still
needs booting with the password for that terminal), and Ctrl-C detaches
without killing it - only `kos close` does that. There's no multi-app
desktop view unless you ask for one with `kos boot desktop`.

`kos ls`/`kos cat`/`kos explore` treat real directories and zip files
(including `.kapp` apps) as one continuous tree - `cd`-ing into a zip is
just another `cd`, and nothing is ever extracted to disk to look at it.

Included apps: `examples/hello` (text + graphical + cmd-mode demo) and
`examples/web` — a no-graphics browser: type a URL, the page appears as a
folder of links you click through, type `run` to view the page text. Every
page it fetches is scanned before you see it; the status line says so.

Everything that enters the system is scanned before it's trusted: `install`
and `update` refuse and quarantine a flagged `.kapp`, without ever asking
for your password on it, and `kos scan watch DIR` extends that to any
directory you point it at. Installing an app doesn't grant it permission to
run - `kos permit NAME` does that separately, once; the password is still
asked on every single launch regardless. Each run gets a private, writable
cache directory that is securely wiped the moment that process ends, so
nothing an app writes outlives it. `kos optimize` reclaims disk space:
recompressing installed apps (re-sealed at the new bytes), dropping old
quarantine files and dead background-app records, and trimming the audit
log.

## Every line is a command

```
kos> run hello                  kos> abre hello                kos> 运行 hello
kos> please scan notes.kapp     kos> lance l'app hello         kos> write notes.txt "hi there."
kos> print(6 * 7)               -> asks your password, runs in a sandbox, prints 42
kos> run hello; rm -rf /        -> a command too: shell code, but there is no sandboxed
                                   shell runtime, so nothing runs (and it never touches the host)
```

Human language: the words are only *names for existing commands*; each one
still asks for the password exactly as `kos ...` does. The first meaningful
word is looked up in the lexicon (politeness words and articles skipped,
case/accents ignored, CJK matched by prefix); otherwise "I don't know that
command" with a did-you-mean. Shell command names (`ls`, `cat`, `kill`) are
not words in the lexicon - they are code.

Code: detected by syntax, scanned, then run as a one-shot sandboxed app with a
password and a 10 s limit. Only Python has a sandboxed runtime here; any
other language is still a command - understood, scanned, logged - and says
it has no runtime. `kos line --explain` shows how each line was understood.
Honest limits: it is a verb lexicon, not language understanding; the verb comes
first; each code line is its own app, so variables do not persist.

## The desktop is made of apps

```
kos desktop install       # once: packs, scans, installs and permits every interface app (one password)
kos boot desktop          # or just say: desktop        (kos boot desktop --classic = the older mode)
kos desktop shot out.png  # no screen needed: boot it headless and save what it looks like
```

The interface is not one program. The OS runs a small **compositor** (`kos/shell.py`) and every part of what you
see is a *separate sandboxed app* that only draws flat shapes and text:

| Interface app | Role |
|---|---|
| `wallpaper` | the background (sky and layered waves, drawn from code - there are no image files) |
| `menubar` | the **top panel**: KOS menu, the active app's name and the commands it offers (click one to run it), CPU/memory, network, date and clock |
| `dock` | the **floating dock**, centered at the bottom: pinned apps, then whatever else is running; a dot marks open apps (Windows Blue when active) |
| `icons` | every installed app as an icon; click to open |
| `search` | type anywhere: finds apps **and the commands they offer**; any other line is a command too - `print(1)` runs sandboxed and prints 1 |
| `widgets` + `widget-clock/calendar/network/system` | the widget handler (show/hide/reorder, remembered) and the widgets |

Apps never touch the screen. The OS adds the glass (blur, tint, sheen, bevel, soft shadow, rounded corners) around
their shapes, draws the window frames itself, and asks for your password in its own overlay that no app can see or
cover. Opening anything is a *request*; the right mouse button shows the desktop.

**Look:** a minimalist top panel and a floating bottom dock (macOS-style), Windows Blue **`#0078D4`** for active and
selected states, neutral dark glass instead of navy, and smooth proportional type. Smooth type is the OS's own
pure-Python TrueType rasterizer (`kos/ttf.py`, exact-coverage anti-aliasing) using a system font; apps send
`["stext", x, y, text, color, px, face]` and the OS draws it, so apps never need a font file. Not yet converted:
the app windows' *content* is still the older text-mode pages (now drawn in a smooth monospace font), and a few
widget details still use the pixel font.

**Real desktop on your own machine:** `native-desktop/` is a separate kit that gives a normal Linux X11 session
the same layout - polybar (top panel), plank (floating dock), picom (blur, rounded corners), rofi, Papirus icons,
Inter font - all in `#0078D4`, with `install.sh` and `kos-desktop apply|preview|reload|revert`. It runs natively on
your session (no nested desktop), changes only files in your home, and `revert` restores your originals exactly. See
`native-desktop/README.md`; it could not be looked at in the environment it was written in, so use `preview` first.

## "Requires"

`kos/requires.py` is one small table, and it is the whole policy:

```
session.unlock  requires (before)  admin.keyboard
admin.keyboard  requires (before)  kernel
file.write      requires (before)  admin.keyboard
                requires (after)   scan, optimize
backup.create   requires (after)   scan
```

*Before* is a chain followed deepest-first: login asks for the password once,
checks the kernel, boots the administrator keyboard with that same password,
and only then unlocks. If a link fails, nothing above it happens and the
refusal names the chain: `session.unlock requires admin.keyboard requires
kernel: Landlock (kernel sandbox) is not available`.

*After* is an obligation. `kos write notes.txt --text hi`:
1. needs the keyboard booted this boot, the kernel present, and the password typed on it;
2. writes the file and records on the ledger that it owes `scan` and `optimize`;
3. scans what is on disk (flagged → moved to quarantine, exit 3), then optimizes the disk, under the same password;
4. strikes each off as it is done. Whatever is still owed survives a crash and blocks the next write: `kos owed`, then `kos settle`.

Honest limits: the lease is a signed record, not a separate privileged
process - a program running as you can read it but not forge it, and it still
needs the password to write through KOS; it does not stop a program running as
you from calling `open()` itself (that is what the app sandbox is for). Exclusive
keyboard capture needs real evdev hardware and has **not been run on hardware
here**; over a plain terminal set `KOS_DEV_ADMIN_WEAK=1` (the lease is then
marked WEAK and the keyboard is not exclusive).

## Apps run through npm

Every app is started the same way: **`npm run start`** (or `npx --no-install TOOL`).
A `.kapp` with `"runtime": "npm"` ships a `package.json`; the manifest's `entry` is
the script name (default `start`). The zip is verified against its seal exactly as
before, then **unpacked into RAM only** (`/dev/shm`, never the disk), read-only to the
app with a separate scratch folder, and run inside the same sandbox (unprivileged
user, no network unless allowed, Landlock) - offline, nothing is ever installed at
run time. All of it is wiped when the app ends. Apps can be written in JavaScript
(`sdk/js`: `const { App, Canvas } = require(process.env.KOS_SDK_JS)`) or anything
npm can launch - the Python apps in `examples/` start through npm too. Limits:
npm needs Node.js on the machine; **cells (VMs) run Python/native apps only**.

## The built-in apps

Everything on the desktop is an app: sandboxed, no screen/file/network access of
its own, only *requests* to the OS (which needs the `system` permission and, for
anything that changes something, your password in the OS's own prompt).
`kos desktop install` installs and permits all of them.

| App | What it does |
|---|---|
| `taskbar` | Home screen of the classic (`--classic`) mode: what is open, switch to it. |
| `app-library` | Every installed app; Enter opens one (password). Right mouse = this. |
| `files` | **File viewer**: browse folders and zips (never extracted); Enter on a file views it (password); `s` scans it. |
| `editor` | **File editor**: opens a file (password), edit, Ctrl-S saves through the *guarded write* (admin keyboard, password, then a scan + optimize are owed). A file that would not round-trip exactly (tabs, CRLF, very long lines, binary, too big) opens **read-only**. |
| `backup` | **Backups of your documents**: back up a file/folder into a zip that only KOS writes and scans; browse a backup without extracting; restore one file (guarded write); push to *your own* private GitHub. |
| `settings` | Kernel protections; which apps are permitted to run (Enter toggles, password). |
| `updates` | **Where everything comes from** (every app's source, KOS's git origin and commit, Python/Node/npm/kernel and who updates them) and **installing newer versions** from sources you add - see below. |
| `processes` | Process manager: every task, state, scheduling (nice, priority, context switches), pause/continue/terminate, lower priority, and the IPC channels. |
| `memory` | Memory manager: RAM, cache, swap, paging, pressure, available-over-time history, biggest users. |
| `filesystem` | File systems & permissions: mounts and capacity, who may read/write/run what (explained), make folder / trash / rename / chmod. |
| `devices` | I/O: disks and throughput, input devices, drivers, display, buffers and cache. |
| `network` | Interfaces and rates, protocol counters, connections, local IPC sockets, internet check. |
| `isolation` | Protection: how each app is confined, kernel hardening verdicts, authentication and access levels. |
| `health` | Error handling: sensors, link/disk errors, apps that crashed, security events; stop a faulty app. |
| `resources` | Accounting: CPU/memory/disk, per-app consumption, priority tuning. |
| `security` | Administrator keyboard status, what is owed, scans, recent decisions; settle / optimize. |
| `terminal` | The line shell as an app: plain language *and* code lines (sandboxed). |

### Sources and updates

`kos provenance` / the Updates app list, for every app: the source, exact location,
version, hash and date it was installed or updated from; for KOS itself its git remote
and commit; and the Python, Node.js, npm, kernel and OS underneath with who updates each.

A **source** is a place you chose: a `folder` of `.kapp` files, an `https` site serving
`kapps.json` (`{"apps":[{"name","version","file","sha256"}]}`) beside them, or a `github`
OWNER/REPO whose latest release has the same. `kos sources add NAME KIND LOCATION`,
`kos updates check`, `kos updates install NAME|all`, `kos updates core`. Nothing is
automatic: *checking* contacts your sources (password); *installing* needs the download
to match the advertised sha256, then runs the normal `kos update` path (scanned -
a flagged file is quarantined - no downgrades, sealed with your password), and an update
that asks for **more permissions than the version you have is held back** until you
approve it. KOS itself, when it runs from a git checkout, is fast-forwarded from its own
remote (refused if modified or diverged); Python, Node and the kernel are reported but left
to your operating system. Plain `http` is refused (loopback only in tests).

### Backups and your own GitHub

Whoever uses the OS pushes **their own** backups to **their own** GitHub account:
`kos offsite remote https://github.com/YOU/REPO` (or `g` in the Backup app) stores
*their* repository on *their* machine; nothing about any particular account is in
the code. Pushing uses your normal git credentials (credential helper / ssh agent) -
KOS never sees or stores a token. Guards: only `github.com` repositories are
accepted (git's exotic transports can't be reached); **before every push** the
repository is probed anonymously and the push is **refused if it is publicly
readable**; every push needs your password. Limits: the backup is not
encrypted - "private" is GitHub's access control, not cryptography - and the probe
can't tell a private repository from one that doesn't exist (the push then fails).

## Try it on any Linux machine

```
export KOS_ROOT=~/.kos-dev PATH=$PWD/bin:$PATH
kos setup
kos pack examples/hello -o hello.kapp && kos install hello.kapp
run hello
run graphical hello        # draws in the terminal with 24-bit color
python3 -m unittest discover -s tests -v
```

## Building a bootable image

`kernel/kos.config` (hardening config fragment), `boot/mkinitramfs.sh`,
`image/mkimage.sh` (UEFI + LUKS2 disk image), `image/run-qemu.sh`.

## Status (honest)

* **Tested here:** password/grants/audit, app sealing and tamper detection,
  running from the zip in RAM, the sandbox (verified: app can't read
  `/etc/passwd`, write files, use the network or signal PID 1), the command
  protocol, device booting flow, rendering, update/downgrade, the cell agent,
  the `open`/`ps`/`attach`/`close` background lifecycle (including a real
  fork+daemonize broker, over a real pty), `cmd` mode, zip `cd`/browsing,
  the scanner (EICAR + heuristics, recursing into zips), install/update
  quarantine, the inotify watcher, permits, per-run cache wipe-on-exit
  (verified over a real pty: gone after a clean exit), and `kos optimize`'s
  recompress-and-reseal.
* **Also tested here (this round):** the line shell (many languages, code
  refusal incl. shell glue, `kos do`/`kos line`); the admin keyboard (login
  grant boots it with one prompt, kernel gating, expiry, other-boot, forged
  lease, weak mode) and the guarded write (scan → optimize → write order,
  flagged data never written, one password for the whole pipeline); the
  `request` protocol and system bridge (permit, password, wrong password,
  focus); real sandboxed taskbar/App Library sessions (right mouse is the
  OS's, devices carry over, the library opens an app with a password typed in
  the OS prompt through a real broker); and the real CLI end to end through a
  pseudo-terminal (`desktop install`, `admin boot`, `write`, EICAR blocked,
  `boot desktop` with switching, right-click, launching from the library).
* **Verified here as pictures and tests, not on a real screen:** the compositor desktop (headless screenshots,
  geometry/permission tests); the typeface (checked against FreeType: straight glyphs within ~5%, curves 15-25%
  mostly hinting); `native-desktop/` (parse, dry-run, apply/revert in a throwaway home - not run against a live X server).
* **Written but not yet booted:** exclusive evdev capture for the admin
  keyboard, the compositor on a real framebuffer (`kos boot desktop` on a VT), the initramfs, kos-init as real PID 1, the
  image builder, framebuffer/evdev on real hardware, starting KVM cells (no
  KVM in the dev container).
* The userland is Python (stdlib only) to move fast. Python can't fully wipe
  secrets from memory; the security core should be ported to Rust.

See `docs/ARCHITECTURE.md` for the threat model and `docs/IDEAS.md` for the
running backlog of what's next.
