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
     (every line is a command; lines of code are refused, never run)
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
| Every line is a command | `kos/lang.py`: a line of human language (en/es/fr/de/pt/it/ru/zh/ja) becomes exactly one structured `kos` command - never a shell string. A line written in a programming language, or carrying shell glue (`;` `\|` `&&` `$(...)` redirects), is refused as code and never run. `kos do WORDS...` runs one line; `kos line` is the shell; login starts it instead of `/bin/sh`. |
| The OS is made of apps | `kos/desktop.py`, `kos/system.py`, `examples/system/`: the **taskbar** and the **App Library** are ordinary sandboxed apps. They never touch the screen or other apps - they *ask* the OS with a `request` command (needs the `system` permission in the manifest + a permit; opening/closing needs your password in the OS's own prompt). The **right mouse button is the App Library**, handled by the OS from any app. |
| Elevated administrator keyboard | `kos/admin.py`: the password you type to unlock boots it - a lease signed with a password-derived key, bound to this boot, **refused unless the KOS kernel protections are present** (re-checked on every use). `kos write` needs it: the password is typed *on that keyboard* (exclusive `EVIOCGRAB`), the data must pass the **security scan**, and the disk is **optimized** first - in that order, or nothing is written. |
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
kos desktop install         pack, scan, install + permit the taskbar and App Library
kos boot desktop            the desktop: taskbar + App Library apps (--graphical for pixels)
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
kos write PATH --text T      write a file: admin keyboard + password on it + scan + optimize
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
kos> x = 5                      -> refused: that looks like code (assignment)
kos> run hello; rm -rf /        -> refused: that looks like code (shell) - nothing runs
```

The words are only *names for existing commands*; each one still asks for the
password exactly as `kos ...` does. Resolution: empty → code? (refused) →
first meaningful word is a verb in the lexicon (politeness words and
articles skipped, case/accents ignored, CJK matched by prefix) → otherwise
"I don't know that command" with a did-you-mean. `kos line --explain` shows how
each line was understood. Limits, honestly: this is a verb lexicon, not
language understanding; the verb comes first; code detection is heuristic
(it errs toward refusing); and an unknown language is simply "unknown".

## The desktop is made of apps

```
kos desktop install       # once: packs, scans, installs and permits the two apps
kos boot desktop          # or just say: desktop
```

There is no window manager. `boot desktop` opens the **taskbar** (home) and
the **App Library** as background apps and moves your terminal between running
apps: taskbar → pick an app → attach; **right mouse anywhere → App Library**;
Ctrl-C returns to the taskbar; Ctrl-C on the taskbar leaves (nothing is closed).
Mouse and keyboard are booted once, with your password, and carry over as you
move. Opening a new app from the library asks for your password in the OS's own
prompt, which no app can see or cover. Any app can be part of this: give it
`"permissions": ["system"]`, `kos permit` it, and it can list, open, close and
switch apps - but only by asking, and only with your password for anything that
starts or stops something. Starting the desktop asks for the password five
times (desktop, taskbar, library, mouse, keyboard); after that, switching is free.

## The administrator keyboard and guarded writes

```
login password ──► session.login ──► boots the administrator keyboard (no 2nd prompt)
kos write notes.txt --text hi
   1. lease booted this boot, unexpired, correctly signed, kernel protections present
   2. password typed ON the exclusively-grabbed keyboard
   3. security scan of the data           (flagged → nothing written, exit 3)
   4. disk optimize                       (under the same password)
   5. atomic write, mode 0600             (KOS's own state is never writable this way)
```

Honest limits: the lease is a signed record, not a separate privileged
process - a program running as you can read it but not forge it, and it still
needs the password to write through KOS; it does not stop a program running as
you from calling `open()` itself (that is what the app sandbox is for). Exclusive
keyboard capture needs real evdev hardware and has **not been run on hardware
here**; over a plain terminal set `KOS_DEV_ADMIN_WEAK=1` (the lease is then
marked WEAK and the keyboard is not exclusive).

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
* **Written but not yet booted:** exclusive evdev capture for the admin
  keyboard, the graphical desktop (`boot desktop --graphical`), the initramfs, kos-init as real PID 1, the
  image builder, framebuffer/evdev on real hardware, starting KVM cells (no
  KVM in the dev container).
* The userland is Python (stdlib only) to move fast. Python can't fully wipe
  secrets from memory; the security core should be ported to Rust.

See `docs/ARCHITECTURE.md` for the threat model and `docs/IDEAS.md` for the
running backlog of what's next.
