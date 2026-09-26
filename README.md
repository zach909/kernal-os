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
       asks for password again → starts your shell. Starts nothing else. Ever.
  └─ you type:  run hello            → password → app opens as a text page
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
kos boot desktop            choose among open apps - no desktop otherwise
kos ls PATH / kos cat PATH  browse/view real dirs and zips, never extracted
kos explore [PATH]          interactively cd/ls/cat, straight into zip files
kos activity                one feed: what's open + recent password decisions
kos view FILE               view a file (password first)
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
folder of links you click through, type `run` to view the page text.

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
  fork+daemonize broker, over a real pty), `cmd` mode, and zip `cd`/browsing.
* **Written but not yet booted:** the initramfs, kos-init as real PID 1, the
  image builder, framebuffer/evdev on real hardware, starting KVM cells (no
  KVM in the dev container).
* The userland is Python (stdlib only) to move fast. Python can't fully wipe
  secrets from memory; the security core should be ported to Rust.

See `docs/ARCHITECTURE.md` for the threat model and `docs/IDEAS.md` for the
running backlog of what's next.
