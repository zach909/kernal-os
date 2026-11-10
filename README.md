# kernal-os (KOS) - a password-first, security-focused Linux operating system

**KOS** (also searched as *kernal os* / *kernel os*) is an open-source,
security-first operating system built on its own patched Linux kernel (`kernel/`), written in Python.
It has no background services, no cached logins and no autostart: every
action needs your password. Apps are sealed zip files run in a Landlock +
namespace sandbox, and it adds a built-in malware scanner, parallel
micro-VM kernels, and a command line that understands nine human languages.

**Keywords:** secure Linux OS, hardened Linux distribution, password-protected
operating system, Landlock sandbox, LUKS2 encrypted boot, KVM micro-VM,
sandboxed apps, malware scanner, multilingual command shell, Python OS.

## Rules

These four rules govern every change to KOS. A change that breaks one is wrong.

1. **Everything needs verification.**
   - In the OS: every action goes through `Authority.authorize(action, target)`
     and needs the password typed for *that* action. A new command or feature
     must add its action to `ACTIONS` in `kos/auth.py` and call `authorize`
     before it does anything. A second kind of verification (a `requires`
     dependency, a security scan, a signed seal) adds to the password; it never
     replaces it.
   - In the work: nothing is called done until it has been run and checked.
     Tests pass, or the failure is reported as it is.
2. **Everything is an app.** Features ship as sandboxed `.kapp`s that talk to
   the OS only through the command protocol (`request` for system functions,
   `service` for the OS's own information and actions - `kos/servicespec.py` is
   the whole list - each with the manifest permission it needs and the password
   typed in the OS's own prompt). What is not an app is the kernel: the patched
   Linux in `kernel/` that enforces what apps may connect to, open and trace, and
   a small Python core (password, seals, the sandbox launch, the protocol, input and
   display) that is still to be moved down into it - see the gaps table for what is
   done and what is not. The taskbar, the App Library and the OS's own apps
   (audit log, firewall, files, ...) are the model.
3. **Every connection is blocked by default.** Any connection between anything
   (app to internet, app to app, app to cell, the OS to the internet, inbound
   listeners, any protocol, any port) is denied until a firewall rule allows it.
   - Websites are blocked too. A site installed as an app follows the same
     rules as any other app.
   - The firewall is an app. It holds no power of its own: it asks the OS, and
     every change needs the password. Enforcement stays in the OS, so the
     firewall app being broken or hostile leaves the default at deny.
   - A rule names one app, one host, one port and one protocol. No wildcards
     unless typed out.
   - Using a privilege asks at the moment of use, after the password that ran
     the app, in the OS's own prompt. Grants last until the app exits unless
     you explicitly make one permanent (which costs a password).
   - Every connection is encrypted and verifiable. Plain-text connections
     (`http://`, FTP, anything unencrypted) are refused, never silently
     upgraded. The peer's certificate and host name must verify, with no
     "continue anyway" and no switch to turn it off. A redirect may not move
     from encrypted to plain.
   - The browser tells you on every page that websites can see your IP address.
   - Every allowed and every blocked attempt goes in the audit log.

4. **The whole pipeline is encrypted.** What you see, what you click, the
   commands between the app and the OS, and the OS's calls down to the kernel
   and hardware: screen <- `frame`/`screen` <- app <- `key`/`pointer`/`button`
   <- OS <- kernel <- hardware. Apps never touch the kernel or hardware; only
   the OS does. Every channel between separate parties is encrypted and
   authenticated.

Agent skills for AI agents working on this repo live in `.claude/skills/`:
`kos-rules` (these rules as a checklist) and one per layer of the pipeline -
`kos-graphics`, `kos-input`, `kos-command-protocol`, `kos-kernel`,
`kos-hardware`.

### Where the code does not meet the rules yet

Honest list, so nobody assumes these are covered:

| Rule | Gap |
|---|---|
| Verification | Still run with no password: `list`, `ps`, `dirs`, `pack`, `help`. `attach` asks for no new password, and `setup` cannot (no password exists yet). What used to show private state without one - `audit`, `activity`, `security`, `doctor`, `firmware`, `owed`, `ls`, `scan file`, `cell list`, `spaces` - is an app now, and asks for the password in the OS's own prompt every time it reads (actions `audit.read`, `activity.read`, `security.check`, `system.read`, `file.view`, `cell.list`, `space.list`). Not tested on real hardware: the OS's prompt on a framebuffer. |
| Connections blocked | **On the KOS kernel,** every connection of every confined app is denied (connect, bind, listen, send to an address) unless the owner added a rule: one app, protocol, direction, IP address and port, typed out, no wildcards. Every allowed and every blocked attempt is logged and copied into the audit log. **Not covered:** (1) a stock kernel enforces nothing - a boot with `kos.require_kernel=1` on the signed command line (the shipped `kernel/cmdline.txt` sets it) refuses to start, and refuses to run any app, without the KOS kernel; (2) only confined apps are covered - connections made by the OS itself, by anything outside the sandbox, and from inside a kernel cell (its guest kernel does not have the module) are not blocked or logged; (3) rules are IP addresses, never names (resolving a name is itself a connection), and a change reaches an app the next time it is opened; (4) the kernel cannot tell encrypted from plain traffic: an allowed address and port can carry anything, and encryption and certificate checks are still enforced only inside the `web` example (`check_url`, `fetch`); (5) the `network` yes/no and the rules are decided when the app is launched, not at first use; (6) the kernel keeps the newest 256 log lines until the core copies them into the audit log (when an app ends, or when the firewall app reads); a burst in between overwrites the oldest and the loss is counted and written. |
| Pipeline encrypted | Nothing is encrypted. The command channel is plain JSON lines over a socket (`Channel` in `kos/protocol.py`). The real exposure is the broker socket (`kos open`/`attach`: any process running as you can connect) and cell vsock. The kernel module's rule and log files (`/sys/kernel/security/kos/`) are local files only the core can open; they are not encrypted either. Encrypting needs a vetted library; the standard library has no authenticated encryption and KOS has no third-party dependencies yet. |
| The KOS kernel | Linux 6.12.116 with `kernel/patches/0001-kos-lsm.patch` (`security/kos`), built by `kernel/build.sh`, which refuses a source tree whose SHA-256 is not the pinned one and fails if any option in `kernel/kos.config` is missing from the final config. **Tested:** `kernel/test/run.sh` boots it in QEMU with a test program as PID 1 - 96 checks that a confined app is refused (sockets, device nodes, ptrace, rule changes) and that the same call works once the core allows it - on a minimal build and on the full hardened build. **Not tested:** real hardware, KVM, any CPU but x86_64, and stacking with SELinux or AppArmor (neither is configured). The module is out of tree and uses LSM id 114, which is not registered upstream; a new Linux version needs the patch rebased. |
| Everything is an app | **Done:** 18 commands are apps - `audit`, `activity`, `security`, `doctor`, `firmware`, `ls`/`cat`/`explore`/`view`, `scan file`, `optimize`/`settle`/`owed`, `cell`, `convert`, `skills`, `grant`/`spaces`. The command line only opens the app (`kos/launchmap.py` lists which); the app asks the OS through the service layer. **Not done:** (1) the OS still has a Python core: the password check, seals and the app loader, command validation and the session loop, the audit chain, drawing and input, `init`. Phase 1 moved only the enforcement of apps' network, device and ptrace access into the kernel; moving more is not started. (2) Kept in the command line because a new machine needs them before any app exists: `setup`, `install`, `update`, `remove`, `permit`, `list`, `help`, `line` (apps with the same jobs exist: Software Updates, Terminal, KOS Help). (3) The OS's own machinery: `run`, `open`, `go`, `ps`, `attach`, `close`, `boot`, `desktop`, `extend`, `dirs`, `admin`, `write`, `usb`, `aios`, `do`, `exec`, `backup`, `pack`, `passwd`. (4) Limits of the converted ones: Files cannot write (a write needs the exclusive administrator keyboard: `kos write`); Skill Maker previews, and `kos skills --out DIR` (which writes the files through the guarded write) stays a command; the Debian Converter still parses the package in the OS, not in the app, and writes its output with a plain create; `scan watch` stays a command because it is a watcher; the Terminal app opens other apps but shows none of their output. |
| Search box | The Ctrl-N box and the App Library's `/` search (`kos/office/finder.py`) only *show*: a command hit is the line to type, never a run, and an app hit is a `request` the OS still asks your password for. File search covers only what the app can already read (its own vault plus the shared folders it was granted), at most 200 items and 20,000 characters each per place, and never keys that look like credentials (`llm`, `api_key`, `token`, `password`, ...), the agent's chat history or exports. That filter is a **name pattern, not a classifier**: a secret stored under an ordinary key name (say `note-7`) would be searchable by that same app. The App Library has no files of its own, so it searches apps and commands only, and its "Ask the assistant" row opens the `ai-assistant` app but cannot hand it your question. The command list is a generated table (`python3 -m kos.office.cmdindex --write`); a test fails if it drifts from `kos help`. Not tested: the graphical-mode drawing of the Ctrl-N box. |

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
| Debian conversion | `kos/debconv.py`, `kos/debshim.py`, the Debian Converter app (`kos convert`): a `.deb` becomes a `.kapp`. The package is read in memory only (never unpacked to disk), bounded and path-checked, and the result is scanned; a flagged or unconvertible package is refused **before** any password prompt. The password (`app.convert`) is needed to write the file, and `kos install` then scans again, asks again and seals. **Maintainer scripts are never run and never kept.** Only **statically linked** programs convert (dynamic ones are refused with the package's `Depends` shown); symlinks and devices are dropped; setuid bits are stripped; the app gets **no permissions**. A small shim runs the program from a sealed in-RAM file with no stdin, a 10 s limit and a 64 KiB output cap, and shows its output as a text page. |
| Skill maker | `kos/skillmaker.py`, the Skill Maker app (`kos skills`; `kos skills --out DIR` writes the files and stays a command): one skill for the commands (read from the real parser) and one per installed app. One password (`skill.make`) verifies every app's seal first; a tampered app is skipped. Each file is scanned, and a flagged app skill is left out. An app's free-text description never reaches the instructions - it sits in one inert, labelled data block. Printing writes nothing; `--out DIR` writes each file through the guarded `file.write` path. |
| Password on everything | `kos/auth.py`: scrypt-derived master key; every action (`app.run`, `device.mouse`, `file.view`, ...) needs the password typed for *that* action. All decisions go to an audit log (`kos audit`). |
| Password on everything | `kos/auth.py`: scrypt-derived master key; every action (`app.run`, `device.mouse`, `file.view`, ...) needs the password typed for *that* action. All decisions go to a tamper-evident audit log: hash-chained, with every grant anchored to your password (`kos audit`, `kos audit --verify`). |
| Apps are zip files that are never unzipped | `kos/kapp.py`, `kos/loader.py`: the zip is stored as-is, sealed with a password-derived key. At run time it's copied into a sealed in-RAM file (memfd) and run from there. A modified zip refuses to run. |
| Mouse/keyboard are "booted" | `kos/devices.py`, `kos/session.py`: apps never touch devices. The OS reads them and sends **commands** (`key`, `pointer`, `button`) to the app; the app answers with commands (`screen`, `frame`) that the OS checks and draws. Password prompts are an OS overlay the app can't see or cover. Ctrl-C always quits. |
| Everything goes through the security system | Apps run as `nobody` under Landlock + namespaces + a seccomp denylist (`kos/sandbox.py`): no reading your files, no writing, no network unless you allow it with your password, no `bpf`/`io_uring`/`perf`/keyring syscalls, 1 GiB of memory and 64 MiB per file at most. If the kernel can't enforce Landlock, apps don't start. The seccomp filter is x86_64 only (`kos doctor` says so). |
| Multi-kernel in parallel | `kos/cells.py`: a *cell* is a separate Linux kernel (KVM micro-VM) pinned to its own CPU cores. `run hello --cell c1` runs the app inside it over the same command protocol. |
| Virus scanning | `kos/scan.py`: a static/heuristic scanner (EICAR + hand-written rules for reverse shells, obfuscated `eval`, credential-file reads, fork bombs, curl-pipe-shell, ...) that recurses into zips without extracting them. Every `install` and `update` is scanned *before* the password prompt; a flagged file is quarantined, never installed. `kos scan watch DIR` scans every file written under a directory - started with your password, like a cell, so it's bounded and visible, not a silent background daemon. |
| Apps need permission to run | `kos/permit.py`: a persistent grant, separate from the password - `kos permit NAME` decides an app is allowed to run *at all*, once. It never replaces the password: `run`/`open` still ask for it on every single launch regardless. |
| The KOS kernel and the firewall | `kernel/`, `kos/kernel.py`, `kos/firewall.py`, the Firewall Management app. The kernel module (`security/kos`) is where connection rules are enforced: PID 1 claims the **core** once per boot (`prctl`), the core confines each app with a never-reused id before the app runs any code (one way, inherited by every child and across `exec`), and from then on the kernel denies that app every connect, bind, listen and send to an address, every device node but `null/zero/full/random/urandom`, and `ptrace`, `bpf`, `perf_event_open` - unless the core wrote a rule for exactly that app, protocol, direction, IP address and port. The owner's rules live in `<state>/firewall/rules.json` sealed with an HMAC under a key derived from the password (a file that fails its seal gives the app no rules); at launch the core writes an app's rules to the kernel *before* the fork (only if the owner said yes to the network for that launch), and at exit takes them back and copies the kernel's log of allowed and blocked attempts into the audit log (`kos audit`: `net.connect ... allowed/blocked`). A boot with `kos.require_kernel=1` (the shipped command line) refuses to run apps on a kernel without the module. |
| Services: how an app asks the OS | `kos/servicespec.py` (the whole list: 28 services in 13 groups, one schema each), `kos/services.py`. An app whose manifest says `"service:audit"` can send `{"cmd":"service","id":N,"name":"audit.tail","args":{...}}`. The OS checks the name and every argument against the schema (an unknown key, a bool for an int, a path with a control character: refused), checks the manifest asked for that group, asks for the password **in its own prompt, now, for this call**, runs the handler, scrubs every string in the answer of control and bidi characters and bounds its size. A handler that crashes returns a generic error, never a traceback. An extension or a mod can never hold a `service:` permission. |
| The OS's own apps | `kos/office/pack_system.py`, `pack_os.py`, `kos/sysapps.py`, `kos/launchmap.py`: Audit Log, Security Check, Files, Scanner, Kernel Cells, Shared Folders, Debian Converter, Skill Maker, Terminal, Firewall Management, System Information and Diagnostics, Storage and Disk Management, Process and Resource Monitor, Software Updates. Each is a sandboxed `.kapp` that formats what the OS tells it. `kos desktop install` installs them together under one password (`app.install.all`): every file is scanned first and one flagged file stops the lot before any prompt. |
| Per-app cache, wiped on exit | `kos/cache.py`: each run gets one private, writable scratch directory inside its sandbox (the sandbox previously allowed *no* writable directory at all). The moment that app's process ends - clean exit, `kos close`, anything - the directory is overwritten and deleted. |
| Every line is a command | `kos/lang.py`, `kos/coderun.py`: a line of human language (en/es/fr/de/pt/it/ru/zh/ja) becomes exactly one structured `kos` command - never a shell string. A line of **code is a command too**: *run this line* - but never on the host. It is scanned, needs your password, and runs as a one-shot app in the usual sandbox (no files, no network, time limit, nothing carries over to the next line). `kos do WORDS...` runs one line; `kos line` is the shell; login starts it instead of `/bin/sh`. |
| The OS is made of apps | `kos/desktop.py`, `kos/system.py`, `examples/system/`: the **taskbar** and the **App Library** are ordinary sandboxed apps. They never touch the screen or other apps - they *ask* the OS with a `request` command (needs the `system` permission in the manifest + a permit; opening/closing needs your password in the OS's own prompt). The **right mouse button is the App Library**, handled by the OS from any app. |
| Elevated administrator keyboard + **requires** | `kos/admin.py`, `kos/requires.py`: *requires* is a dependency, not an action. **Unlocking requires the elevated administrator keyboard, which requires the kernel**: the unlock password boots the keyboard (a lease signed with a password-derived key, bound to this boot) and if the kernel protections are missing the computer simply does not unlock. **Writing a file requires a security scan and a disk optimize afterwards**: the write is recorded on a ledger as owing both, they are done in order under the same password, and anything left owed (a crash, a failed step) survives restarts and blocks the next write until `kos settle`. |
| Backups (the backup app) | `kos/backup.py`, `examples/backup`: **content-addressed, deduplicated** backups. A file body is stored once under its SHA-256 no matter how many names or times it is added; every file is **scanned before it is stored** (flagged files never enter the vault); `add`/`list`/`remove`/`restore` each need the password; the index is HMAC-sealed with a password-derived key and every body is re-hashed when read, so tampering is refused. **Restore is a write**, so it goes through the guarded write (admin keyboard, scan, optimize) and never overwrites. The `backup` app is a sandboxed front-end that can't read files itself - it *asks* the OS (`system` permission) and the password is typed in the OS's own prompt. |
| AI OS: KOS is the engine | `kos/aios.py`: four layers only - the graphical button clicker (`gui`), terminal app commands (`app`), kernel commands (`kernel`, NeuroClaw's Linux permission tools) and the auto skill maker (`skill`). KOS carries a request to the NeuroClaw engine on this computer and asks for no password; the engine's own tool gate and approvals decide what happens. Nothing else of NeuroClaw is reachable, nothing autostarts, and the engine address must be loopback. |
| Security check | the Security Check app (`kos security`, `kos/secure.py`): one read-only check that changes nothing and asks for the password (`security.check`) because what it reports is private, nothing running in the background. Kernel protections, private folders and secrets, audit-chain integrity, every installed app rescanned and compared with what was installed, permissions nothing uses any more or that were never pinned, owed work, crash leftovers. Exit code 3 if anything failed. |
| Firmware control (no ME, PSP or BMC in charge) | `kos/firmware.py`, `boot/initramfs/firmware.sh`: before the disk is unlocked, and again in `kos-init`, KOS looks for management processors that run below the OS - **Intel ME/AMT, AMD PSP, server BMCs (IPMI)**, and every other chip with its own firmware (Thunderbolt/USB4, USB-C port controller, embedded controller, network, GPU, NVMe, wireless), plus a missing IOMMU. If one is running it alerts, cuts the OS's side of it (unbinds the driver, forbids rebinding) and **refuses to boot**. Only an Intel ME whose own status register says *disabled* is believed off. `kos.firmware=warn` on the signed kernel command line boots anyway. **This cannot switch them off** - see the limits in `docs/ARCHITECTURE.md`; almost no real hardware will boot under the default policy (VMs will). There is no resident checker: it runs once at boot and at each unlock. An owner-written allow list (`boot/firmware.allow`, `/etc/kos/firmware.allow`) accepts chips whose firmware you replaced yourself; KOS never flashes anything. `kos firmware` also lists which protections (IOMMU, memory encryption, LUKS2, Thunderbolt security) narrow what the remaining chips can see. |
| Open apps like websites | `kos/address.py`: `kos go kos://web/example.com/news` opens the app `web` and tells it the path, the way a browser opens a site. `run` and `open` take addresses too; an app can ask for one with a `request`. Addresses are checked strictly (no other schemes, `..`, `%`, `#`, whitespace or control characters) and the path is *data for the app*, never a file name or a command. |
| Extensions and mods, still apps | `kos/extensions.py`: two kinds of app, both ordinary sealed, scanned, permitted `.kapp`s. An **extension** adds to an ordinary app, like a browser extension (bookmarks for `web`). A **mod** modifies a system app (pins and a new accent for the taskbar, a shelf for the App Library). They are *data*, not code injected into another app: the host's zip and seal are never touched, and the OS hands the host the validated entries after `hello`. Nothing happens until you switch one on with `kos extend NAME` (password; a mod is a separate `app.mod` action); the switch pins the exact build you approved, so an updated or tampered add-on stops contributing until you approve it again. |
| Every app action passes gui, app, kernel | `kos/layers.py`: opening, running, closing, switching to and extending an app all go through one door, `layers.traverse`, which sends the request through the **graphical button clicker** (is there a button for it?), then **app commands** (is it permitted?), then **kernel commands** (the password, the seal, the sandbox), in that order. A layer that says no stops the rest, so an unpermitted app is refused before any password is asked. Every layer's `pass` or `refused` is in `kos audit`. A test fails if any other code asks for the password to use an app. |
| Disk optimization | the Storage and Disk Management app (`kos optimize`, `kos/optimize.py`): recompresses installed apps to the smallest lossless size and re-seals them at the new bytes, prunes dead background-app records, trims the audit log - all under one password. |

## Build the KOS kernel

```
kernel/build.sh                 # Linux 6.12.116 + the KOS security module -> build/kernel/bzImage
kernel/test/run.sh              # boot it under QEMU (no KVM) and run the module's 96 checks
```

`docs/KERNEL.md` says what the module enforces, what it does not, and how to work on the patch. The
shipped command line (`kernel/cmdline.txt`) sets `kos.require_kernel=1`: an image built with any other
kernel starts, says why, and runs no apps.

## Install as a Debian package

The whole repository builds into one `.deb`, from the last commit (so a version
always means the same bytes; building twice gives identical files):

```
python3 packaging/build_deb.py          # -> dist/kernal-os_VERSION_all.deb
sudo dpkg -i dist/kernal-os_*.deb       # installs files only
kos setup                               # choose your password
```

It installs the tree under `/usr/lib/kernal-os/` with `kos` and `kos-run` in
`/usr/bin`. It has **no maintainer scripts**, starts no service, touches
nothing in `/etc` and creates no state, which is KOS's own rule applied to its
package. Needs `python3 (>= 3.11)`; the full test suite was run from an
extracted copy on 3.11, 3.12 and 3.13. Not done yet: a license (the repo has
none, so the package ships no copyright file), a changelog, and an apt
repository.
## Productivity suite

149 products were asked for (document/spreadsheet/slides editors, mail, calendar, databases, project and
security tools, AI assistants, ...). **144 are built as apps; 5 are not, with the reason in the catalogue.**
Honest breakdown: 51 full, 93 partial (a real, useful part - the catalogue says exactly what is missing),
5 not built. See [docs/CATALOG.md](docs/CATALOG.md) for every product, its app name and its scope.

```
bin/suite list                list every product, scope and app name
bin/suite build DIR           pack one .kapp per app into DIR
kos install DIR/document-editor.kapp && kos permit document-editor && run document-editor
```

How it fits the security model: apps are ordinary sandboxed `.kapp`s (manifest + 3-line launcher); all code
lives in `kos/office`, on every app's import path like `kos.sdk`. Each app gets one folder:

```
<state>/appdata/<app>/cache/   scratch for each run, wiped the instant the app ends
<state>/appdata/<app>/data/    private user data (the vault); never wiped, survives updates
<state>/appdata/<app>/run/     live state of its running instances (record, socket, log)
<state>/permissions/grants.json  ONE universal permission store, for every app
<state>/spaces/<name>/         shared folders, created by the app that owns them
```

Apps *ask* the OS (a `vault` command) to put/get/list/delete named text items - never paths. No password
prompt for that (the run permit + the password at launch still apply), size/count caps apply.

**Shared folders.** An app whose manifest says `owns:contacts` creates the `contacts` folder, and its
permission, the first time it uses it. Any other app that says `uses:contacts` can look for it, but is only
let in after you grant it (`kos grant email-client space:contacts --level read`, with the password): the
manifest has to ask *and* the permission store has to say yes, and nobody can take over a name someone else
owns. Anyone holding a grant of at least the level asked for may use it - that is the whole rule. Wired so
far: Contact Manager owns `contacts` (Email Client and Appointment Scheduler look people up in it),
Calendar Manager owns `calendar` (the scheduler books onto it), Task Manager owns `tasks` (the collaboration
and workspace apps show the same tasks). `kos spaces` shows who owns what and who has access; `kos dirs APP`
shows an app's folders.

`kos permit` now records which manifest permissions you approved; if an update asks for more (say `network`)
it is refused until you permit again. AI apps additionally declare `network` (password at launch) and work
**without** a model using local deterministic tools; connect a model in the app's settings for open-ended
answers.

What is real vs. what is not: SQL is real SQLite; spreadsheets have a real formula parser (no `eval`); mail has
a real delivery pipeline; TOTP matches RFC 6238; the suite's Audit Log Manager and the OS audit log (`kos audit --verify`) are both hash-chained; search is BM25. What is not:
anything needing audio/video/camera/screen/other machines (conferencing, voice, capture, scanning, speech) and
anything that needs two *people* or two *machines* to share live data - every app is single-user and local, and apps share only through the owned folders above.

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
kos go kos://NAME[/path]    open an address, like a browser's address bar (open and run take them too)
kos extend NAME             switch an extension or mod on for the app it extends (password; --revoke, --list)
kos desktop install         pack, scan, install + permit the taskbar, the App Library and the OS's own apps
kos boot desktop            the desktop: taskbar + App Library apps (--graphical for pixels)
kos ls PATH / kos cat PATH  opens the Files app: browse/view real dirs and zips, never extracted
kos explore [PATH]          opens the Files app
kos activity                opens the Process and Resource Monitor app (what's open + recent password decisions)
kos view FILE               opens the Files app (password first)
kos permit NAME             give an app permission to run (password still needed every run)
kos grant APP space:NAME    opens the Shared Folders app: let an app into a shared folder
kos spaces                  opens the Shared Folders app: who has access to what
kos dirs APP                an app's cache / data / run folders
kos scan file PATH          opens the Scanner app (it asks the password to read the file)
kos scan watch DIR...       scan every file written here until Ctrl-C (password to start)
kos update all --from DIR   update every installed app that's newer in DIR, all scanned first
kos optimize                 opens the Storage and Disk Management app: recompress apps, prune dead state
kos admin [status|boot|lock] the elevated administrator keyboard (boots at login)
kos convert                 opens the Debian Converter app (static programs only)
kos skills [--out DIR]       opens the Skill Maker app; --out DIR writes the files (a guarded write)
kos write PATH --text T      write a file (needs the admin keyboard); owes a scan + optimize afterwards
kos backup add PATH...       back up files/folders (scanned, stored once per content)
kos backup [list]            what is backed up + what deduplication saved
kos backup restore ID DIR    put one item back (guarded write, never overwrites)
kos backup remove ID         forget one item (body deleted when nothing else uses it)
kos owed / kos settle        open the Storage and Disk Management app: what writes still owe / do it now
kos exec --code LINE         run one line of code as a sandboxed command
kos do WORDS...              one line of human language, run as one command
kos line [--explain]         the line shell: every line you type is a command
kos cell                    opens the Kernel Cells app: start, list and stop cells
kos aios status             the four AI OS layers and whether NeuroClaw answers
kos aios gui|app|kernel|skill WORDS...   one request on one layer (no password)
kos usb list|check|write|test   boot from a USB stick: write an image to one safely (see below)
kos doctor                  opens the System Information and Diagnostics app
kos audit                   opens the Audit Log app: every password decision, and a tamper check
kos security                opens the Security Check app (read-only; asks the password)
kos firmware                opens the System Information and Diagnostics app (press f)
kos firmware plan           the same app (press p): read-only advice
```

A command that is an app now (marked "opens" above) only opens that app, with no arguments: type the
path or the name inside it. If the app is not installed it says so and exits 66 - `kos desktop install` installs
them. `kos/launchmap.py` lists, for every command, whether it is an app, kept in the command line because a new
machine needs it before any app exists (`install`, `update`, `remove`, `permit`, `list`, `help`, `line`), or the
OS's own.

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

Included apps: `examples/backup` (a front-end for `kos backup`: `kos pack
examples/backup -o backup.kapp && kos install backup.kapp && kos permit backup`,
then `run backup` - `r` lists, `a` adds a path, `d` removes; each asks the OS for
your password), `examples/hello` (text + graphical + cmd-mode demo) and
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

## Addresses, extensions and mods

```
kos go kos://web/example.com/news?page=2   open the browser straight at that page (asks the password)
kos open graphical kos://hello             or kos://hello?mode=graphical
kos> kos://web/example.com                 in the line shell, a lone address opens it, like a URL bar
```

An extension or a mod is an app whose manifest says what it extends, and which ships `extension.json`
(data, validated at install, never run):

```
{"kind": "extension", "extends": "web", ...}          manifest.json: adds to an ordinary app
{"kind": "mod",       "extends": "taskbar", ...}      manifest.json: modifies a system app (taskbar, app-library)

extension.json:  {"entries": [{"label": "Wikipedia", "address": "kos://web/en.wikipedia.org"}],
                  "colors":  {"accent": "#c2410c"}}   (colors: mods only)
```

```
kos desktop install            once: the taskbar and App Library are the apps a mod modifies
kos pack examples/mods/taskbar-pins -o taskbar-pins.kapp && kos install taskbar-pins.kapp
kos permit taskbar-pins        it is an app, so it needs a permit like any app
kos extend taskbar-pins        password; the taskbar now shows its pins the next time it starts (a-i opens one)
kos extend --list              what is switched on, and the build each one is pinned to
kos extend --revoke taskbar-pins
```

Examples: `examples/extensions/web-bookmarks` (bookmarks on the browser's start page),
`examples/mods/taskbar-pins` (pinned apps + accent on the taskbar) and `examples/mods/library-shelf`
(a shelf of shortcuts + accent in the App Library). Rules the OS enforces: an extension cannot target a
system app and a mod cannot target an ordinary one; neither can ask for the `system` permission (the power
to open and close apps never rides in on an add-on); an app's `extension.json` must match its kind.
A pinned entry is only a *request* to open an address - the OS still runs it through gui, app and kernel
and asks for your password. Only the host app that was extended is told about it, and only apps written
to show entries do: the taskbar, the App Library and `web` do.

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

## One search box

Press **Ctrl-N** in any suite app (or **/** in the App Library). One line, no modes to pick, and the box
decides what you meant:

```
find> bac                         Commands:  kos backup  - deduplicated backups: add | list | restore | remove
                                  Assistant: Ask the assistant: bac
find> how do I back up?           Assistant: Ask the assistant: how do I back up?   (first: it reads like a question)
                                  Commands:  kos backup ...
find> quarterly                   Files:     note-1  - the quarterly report is due on friday
find> (empty, Enter)              Talk to the assistant
```

* **Commands** come from `kos help`. Choosing one shows what it does and the exact line to type. KOS never runs
  a command for you and never takes your password from an app: if the command needs it, the shell asks.
* **Files** means only what this app can already read: its own data and the shared folders you granted it
  (`kos spaces`). Nothing new is opened and there is no new permission. Credential-looking keys and the
  assistant's own history are never indexed.
* **Assistant** opens this app's built-in agent with your words already sent. With no model connected it
  answers from local tools and says so.
* The **App Library** adds installed apps to the same list (Enter asks the OS to open one, with your password in
  the OS's own prompt). Text from app descriptions and files is untrusted and stripped of control characters
  before it is drawn.

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

## "Requires"

`kos/requires.py` is one small table, and it is the whole policy:

```
session.unlock  requires (before)  admin.keyboard
admin.keyboard  requires (before)  kernel
file.write      requires (before)  admin.keyboard
                requires (after)   scan, optimize
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

### Booting from USB

```
sudo image/mkimage.sh --kernel bzImage --rootfs rootfs.tar --out kos.img
bin/kos usb check kos.img              # GPT + EFI/BOOT/BOOTX64.EFI present?
bin/kos usb test kos.img               # boot it in QEMU attached as a USB stick
bin/kos usb list                       # which USB disks it would write
sudo bin/kos usb write kos.img /dev/sdX   # then pick the stick in the firmware boot menu
```

`write` refuses anything that is not a whole, unmounted, writable USB disk big
enough for the image (`--allow-non-usb` relaxes only the USB rule, never the
mounted one), makes you type the device name, writes, reads the stick back and
compares every byte, then moves the backup GPT to the end of the stick. UEFI
boots removable media from `EFI/BOOT/BOOTX64.EFI`, which `mkimage.sh` writes
(and now fails the build if missing). `kernel/kos.config` builds in
xHCI/EHCI/usb-storage/UAS/SCSI-disk since the pre-boot initramfs cannot load
modules, and the pre-boot waits up to 60s for the stick before giving up.
Secure Boot: enroll the key you signed with, or the stick will be refused.

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
* **Backup (this round):** dedup across names and re-adds, versions of a
  changed file, directory walking (symlinks and KOS state skipped), password on
  every action with nothing changed on a wrong one, flagged files never stored,
  shared-body removal, a tampered index and a tampered body both refused,
  restore through the guarded write (round trip, never overwrites, refused
  before any password without the admin keyboard), the app's requests through
  the bridge, and the real CLI through a pseudo-terminal. **Not run here:** the
  `backup` app *running* inside the sandbox - this container's Python lacks
  `fcntl.F_ADD_SEALS`, so no sandboxed app (existing ones too: 14 pre-existing
  test failures) can start; the app's key handling and requests are unit-tested
  instead.
* **Also tested here (hardening round):** a seccomp filter checked three ways (BPF program interpreted, syscall
  numbers compared with the kernel header, every denied call tried from inside the real sandbox); the audit chain
  including a forger who re-links it and concurrent appends/trims (nothing recorded is lost); hostile file and
  zip-entry names (no escape sequences reach the terminal); the broker sleeping with zero wakeups; `kos security`
  against eight deliberately broken installs.
* **Written but not yet booted:** exclusive evdev capture for the admin
* **Written but not yet booted on real hardware or QEMU:** `kos usb` end to end on a real stick (its logic, refusals, byte-for-byte verify and the QEMU argv are unit-tested), the USB kernel options, exclusive evdev capture for the admin
  keyboard, the graphical desktop (`boot desktop --graphical`), the initramfs, kos-init as real PID 1, the
  image builder (including its new bytecode precompile step, which only had its syntax and its `compileall` command checked), framebuffer/evdev on real hardware, starting KVM cells (no
  KVM in the dev container).
* The userland is Python (stdlib only) to move fast. Python can't fully wipe
  secrets from memory; the security core should be ported to Rust.

See `docs/ARCHITECTURE.md` for the threat model and `docs/IDEAS.md` for the
running backlog of what's next.
