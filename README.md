# kernal-os (KOS) - a password-first, security-focused Linux operating system

**KOS** (also searched as *kernal os* / *kernel os*) is an open-source,
security-first operating system built on the Linux kernel, written in Python.
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
   with the `system` permission and a permit). The OS core stays small: auth,
   sandbox, devices, protocol. The taskbar and App Library are the model.
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
| Verification | `list`, `ps`, `activity`, `audit`, `owed` and `cell list` now need the password (`state.view`, refused before anything prints). Still run with no password: `scan file`, `ls`, `pack`, `doctor`, `security`, `firmware`. `attach` asks for no new password. Some of these show private state (`audit`, `activity`). `doctor`, `setup` and `scan file` have a reason to be open (they run before a password exists, or are read-only). The rest do not. |
| Connections blocked | The AI is the first connection the OS makes on an app's behalf and it follows the rule: no endpoint configured means refused and logged (`net.ai` `blocked`), one endpoint only, password per ask, no redirects. Two honest limits: a model on this computer is reached over plain `http://` to a literal loopback address (the bytes never leave the machine, but it is not encrypted, and the rule as written says no plain text); and the API key sits in `<state>/ai.json` (mode 0600, refused if wider) with no cipher beyond the LUKS2 disk, because the standard library has none. The `ask` call blocks the session for up to 30 s. There is still no firewall for anything else. An app's empty network namespace blocks it by default, but the `network` permission is one yes/no at launch that gives the app every host, every port and the ability to listen. Only apps are covered: nothing yet blocks or logs connections made by the OS itself or from outside the sandbox. Privileges are decided at launch, not when first used. Encryption and certificate checks are enforced only inside the `web` example (`check_url`, `fetch`); any other app with the `network` permission can still open plain sockets until connections go through the OS. |
| Pipeline encrypted | Nothing is encrypted. The command channel is plain JSON lines over a socket (`Channel` in `kos/protocol.py`). The real exposure is the broker socket (`kos open`/`attach`: any process running as you can connect) and cell vsock. Encrypting needs a vetted library; the standard library has no authenticated encryption and KOS has no third-party dependencies yet. |
| Everything is an app | Asking for "everything an app" is **not** met: this change added the AI as an app (`examples/ai`) and the browser's `ask`, and made the core smaller to ship, but did not move any existing built-in out of the OS. `kos ai set|show|clear` is OS code (it holds the endpoint and key, which an app must never see). `kos convert` is built into the OS, not an app, and like `pack` it writes its output with a plain create rather than the guarded `file.write` path. Converted programs have no stdin, no network and no arguments yet, so only simple non-interactive programs are useful. `kos skills` is built into the OS, not an app (an app can't write files, and it needs the command list, which no `request` returns yet). With `--out`, every file is a separate guarded write, so it asks for the password once per file; the empty `kos-app-NAME/` directories are created without the guarded path. The line shell (`kos line`), `ls`/`cat`/`explore`, `scan`, `audit`, `activity`, `optimize` and `settle` are built into the OS, not apps. Only the taskbar and App Library are apps today. |
| Everything is an app | `kos convert` is built into the OS, not an app, and like `pack` it writes its output with a plain create rather than the guarded `file.write` path. Converted programs have no stdin, no network and no arguments yet, so only simple non-interactive programs are useful. `kos skills` is built into the OS, not an app (an app can't write files, and it needs the command list, which no `request` returns yet). With `--out`, every file is a separate guarded write, so it asks for the password once per file; the empty `kos-app-NAME/` directories are created without the guarded path. The line shell (`kos line`), `ls`/`cat`/`explore`, `scan`, `audit`, `activity`, `optimize` and `settle` are built into the OS, not apps. Only the taskbar and App Library are apps today. |
| Modding layers | `kos/overlay.py` merges mod files over a base in an owner-chosen load order (see `docs/MODDING.md`). Nothing reads files through it yet, the CLI's base is empty because KOS has no core file set, and the writable `user` layer is memory only. Most of the wider "modding-centric OS" list (Wasm sandbox, hot-swap with state serialization, watchdog rollback, input hooks, driver processes) is **not built**; that doc says which items and why. |
| Programs | `ask:ACTION` permissions only cover the four `request` actions that touch the backup vault and the app list (`apps`, `backup`, `backup_add`, `backup_remove`). `open`, `close` and `focus` stay inside `system`, which is still all-or-nothing (and all of them at once): a program that opens other apps holds the whole `system` permission. `network` is still one yes/no per program. Apps of one group get separate data folders and share only through `owns:`/`uses:` spaces, but nothing stops you permitting every app of a group, which gives that set of apps the union of their powers. Single-file apps are covered by packing, install and permit tests, but **no single-file app has been run in the real sandbox yet**, and a single-file app must be Python (`app` / `app:FUNCTION`). Permits are now pinned to the file's hash, so updating an app (new bytes) means `kos permit` again; permits made earlier have no pin and are unrestricted. The 200-character id limit is the only bound on group depth. The old single-app `examples/backup` (one program, `system`) still ships and is still the one the older tests cover. `kos install FOLDER` asks the password once per app. Only ordinary apps can live in a group, not extensions or mods yet. Nesting apps inside a folder app (the older `mail.compose.attach` layout) is now refused; use a group. Not tested: a graphical-mode run of the split backup programs (they have a text page only). |
| Org blueprint | `docs/ORG_BLUEPRINT.md` maps the "organization-centric OS" blueprint to KOS. Only the parts that fit inside one sandboxed app exist: Semantic Graph and Rule Router (`kos/office/pack_org.py`). The semantic object kernel, graph file system, matrix workspaces, state snapshots, data bus, structured pipes, component apps and the kernel event router are **not built** (they need the kernel, a window manager or cross-app access). Both apps keep data in clear, bounded, and their hash chains are not signatures. |
| Search box | The Ctrl-N box and the App Library's `/` search (`kos/office/finder.py`) only *show*: a command hit is the line to type, never a run, and an app hit is a `request` the OS still asks your password for. File search covers only what the app can already read (its own vault plus the shared folders it was granted), at most 200 items and 20,000 characters each per place, and never keys that look like credentials (`llm`, `api_key`, `token`, `password`, ...), the agent's chat history or exports. That filter is a **name pattern, not a classifier**: a secret stored under an ordinary key name (say `note-7`) would be searchable by that same app. The App Library has no files of its own, so it searches apps and commands only, and its "Ask the assistant" row opens the `ai-assistant` app but cannot hand it your question. The command list is a generated table (`python3 -m kos.office.cmdindex --write`); a test fails if it drifts from `kos help`. Not tested: the graphical-mode drawing of the Ctrl-N box. |
| Local mesh | Design only, no code: `docs/MESH.md`. No pairing, peer transport, proximity sensing, camera or tether sharing exists, and the design conflicts with the firmware gate (radios are unbound at boot) and needs the same encryption dependency decision as the pipeline row above. |

A section-by-section comparison with a "formally verified microkernel"
hardening blueprint (what exists, what is only a kernel option, what cannot be
met on Linux, and what the blueprint overclaims) is in `docs/BLUEPRINT.md`.

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
| Debian conversion | `kos/debconv.py`, `kos/debshim.py`, `kos convert`: a `.deb` becomes a `.kapp`. The package is read in memory only (never unpacked to disk), bounded and path-checked, and the result is scanned; a flagged or unconvertible package is refused **before** any password prompt. The password (`app.convert`) is needed to write the file, and `kos install` then scans again, asks again and seals. **Maintainer scripts are never run and never kept.** Only **statically linked** programs convert (dynamic ones are refused with the package's `Depends` shown); symlinks and devices are dropped; setuid bits are stripped; the app gets **no permissions**. A small shim runs the program from a sealed in-RAM file with no stdin, a 10 s limit and a 64 KiB output cap, and shows its output as a text page. |
| Skill maker | `kos/skillmaker.py`, `kos skills`: one skill for the commands (read from the real parser) and one per installed app. One password (`skill.make`) verifies every app's seal first; a tampered app is skipped. Each file is scanned, and a flagged app skill is left out. An app's free-text description never reaches the instructions - it sits in one inert, labelled data block. Printing writes nothing; `--out DIR` writes each file through the guarded `file.write` path. |
| AI in the OS | `kos/ai.py`, `request ask`, `examples/ai`, the browser's `ask`: an app never talks to a model, it asks the OS. Needs the `ai` manifest permission (an extension or mod cannot have it; it grants no `system` power). One endpoint, chosen with `kos ai set` (password): `https` with the certificate checked, or `http` to a literal loopback address for a local model. Each ask needs the password, and the prompt names the app, the host and how many characters leave; `ai.ask` and `net.ai` go in the audit log. The model has no tools and its answer is plain text lines, so nothing in it can open, run or write anything; text an app hands over (a web page) is fenced as untrusted data, which lowers prompt injection but cannot remove it, which is why the answer can do nothing. |
| Lean build | `packaging/lean.py`, `python3 packaging/build_deb.py --lean`: package `kernal-os-core` is only the OS core (`bin`, `kos/*.py`, the two system apps) with docstrings and comments stripped and xz compression. 89 KB (89,152 bytes), against 398 KB (397,602) for the whole repository. Raw stripped core source is about 345 KB. The Python interpreter and the Linux kernel are not counted: KOS is a layer on them, so the whole system is not kilobytes. The whole test suite passes against the stripped sources (`KOS_LEAN_FULL=1`). Reproducible with the same Python only. |
| Password on everything | `kos/auth.py`: scrypt-derived master key; every action (`app.run`, `device.mouse`, `file.view`, ...) needs the password typed for *that* action. All decisions go to a tamper-evident audit log: hash-chained, with every grant anchored to your password (`kos audit`, `kos audit --verify`). |
| Apps are zip files that are never unzipped | `kos/kapp.py`, `kos/loader.py`: the zip is stored as-is, sealed with a password-derived key. At run time it's copied into a sealed in-RAM file (memfd) and run from there. A modified zip refuses to run. |
| Mouse/keyboard are "booted" | `kos/devices.py`, `kos/session.py`: apps never touch devices. The OS reads them and sends **commands** (`key`, `pointer`, `button`) to the app; the app answers with commands (`screen`, `frame`) that the OS checks and draws. Password prompts are an OS overlay the app can't see or cover. Ctrl-C always quits. |
| Everything goes through the security system | Apps run as `nobody` under Landlock + namespaces + a seccomp denylist (`kos/sandbox.py`): no reading your files, no writing, no network unless you allow it with your password, no `bpf`/`io_uring`/`perf`/keyring syscalls, 1 GiB of memory and 64 MiB per file at most. If the kernel can't enforce Landlock, apps don't start. The seccomp filter is x86_64 only (`kos doctor` says so). |
| Multi-kernel in parallel | `kos/cells.py`: a *cell* is a separate Linux kernel (KVM micro-VM) pinned to its own CPU cores. `run hello --cell c1` runs the app inside it over the same command protocol. |
| Virus scanning | `kos/scan.py`: a static/heuristic scanner (EICAR + hand-written rules for reverse shells, obfuscated `eval`, credential-file reads, fork bombs, curl-pipe-shell, ...) that recurses into zips without extracting them. Every `install` and `update` is scanned *before* the password prompt; a flagged file is quarantined, never installed. `kos scan watch DIR` scans every file written under a directory - started with your password, like a cell, so it's bounded and visible, not a silent background daemon. |
| Apps need permission to run | `kos/permit.py`: a persistent grant, separate from the password - `kos permit NAME` decides an app is allowed to run *at all*, once. It never replaces the password: `run`/`open` still ask for it on every single launch regardless. |
| Per-app cache, wiped on exit | `kos/cache.py`: each run gets one private, writable scratch directory inside its sandbox (the sandbox previously allowed *no* writable directory at all). The moment that app's process ends - clean exit, `kos close`, anything - the directory is overwritten and deleted. |
| Every line is a command | `kos/lang.py`, `kos/coderun.py`: a line of human language (en/es/fr/de/pt/it/ru/zh/ja) becomes exactly one structured `kos` command - never a shell string. A line of **code is a command too**: *run this line* - but never on the host. It is scanned, needs your password, and runs as a one-shot app in the usual sandbox (no files, no network, time limit, nothing carries over to the next line). `kos do WORDS...` runs one line; `kos line` is the shell; login starts it instead of `/bin/sh`. |
| The OS is made of apps | `kos/desktop.py`, `kos/system.py`, `examples/system/`: the **taskbar** and the **App Library** are ordinary sandboxed apps. They never touch the screen or other apps - they *ask* the OS with a `request` command (needs the `system` permission in the manifest + a permit; opening/closing needs your password in the OS's own prompt). The **right mouse button is the App Library**, handled by the OS from any app. |
| Elevated administrator keyboard + **requires** | `kos/admin.py`, `kos/requires.py`: *requires* is a dependency, not an action. **Unlocking requires the elevated administrator keyboard, which requires the kernel**: the unlock password boots the keyboard (a lease signed with a password-derived key, bound to this boot) and if the kernel protections are missing the computer simply does not unlock. **Writing a file requires a security scan and a disk optimize afterwards**: the write is recorded on a ledger as owing both, they are done in order under the same password, and anything left owed (a crash, a failed step) survives restarts and blocks the next write until `kos settle`. |
| Backups (the backup app) | `kos/backup.py`, `examples/backup`: **content-addressed, deduplicated** backups. A file body is stored once under its SHA-256 no matter how many names or times it is added; every file is **scanned before it is stored** (flagged files never enter the vault); `add`/`list`/`remove`/`restore` each need the password; the index is HMAC-sealed with a password-derived key and every body is re-hashed when read, so tampering is refused. **Restore is a write**, so it goes through the guarded write (admin keyboard, scan, optimize) and never overwrites. The `backup` app is a sandboxed front-end that can't read files itself - it *asks* the OS (`system` permission) and the password is typed in the OS's own prompt. |
| AI OS: KOS is the engine | `kos/aios.py`: four layers only - the graphical button clicker (`gui`), terminal app commands (`app`), kernel commands (`kernel`, NeuroClaw's Linux permission tools) and the auto skill maker (`skill`). KOS carries a request to the NeuroClaw engine on this computer and asks for no password; the engine's own tool gate and approvals decide what happens. Nothing else of NeuroClaw is reachable, nothing autostarts, and the engine address must be loopback. |
| Security check | `kos security` (`kos/secure.py`): one read-only check, no password, nothing changed, nothing running in the background. Kernel protections, private folders and secrets, audit-chain integrity, every installed app rescanned and compared with what was installed, permissions nothing uses any more or that were never pinned, owed work, crash leftovers. Exit code 3 if anything failed. |
| Firmware control (no ME, PSP or BMC in charge) | `kos/firmware.py`, `boot/initramfs/firmware.sh`: before the disk is unlocked, and again in `kos-init`, KOS looks for management processors that run below the OS - **Intel ME/AMT, AMD PSP, server BMCs (IPMI)**, and every other chip with its own firmware (Thunderbolt/USB4, USB-C port controller, embedded controller, network, GPU, NVMe, wireless), plus a missing IOMMU. If one is running it alerts, cuts the OS's side of it (unbinds the driver, forbids rebinding) and **refuses to boot**. Only an Intel ME whose own status register says *disabled* is believed off. `kos.firmware=warn` on the signed kernel command line boots anyway. **This cannot switch them off** - see the limits in `docs/ARCHITECTURE.md`; almost no real hardware will boot under the default policy (VMs will). There is no resident checker: it runs once at boot and at each unlock. An owner-written allow list (`boot/firmware.allow`, `/etc/kos/firmware.allow`) accepts chips whose firmware you replaced yourself; KOS never flashes anything. `kos firmware` also lists which protections (IOMMU, memory encryption, LUKS2, Thunderbolt security) narrow what the remaining chips can see. |
| Open apps like websites | `kos/address.py`: `kos go kos://web/example.com/news` opens the app `web` and tells it the path, the way a browser opens a site. `run` and `open` take addresses too; an app can ask for one with a `request`. Addresses are checked strictly (no other schemes, `..`, `%`, `#`, whitespace or control characters) and the path is *data for the app*, never a file name or a command. |
| Mod file overlay | `kos/overlay.py`, `kos overlay`: mods ship files under `overlay/`; the OS merges them over a read-only base at read time, last in the load order wins, `X.kos-delete` hides a file, writes are copy-on-write in memory, `core/` is protected. Order changes need the password (`overlay.order`). |
| Extensions and mods, still apps | `kos/extensions.py`: two kinds of app, both ordinary sealed, scanned, permitted `.kapp`s. An **extension** adds to an ordinary app, like a browser extension (bookmarks for `web`). A **mod** modifies a system app (pins and a new accent for the taskbar, a shelf for the App Library). They are *data*, not code injected into another app: the host's zip and seal are never touched, and the OS hands the host the validated entries after `hello`. Nothing happens until you switch one on with `kos extend NAME` (password; a mod is a separate `app.mod` action); the switch pins the exact build you approved, so an updated or tampered add-on stops contributing until you approve it again. |
| Every app action passes gui, app, kernel | `kos/layers.py`: opening, running, closing, switching to and extending an app all go through one door, `layers.traverse`, which sends the request through the **graphical button clicker** (is there a button for it?), then **app commands** (is it permitted?), then **kernel commands** (the password, the seal, the sandbox), in that order. A layer that says no stops the rest, so an unpermitted app is refused before any password is asked. Every layer's `pass` or `refused` is in `kos audit`. A test fails if any other code asks for the password to use an app. |
| Groups of apps | `kos/kapp.py` (`find_programs`, `pack_tree`), `kos/permit.py`, `apps/backup/`: **every page is an app, and an app is a file** (`NAME.py` with its `NAME.json`; a folder with a `manifest.json` is also still an app). A **group** is a folder with no manifest: it holds only apps and other groups, so it has no code and no permissions to give. Groups nest with **no level limit**; an app has no apps inside it. An app's id is the group path joined with dots (`docs.editor.format`). Permissions are asked for in the app's own manifest and approved on that one file: `kos permit` pins the permit to the file's sha256, so a different file under the same name needs a new permit. Nothing is inherited, up or down the tree. See [Groups of apps](#groups-of-apps). |
| Disk optimization | `kos optimize` (`kos/optimize.py`): recompresses installed apps to the smallest lossless size and re-seals them at the new bytes, prunes dead background-app records, trims the audit log - all under one password. |

## Groups of apps

Every page is an app, and an app is a file. Apps live in **groups**: folders that hold only apps
and other groups. Permissions go to the file, never to a group:

```
apps/docs/                      a group: no manifest, no code, no permissions
    spell.py + spell.json       the app docs.spell        (one file + its manifest)
    editor/                     a group inside the group; groups nest as deep as you like
        format.py + format.json     the app docs.editor.format
apps/backup/list/manifest.json  a folder app (several files) is still an app: backup.list
```

```
kos pack apps/docs -o dist/docs         # one .kapp per app; -o is a folder
kos install dist/docs                   # every app, each with its own password
kos permit docs.editor.format           # one file at a time; `kos permit docs` is refused (a group)
run docs.editor.format                  # kos://docs.editor.format opens it too
```

* **One file, one manifest.** `NAME.json` is an ordinary manifest (name, modes, permissions); its `name`
  must be exactly the group path plus `NAME`, or packing is refused. The file is packed as `app.py`, so
  the entry must be `app` or `app:FUNCTION`. A `.py` with no `.json`, a `.json` with no `.py`, or any
  other loose file in a group is refused: code with no manifest would run with no permissions listed.
* **An app has no apps inside it.** A folder with a `manifest.json` that holds another app is refused;
  make it a group. A name cannot be both an app and a group.
* **No depth limit.** The only bound is an id of at most 200 characters, because the id becomes the
  file name `<id>.kapp`.
* **Permissions belong to the file.** `kos permit` records what that file's manifest asked for and the
  file's sha256. An update that asks for more, or a different file with the same name, is refused until you
  permit again (permits made before pinning have no pin and are not restricted). Permitting one app
  permits no other. Beyond `network` and the shared-folder permissions, an app may ask the OS for single
  things with `ask:ACTION`; `system` is every request and stays for apps like the taskbar; an
  extension or a mod cannot hold `system` or any `ask:`.
* **Apps do not share anything by name.** Each has its own cache, data and run folders
  (`kos dirs docs.spell`). They meet only in shared folders (`owns:` / `uses:`), each needing its own grant.

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
kos install app.kapp       install (kept zipped, sealed); a folder installs every .kapp in it
kos pack GROUP -o FOLDER   a group of apps: one .kapp per app (see Groups of apps)
kos update app.kapp        update to a NEWER version (downgrades refused)
kos remove NAME / kos list
run [graphical|cmd] NAME   run in the foreground: text page, graphical, or raw command stream
kos open [graphical|cmd] NAME   open in the background, return immediately
kos ps                     apps opened with 'kos open'
kos attach ID               connect your terminal to one (Ctrl-C detaches, doesn't kill it)
kos close ID                actually stop one
kos ai set|show|clear       the one AI endpoint (password; key from $KOS_AI_KEY or a hidden prompt, never argv)
kos go kos://NAME[/path]    open an address, like a browser's address bar (open and run take them too)
kos extend NAME             switch an extension or mod on for the app it extends (password; --revoke, --list)
kos desktop install         pack, scan, install + permit the taskbar and App Library
kos boot desktop            the desktop: taskbar + App Library apps (--graphical for pixels)
kos ls PATH / kos cat PATH  browse/view real dirs and zips, never extracted
kos explore [PATH]          interactively cd/ls/cat, straight into zip files
kos activity                one feed: what's open + recent password decisions
kos view FILE               view a file (password first)
kos permit NAME             give an app permission to run (password still needed every run)
kos grant APP space:NAME    let an app into a shared folder (--level read|write; --revoke; --list)
kos spaces                  shared folders: owner, item count, who has access
kos dirs APP                an app's cache / data / run folders
kos scan file PATH          scan a file/zip right now (no password needed)
kos scan watch DIR...       scan every file written here until Ctrl-C (password to start)
kos update all --from DIR   update every installed app that's newer in DIR, all scanned first
kos optimize                 recompress apps, prune dead state, reclaim disk space
kos admin [status|boot|lock] the elevated administrator keyboard (boots at login)
kos convert PKG.deb -o OUT.kapp [--exe PATH]
                             convert a Debian package into an app (static programs only)
kos skills [--out DIR]       make agent skills from the installed apps and commands
kos write PATH --text T      write a file (needs the admin keyboard); owes a scan + optimize afterwards
kos backup add PATH...       back up files/folders (scanned, stored once per content)
kos backup [list]            what is backed up + what deduplication saved
kos backup restore ID DIR    put one item back (guarded write, never overwrites)
kos backup remove ID         forget one item (body deleted when nothing else uses it)
kos owed / kos settle        what earlier writes still owe / do it now
kos exec --code LINE         run one line of code as a sandboxed command
kos do WORDS...              one line of human language, run as one command
kos line [--explain]         the line shell: every line you type is a command
kos cell start NAME --kernel K --initrd I --cpus 2,3
kos aios status             the four AI OS layers and whether NeuroClaw answers
kos aios gui|app|kernel|skill WORDS...   one request on one layer (no password)
kos usb list|check|write|test   boot from a USB stick: write an image to one safely (see below)
kos doctor                  which kernel protections this machine has
kos audit [--verify]         every password decision; --verify checks the log for tampering
kos security                 check everything KOS can verify about itself (no password, read-only)
kos firmware                management processors (Intel ME, AMD PSP, BMC) and whether the OS would boot
kos firmware plan           read-only advice: which blocking chips have open firmware, which must be disabled or allow-listed
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
