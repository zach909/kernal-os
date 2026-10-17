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
| Apps are sealed zip files, **never run while zipped** | `kos/kapp.py`, `kos/loader.py`: the zip is stored as-is, sealed with a password-derived key; a modified zip refuses to run. At run time the verified archive is **unpacked into a private folder** (mode 0700, in RAM when programs may run from there, every file read-only), the unpacked files are read back and compared with the archive, and the app runs from that folder. The folder is wiped when the app ends. Browsing a zip (`kos ls`, Files) still never extracts it. |
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
kos> c: printf("hi %d\n", 6*7);   -> built by the machine's C compiler *inside the sandbox*, then run: hi 42
kos> go: fmt.Println(6 * 7)     -> the same for go:, cpp:, rust:, js:, ruby:, perl:, php:
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
password and a time limit. **Python** runs on the OS's own interpreter. **C, C++, Go, Rust, JavaScript, Ruby, Perl and PHP** go through the
compiler path (`kos/compiler.py`): KOS writes no compiler of its own, it drives the toolchain the machine already has - *as an app*: the line becomes
a one-shot app that, in the same sandbox as every other app (unprivileged user, no network, none of your files, Landlock), writes the source into
its RAM scratch directory, calls the compiler, runs what it built and prints the output; the scratch is wiped afterwards. A fragment is wrapped
into a program (`printf(...)` gets `main` and the includes; `fmt.Println(1)` gets `package main` and the packages it names). Which language a line is
in is guessed, or say it: `c:`, `cpp:`, `go:`, `rust:`, `js:`, `ruby:`, `perl:`, `php:`. The sandbox may read the toolchain's own install
directory and nothing else; a toolchain under `/root` or `/home` (like a rustup install) is reported as unavailable rather than widened for. A language
with no toolchain (Java here) is still a command - understood, scanned, logged - and says so. `kos line --explain` shows how each line was understood.
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
| `menubar` | the **top panel**: the KOS menu (opens the launcher), the active app's name and the commands it offers (click one to run it), CPU/memory, network, a sudo indicator, date and clock |
| `dock` | the **floating dock**, centered at the bottom: pinned apps, then whatever else is running; a dot marks open apps (KOS Blue when active) |
| `sidebar` | the **right-hand panel**: a segmented tab (Notifications / Widgets), the notification list, and a **shelf** of pinned links at the bottom |
| `pins` | the backdrop's pins: apps, files, folders and web addresses you pinned (the `+` tile pins one: a path, a web address or an app name) |
| `launcher` | the **Super key** panel: every app, plus the same search as the desktop - apps *and* the commands they offer |
| `search` | type anywhere: finds apps **and the commands they offer**; any other line is a command too - `print(1)` runs sandboxed and prints 1 |
| `widgets` + `widget-*` | the widget handler (show/hide/reorder, remembered) and the widgets, stacked in the sidebar's Widgets tab (the ones that do not fit are hidden) |
| `cursor` | the **mouse pointer**: an arrow drawn by code that can turn to point the way you move, and presses down when you click |
| `effects` | click effects: in the 3D look, a ring and small bubbles pop off every click |
| `appearance`, `passwords`, `mods`, `browser`, `converter` | settings for the look, the password layers, system mods, a text-mode web browser, the `.deb`/AppImage converter |

Apps never touch the screen. The OS adds the glass (blur, tint, sheen, bevel, soft shadow, rounded corners) around
their shapes, draws the window frames itself, and asks for your password in its own overlay that no app can see or
cover. Opening anything is a *request*; the right mouse button shows the desktop.

**Look:** a minimalist top panel and a floating bottom dock (a top panel and a floating dock), KOS Blue **`#0078D4`** for active and
selected states, neutral dark glass instead of navy, and smooth proportional type. Smooth type is the OS's own
pure-Python TrueType rasterizer (`kos/ttf.py`, exact-coverage anti-aliasing) using a system font; apps send
`["stext", x, y, text, color, px, face]` and the OS draws it, so apps never need a font file. Not yet converted:
the app windows' *content* is still the older text-mode pages (now drawn in a smooth monospace font), and a few
widget details still use the pixel font.

### Agents: an outside AI can propose, only you can approve

An AI agent (Claude Code, a script, any program you run yourself) cannot live inside the OS and should not be trusted with it. The optional **agent bridge**
(`kos desktop install --optional agent-bridge`) is a mailbox between the two: the agent drops a plan - `{"agent": "claude-code", "title": "...", "steps": [...]}` -
into the bridge's inbox (or runs `kos agent propose plan.json`; `kos agent` prints the folders, `kos agent results` the answers). A plan is at most eight steps of
*open, focus, close, apps, info, netcheck, sys* - launching and looking, no files, no commands, no writes. It is checked twice (`kos/agentplan.py` and the
bridge's `plan.js`, which a test keeps identical), then proposed to the OS like any assistant's plan: the OS shows it and asks for **your password, never
remembered** (a sudo window cannot approve it); only then does each step run, as the bridge, which holds `system:apps` and `system:os` and nothing else, no network.
The answer goes to the outbox for the agent. *Honest limits:* the agent is outside the sandbox (it is whatever you run); the bridge cannot stop it writing
to its own inbox, only from doing anything without you; there is no live chat with a model - a model that wants to plan from your words is an assistant app you
give network access, as with `assistant`.

**Swipe** a quick horizontal drag on the bare desktop: left for the next desktop, right for the one before (four desktops; it never fires from a window).

### Clear backgrounds: apps do not have to be square

Colours can be see-through: `#rrggbbaa` (the last two digits are the opacity) in `clear`, `rect`, `line` and `poly` ops, so the desktop shows through
glass, glows and soft edges (text stays solid). A manifest can say `"frame": "none"` (graphical apps): the window then has **no frame, shadow or body** - it is
exactly what the app draws, in any shape. Where it draws nothing, **a click goes through to whatever is behind it** (the OS finds the solid pixels by painting
the app's ops on black and on white, once per picture, only when a pointer needs it). The app declares a `drag` rectangle that moves the window and a `hit` for
its own controls; it closes itself by exiting. Frameless windows are drawn that way in the 3D and VR looks too (a thin sheet in its own shape), and the terminal
look lists one as "the window" plus a Close. `examples/optional/orb` is a round, glowing clock you can drag and close: `kos desktop install --optional orb`.
*Honest limits:* a frameless app has no OS chrome, so it can draw a fake title bar inside its own shape (as any app can inside its own window) - but it can
never cover the password prompt, which the OS draws last, and it is capped at 70% of the screen. Text in a see-through colour is drawn solid.

### The interface is an app (and so are the looks)

Only two things are the system's own interface: the **terminal** (every line typed is a command) and the **button selector** (the terminal look: every
control in a numbered list). Everything else you see - the flat glass desktop, the 3D scene, virtual reality, augmented reality, the neural interface - is
an **interface app**: an app with `"driver": "interface"`, a `"look"` name and the `compose` permission. It is told what is running (each layer's name,
rectangle, depth, title and what the app drew), draws all of it however it likes, and hands the OS one picture; the OS puts the password prompt on top of
that picture, always. The desktop itself is apps too: the wallpaper, menubar, dock, widgets, search, launcher, cursor and effects. The terminal launches apps.

* **Where they live:** `interface-normal` and `interface-3d` are installed with the desktop; VR, AR and the neural interface are **optional** and only
  exist if you install them: `kos desktop install --optional interface-vr,interface-ar,interface-neural`. Choosing a look in `Appearance` (or `kos desktop shot
  --look 3d`) starts that look's app - which asks for your password like starting any app. If the interface app dies, the OS draws the flat desktop itself
  until it is back; the terminal look never needs one.
* **What an interface app can and cannot do:** it sees the layers it is sent and nothing else; it cannot read files, run commands or reach the network.
  The OS refuses its picture unless it is exactly the size of the screen. A click is mapped back through the *quads* it declares (where each layer's face
  landed) to the position on the flat layer, then handled exactly as a flat click; *regions* it declares (a waterfall, the kernel) are handed back to it,
  and it can only act by asking the OS like any other app, with the scopes its manifest holds. It gets only the keys and buttons it declared (Alt+arrows,
  the middle button) and pointer moves if it asked. **Ctrl-Up** looks down at the looks as a stack of cards (the interface in front, text and terminal behind).
* **normal** (`interface-normal`) - glass, pills, smooth type.
* **3d** (`interface-3d`) - **everything is a solid block, and the terminal is the water.** Every window, the menubar, the dock, the sidebar, each widget and the launcher
  is a box standing on the wallpaper; the **front** is what the app draws (frosted glass and all), the **back** is the list of its buttons, the sides are
  tinted glass. **The terminal comes down like a waterfall:** from the bottom edge of each app a see-through curtain of that app's own words falls to the
  ground, and **clicking an app's waterfall takes you to its commands** (the Commands app). **The ground is a lake of terminal**; look down and a bright
  river of text runs along it - **the lake flows to the Kernel, and from the kernel on to the Hardware**, two blocks standing on the river
  (click the kernel: Isolation; the hardware blocks are the real machine - CPU, RAM, each disk, each network card, the input devices - and each opens its own monitor: Resources, Memory, Devices, Network). **Click the ground and you are back at the terminal** (the system's own interface). The **pointer is a cone on a cylinder** (the cursor app), shaded and floating over the screen; **when you click it points
  straight down** at what you are pressing. **Go around it**: Alt + arrow keys, or drag with the middle button (Alt-0 resets; `kos desktop shot --keys alt-left,alt-up`).
  Text is extruded (letters have depth) and icon symbols are solid; clicks pop bubbles and the screen tilts a little toward your movement. *How:* each face
  is a flat quad, which a perspective camera turns into a homography of its texture, so every face is filled scanline by scanline (`kos/blocks.py`).
  *Honest limits:* pure Python - a frame is a second or so, so orbiting is not smooth; blocks are boxes, not meshes; no colour-emoji font, so emoji are not
  drawn (icons and text are); the hardware blocks show what the OS reported when last asked (every 15 s), and only what this machine's `/proc` and `/sys` expose - a virtual machine shows its virtual disks.
* **vr** (optional) - virtual reality: **one picture per eye**, side by side (half-width each, the usual half side-by-side format). Every layer sits at a depth -
  the wallpaper far away, windows and the sidebar nearer, effects and the pointer nearest - and each eye sees it shifted by that depth's disparity;
  moving the pointer turns your head, which slides the far layers more than the near ones. *Not here:* head tracking from a headset's sensors, lens
  correction, 90 Hz (it is pure Python). A headset appears as one more display, which the extra-displays layer already handles; its sensors would come in
  through a `"driver": "xr"` app. None was available to test.
* **ar** (optional) - augmented reality: the same stereo view, but the wallpaper is a **camera passthrough** when a camera driver app fills the wallpaper slot (it
  sends frames with the `blit` op) - the interface floats over the world. With no camera driver it says so on screen and floats over the plain
  wallpaper. `examples/drivers/camsim` is a camera *emulator* (a synthetic room), labelled as one; no real camera driver is included.
* **neural** (optional) - a surface neural interface (an EEG band, an EMG wristband): a highlight **scans the buttons on its own** (every 1.4 s), and one signal
  - a blink, a clench, a thought the driver recognises - presses (the app asks the OS to `press` that spot). A **neural driver** is an app with `"driver": "neural"` and the `neural`
  permission; it may send exactly five decisions (`next`, `prev`, `select`, `back`, `pause`), only while this look is on, at most ~12 a second.
  **The OS never receives or asks for the signal**: it stays inside the driver's sandbox, which has no network and no files. `examples/drivers/neurosim`
  is an emulator you click. No real neural device driver is included or was tested.
* **text** - everything is built from text: windows are boxes, labels are characters, buttons are `[Label]`.
* **terminal** - no pictures: a numbered list of **every button on screen**; Up/Down or a number picks one, Enter presses it, or click the line.

All of this works because apps *declare* their controls with invisible `hit` ops (`["hit", x, y, w, h, "Files"]`); the OS gathers them (plus the window
frames it draws itself) into one list. In **every** look, **Tab** (when no window is focused) walks that list with a focus ring and **Enter** presses the
control - the keyboard-only way around the interface. An app with no `hit` ops still shows its text in the text look but is not reachable from the keyboard.

### AI assistants: an app that must ask permission

An AI assistant is an ordinary KOS app with the `assist` permission (`"driver": "assistant"`). It has no password, no files, and no network unless you
gave it some, and **no way to act on its own**: all it can do is *propose a plan* - up to eight steps, only launching and looking actions (open, focus,
close, list, view, scan, system facts) - and the OS shows you the plan and asks for your password. If you do not type it, nothing happens. If you do, each
step runs *as the assistant*, limited to the scopes the assistant holds (a plan step it has no scope for is refused outright) and asking for whatever
password that step needs by itself. Saving, backing up, pushing, signalling, permitting, sudo, mods and the password policy cannot even appear in a plan.
The approval is never remembered: a sudo window cannot approve a plan, and every plan lands in the audit log. `examples/optional/assistant` is a
rule-based stand-in ("open files and processes"); a real model plugs in the same way - an assistant app you let reach its model (the network permission is
asked for separately) that turns what you type into the same kind of plan. Nothing here makes an assistant smarter or safer to *believe*; it makes it
unable to do anything you did not approve.

### Nothing has power over everything (`kos services`)

The rule: **every service, system and part of KOS is an app, and nothing - the OS included - holds power over everything**, because things can be
faked: an app, a "system" app, a update, a driver. So the old all-or-nothing `system` permission is gone from the built-in apps. It is now a list of
**scopes** - `system:apps`, `os`, `files`, `backup`, `processes`, `security`, `passwords`, `run`, `updates`, `maintenance`, `heal`, `mods`, `links`,
`notify`, `hardware` - each opening a few related requests and nothing else (`kos/capabilities.py`). The dock may list and open apps and nothing more;
the clock widget may read OS facts and nothing more; a mod can never exceed the ceiling of its slot. A scope only lets the *question* reach the OS: whatever
changes anything still needs its own password. `kos services` prints the **trusted core** - the five small pieces that cannot be apps because they
launch, seal, confine and ask for the password (authority, store, sandbox/broker, registry, compositor), each with what it does and what it cannot do -
then every installed app with exactly the scopes it holds, and fails if any holds the bare `system`. The tests read each built-in app's own code and
require its manifest to hold **exactly** the scopes that code uses: no more, no less.

### Every layer asks for your password

**Starting an interface app asks for the password like starting any app** (the virtual-reality, augmented-reality and neural ones reach for a headset, a camera
or a neural device through their own drivers). A driver's device node is given only after its own password (`app.device`), exactly as for every hardware driver. **Each app also has its own folder**
(`<state>/appdata/NAME/`, `KOS_DATA_DIR`, `app.data_dir()`): persistent, writable by that app alone (nothing else is mounted into it, checked
with real Landlock), kept when the app is removed (`kos remove NAME --purge-data` deletes it).

Four layers each ask: **interface** (starting the desktop and its devices - *optional*, `kos policy interface off`), **apps** (open, close, install, update,
permit), **commands** (what a running app asks the OS to do: files, code, processes, backups) and the **kernel** (the admin keyboard, your password, software
sources, KOS itself, system mods). `kos sudo on 10` (or the Passwords app) opens a **sudo window**: you type the password once and the interface, app and
command layers are remembered for up to 60 minutes - in the memory of that process only, never on disk, gone when it ends or you run `kos sudo off`. The kernel
layer is never remembered, and neither is anything that changes who or what is trusted or sends your data out (permissions, the password, sources, pushes,
mods, KOS updates): those ask every time, window or not. The honest cost: while a window is open, an app you permitted can ask for remembered actions
without a prompt - so keep windows short, and the menubar shows a sudo chip with a countdown while one is open.

### System mods

A **mod** is an app that fills one part of the interface - `wallpaper`, `menubar`, `dock`, `pins`, `search`, `sidebar`, `launcher`, `cursor`, `effects`, or an
extra `widget` - by naming that `"slot"` in its manifest. `kos install` it like any app, then `kos mod enable NAME` (or the Mods app): the desktop runs it
instead of the built-in one at the next start. Each slot has a **ceiling** on what a mod may ask for (a wallpaper: nothing; a cursor: the pointer and
animation ticks; a dock: what the built-in dock has), enabling is a kernel-layer action that always asks, the built-in app is never deleted, and a mod that
is uninstalled just falls back. Examples in `examples/mods/`: a synthwave wallpaper, a ring pointer, an uptime widget.

### Convert a `.deb` or an AppImage

```
kos convert tool.deb            # or Some-App-1.2-x86_64.AppImage        (nothing is run)
kos install tool.kapp           # scanned, sealed, then it runs sandboxed like any app
```

Conversion reads the package as data: a `.deb`'s files are rewritten as a `.kapp` (setuid bits cleared, symlinks replaced by copies of what they point at inside the
package, docs left out, **maintainer scripts never run** - they are listed), and an AppImage is kept whole and run with `--appimage-extract-and-run` (no FUSE)
from a private RAM scratch directory. Either becomes a `bundle` app: a program tree unpacked read-only into RAM and started - like every app - with `npm run start`,
under the usual sandbox (no network unless you grant it). Output becomes a text page and your keys go to its stdin. **Limits, plainly:** it needs pipes, not a
terminal, so line-oriented programs work and full-screen curses ones do not; a program that wants a graphical display has none (KOS is not an X server) and says
so; dependencies are listed, not installed. A real AppImage (`appimagetool`) was run this way, inside the sandbox, to verify it.

### Sidebar, pins, launcher, notifications

The sidebar's **Notifications** tab shows what apps post (`notify`, rate-limited) and what the OS reports (for example, an app that could not be opened); its
**Shelf** and the desktop **pins** share one list of links (`kos/links.py`). A link is only a name for something - an app, a file, a folder or a web address - so
pinning needs no password, but opening it goes through the usual gates (a file asks for your password; a web address opens in the `browser` app, which has no
network until you allow it and runs no scripts). The Super key or the KOS menu opens the launcher.

### Multiples: seats, desktops, instances, displays

Nothing in the interface assumes there is one of something. **Several mice and keyboards at once:** every mouse/keyboard pair is its own *seat* with its own
pointer, focused window, drag and text box (the i-th keyboard and i-th mouse make seat i; seat 0 is drawn by the pointer app, the others by the OS in the seat's
colour). **Several desktops:** four workspaces - windows belong to one, the interface is on all, **Ctrl-1 to Ctrl-4** switch, and numbered chips in the top panel
show and switch them (asking for a window on another desktop goes there). **Several instances:** any number of an app can be open (`new`), opened in the
background (minimized, no focus), and an app you started with `kos open` in a terminal is adopted into the desktop with no password. **Several displays:** each
framebuffer is a display; they sit side by side as one wide screen with the panel, dock and sidebar on the first. *Honest limits:* seats and displays are written
for real hardware and verified only with scripted devices and headless outputs; there is still one password prompt at a time (it appears on the first display), one
sudo window per process, and the seat/pointer model has no per-seat password.

### Self-healing

If an interface app stops, the desktop **restarts it** (after 1, 3, 8 s, with a notification). An app whose process is gone needs a fresh start, which asks for
your password (or is covered by a sudo window) - it never prompts silently; a mod that keeps failing is replaced by the built-in app for its slot. `kos heal`
(also `f` in the Health app) looks at the state on disk: corrupt preference files are **moved aside, never deleted**, and defaults return (the password policy falls back
to the strict setting); dead instance records and stale RAM scratch are cleaned; a missing or seal-failing **built-in** app is reinstalled from the copy shipped with KOS
(password); a mod that no longer fits its slot is switched off. An app that is not built in and fails its seal is reported and left alone. A race that could leave a
freshly started app stuck as "starting" (found by the benchmark under load) was fixed with an atomic create-if-absent.

### Auto-update

The Updates app (`kos autoupdate`) knows when an update is **due**, tells you in a notification, and updates every app from your sources with one click and one
password. **Auto mode** runs a due update by itself *only* while you have a sudo window open that covers apps and commands - KOS never interrupts you with a
prompt on its own, and truly unattended installs cannot exist because every install is sealed with a key derived from your password. **KOS itself** is
fast-forwarded only with you (always asks). **The OS - kernel, drivers, firmware, packages** - is listed by kind (kernel, drivers, security, other) with the
exact root command, because KOS holds no root and cannot install them. An update that asks for new permissions is held back for review.

### Hardware drivers (quantum is one optional kind)

KOS has one generic way to let an app use a piece of hardware: a **driver** is an ordinary app whose manifest names a kind (`quantum`, `camera`,
`xr`, `neural`) and the device nodes it wants (`"devices": ["/dev/video0"]`). At launch KOS names the nodes, asks, and after your password (every
time, never remembered) opens **exactly those nodes** to that app in the usual sandbox - no network, no files, nothing else in `/dev` (verified
with real Landlock). That is all the OS knows about hardware; everything device-specific lives in the driver app.

Quantum hardware is just one such kind, **not part of the default system**: the Quantum app is in `examples/optional/` and is not installed by
`kos desktop install`; `kos quantum devices|run` is a thin helper over the same driver mechanism. **No real quantum driver exists here and none was
tested**; `examples/drivers/qsim` is a state-vector *emulator* of the job protocol, labelled as one.

### Speed

`kos desktop bench` measures it. On the 1280x720 headless run here (a shared cloud VM): starting all 14 interface apps with one password takes about 1.3 s and
they have drawn 0.17 s later; a cached frame is 0.3 ms; a repaint after the clock, the search box, the top panel or the dock changes is about 20 ms; the first frame
is about 0.3 s. Two changes did most of it: a panel's glass cache now depends only on the layers that can actually reach it (typing in search had been re-blurring
every panel: 570 ms -> 22 ms), and shadows touch each pixel once (7x faster). Text drawing skips empty pixels. Remaining cost is pure-Python pixel work; a damage-rectangle
pass and native blur would be the next step (see `docs/IDEAS.md`).

**Naming and assets:** KOS uses its own names (KOS Blue `#0078D4`, the Super key, the launcher). It follows conventions common to desktop
environments - a top panel, a dock, tabs, a launcher - but copies no one's logos, icons, fonts, sounds or artwork: every icon and the wallpaper
are drawn by code, and fonts are the system's own libre faces (Inter and the Liberation family are OFL/open licensed; the kit only *installs* them
through your package manager, it does not ship them). No trademarked product names are used for features.

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
| `protections` | Kernel protections; which apps are permitted to run (Enter toggles, password). |
| `settings` | The hub: choose the interface, and open every setting and monitor from one place. |
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
readable**; every push needs your password. **The backup is encrypted before it
leaves** (AES-256-GCM from the `cryptography` package, key from your password,
fresh salt per file, chunked so tampering, truncation and reordering are
detected); without that package nothing is sent. `kos offsite decrypt FILE.kenc
OUT` opens one. Limits: the probe can't tell a private repository from one that
doesn't exist (the push then fails); GitHub sees names and sizes; after a
password change, older files open only with the old password.

### Is everything encrypted? `kos encryption`

It answers layer by layer and does not flatter: **disk** (the root must be on LUKS/dm-crypt), **swap** (absent or encrypted), **RAM** (software cannot
encrypt main memory - the CPU can: AMD SME/SEV, Intel TME/TDX; KOS reports what the CPU offers and what the kernel was asked for, and "unknown" where
only the boot log can tell), **scratch and /tmp** (RAM-backed, so exactly as protected as RAM), **core dumps and hibernation** (off), **secrets in
memory** (locked out of swap, wiped after use, KOS's own processes are non-dumpable and non-attachable) and **off-site backups** (above). On a
machine without those hardware features, RAM and the disk report **NO**, and the fix is named. KOS writes no cipher of its own.

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
