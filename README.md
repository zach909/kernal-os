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

These rules govern every change to KOS. A change that breaks one is wrong.

1. **Everything needs verification.**
   - In the OS: every action goes through `Authority.authorize(action, target)`
     and needs the password typed for *that* action. A new command or feature
     must add its action to `ACTIONS` in `kos/auth.py` and call `authorize`
     before it does anything. A second kind of verification (a `requires`
     dependency, a security scan, a signed seal) adds to the password; it never
     replaces it.
   - In the work: nothing is called done until it has been run and checked.
     Tests pass, or the failure is reported as it is.
   - **Nothing runs unproven.** Every app carries `proof.json`. At install and at
     every launch the OS recomputes the proof from the app's own bytes (`kos/proof.py`);
     no proof, a proof that does not match, code that breaks a rule, code that does not
     compile, or a compiled binary (which cannot be checked) means the app does not
     install and does not run. System apps are apps, so the rule covers them too.
   - **No decimals.** Apps use whole numbers only: no float/complex literals or types,
     no `/` (use `//`), no `Decimal`/`Fraction`, no float-returning `math`, clock or
     random calls. The command protocol refuses any number with a point or exponent,
     and NaN/Infinity.
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
   authenticated. `kos/crypt.py` is the channel (X25519 + HKDF-SHA256 +
   ChaCha20-Poly1305 from the vetted `cryptography` library, keyed by the
   password); where it is and is not used is in the gaps table below.

5. **No decimals, only fractions.** A number that is not whole is a `Fraction`
   (`kos/exact.py`). No decimal literals (`0.5`), no `float()`, no `/` between
   numbers in KOS code: use `//` or `Fraction(a, b)`. Numbers shown to people
   are written `7/2`, never `3.5`. The one place a float may be received is
   the code that reads hardware or a library, which converts it at once with
   `from_hardware` (exact, loses nothing). `kos/rulecheck.py` finds breaches
   and `tests/test_fractions_rule.py` fails if one is added.

6. **Proofs for everything that can be proved.** Where a rule can be stated as
   maths it is proved with the Z3 solver (`kos/proofs.py`, run with
   `python3 -m kos.proofs`), with negative controls showing each proof can
   fail. Where it cannot (a password prompt, a sandbox, a library), it is
   covered by tests that try to break it, and the gaps table says which is
   which. A proof is about a model; the tests check the model against the code.

5. **Everything is separate.** One app, one job. Every function is its own app,
   and anything that has a different screen is a different app: not a tab, a
   mode or a page inside another app. This covers the whole system, not only
   what is drawn: mouse, keyboard, display (screen), desktop background,
   taskbar parts, settings, status views, each tool. A function with no screen
   is still its own program (`kos pack`: one `.kapp` per program).
   - **The `apps/` folder is where the OS's functions live: one folder per function,
     each folder one app** (`apps/mouse`, `apps/keyboard`, `apps/display`,
     `apps/wallpaper`, `apps/taskbar`, ...). An app's code is in its own folder and
     nowhere else: no app code in a shared folder, no logic shared between apps by
     importing it. The one thing an app imports from the OS is `kos.sdk`, the
     protocol client. `tests/test_apps_folder.py` fails on any other `kos` import.
   - Before adding a screen, mode or setting to an app, make a new app.
   - Separate apps do not call each other. They share through permissions and a
     shared folder (`owns:`/`uses:`, `kos grant`), never an app-to-app command.
   - What stays in the OS is enforcement only: the password and its overlay,
     the sandbox, reading the real devices, command validation, drawing to the
     framebuffer. An app for the mouse, the keyboard, the screen or the
     background is a front-end that *asks* the OS (`request`); it never opens a
     device, and the OS decides. The trusted overlay is never an app, because
     an app could cover or fake it.
   - A built-in that is not enforcement and is not yet an app is a gap. List it
     in the table below; do not add to it.

Agent skills for AI agents working on this repo live in `.claude/skills/`:
`kos-rules` (these rules as a checklist) and one per layer of the pipeline -
`kos-graphics`, `kos-input`, `kos-command-protocol`, `kos-kernel`,
`kos-hardware`.

### Where the code does not meet the rules yet

Honest list, so nobody assumes these are covered:

| Rule | Gap |
|---|---|
| Proof gate / no decimals | The "proof" is a **static check against a fixed rule set plus a successful compile, bound to the exact bytes**. It is not a formal proof that an app is secure or correct, and the sandbox is still what contains it. It cannot see: a float made by a standard-library call it does not list (`x ** -1`, `json.loads`, `os.stat` times), code reached by string tricks the banned names do not cover, or what an app imports from the `kos` package (OS code, not in the app's zip, not covered by its proof). Compiled binaries are refused outright, so `kos convert` output (a `.deb` binary) can no longer be installed, and an app installed before this change has no `proof.json` and must be re-packed. The OS's own code is **not** decimal-free: 1,107 uses remain in 63 files (clocks, throttle delays, the office packs). `tests/test_proof.py` holds that to a ratchet (`tests/nodecimal_baseline.json`): it may fall, never rise. OS-side modules are not proof-checked at all; they are what the proof gate is built from. |
| Verification | Still run with no password: `list`, `ps`, `dirs`, `pack`, `help`. `attach` asks for no new password, and `setup` cannot (no password exists yet). What used to show private state without one - `audit`, `activity`, `security`, `doctor`, `firmware`, `owed`, `ls`, `scan file`, `cell list`, `spaces` - is an app now, and asks for the password in the OS's own prompt every time it reads (actions `audit.read`, `activity.read`, `security.check`, `system.read`, `file.view`, `cell.list`, `space.list`). Not tested on real hardware: the OS's prompt on a framebuffer. |
| Connections blocked | **On the KOS kernel,** every connection of every confined app is denied (connect, bind, listen, send to an address) unless the owner added a rule: one app, protocol, direction, IP address and port, typed out, no wildcards. Every allowed and every blocked attempt is logged and copied into the audit log. **Not covered:** (1) a stock kernel enforces nothing - a boot with `kos.require_kernel=1` on the signed command line (the shipped `kernel/cmdline.txt` sets it) refuses to start, and refuses to run any app, without the KOS kernel; (2) only confined apps are covered - connections made by the OS itself, by anything outside the sandbox, and from inside a kernel cell (its guest kernel does not have the module) are not blocked or logged; (3) rules are IP addresses, never names (resolving a name is itself a connection), and a change reaches an app the next time it is opened; (4) the kernel cannot tell encrypted from plain traffic: an allowed address and port can carry anything, and encryption and certificate checks are still enforced only inside the `web` example (`check_url`, `fetch`); (5) the `network` yes/no and the rules are decided when the app is launched, not at first use; (6) the kernel keeps the newest 256 log lines until the core copies them into the audit log (when an app ends, or when the firewall app reads); a burst in between overwrites the oldest and the loss is counted and written. |
| Pipeline encrypted | Nothing is encrypted. The command channel is plain JSON lines over a socket (`Channel` in `kos/protocol.py`). The real exposure is the broker socket (`kos open`/`attach`: any process running as you can connect) and cell vsock. The kernel module's rule and log files (`/sys/kernel/security/kos/`) are local files only the core can open; they are not encrypted either. Encrypting needs a vetted library; the standard library has no authenticated encryption and KOS has no third-party dependencies yet. |
| The KOS kernel | Linux 6.12.116 with `kernel/patches/0001-kos-lsm.patch` (`security/kos`), built by `kernel/build.sh`, which refuses a source tree whose SHA-256 is not the pinned one and fails if any option in `kernel/kos.config` is missing from the final config. **Tested:** `kernel/test/run.sh` boots it in QEMU with a test program as PID 1 - 96 checks that a confined app is refused (sockets, device nodes, ptrace, rule changes) and that the same call works once the core allows it - on a minimal build and on the full hardened build. **Not tested:** real hardware, KVM, any CPU but x86_64, and stacking with SELinux or AppArmor (neither is configured). The module is out of tree and uses LSM id 114, which is not registered upstream; a new Linux version needs the patch rebased. |
| Everything is an app | **Done:** 18 commands are apps - `audit`, `activity`, `security`, `doctor`, `firmware`, `ls`/`cat`/`explore`/`view`, `scan file`, `optimize`/`settle`/`owed`, `cell`, `convert`, `skills`, `grant`/`spaces`. The command line only opens the app (`kos/launchmap.py` lists which); the app asks the OS through the service layer. **Not done:** (1) the OS still has a Python core: the password check, seals and the app loader, command validation and the session loop, the audit chain, drawing and input, `init`. Phase 1 moved only the enforcement of apps' network, device and ptrace access into the kernel; moving more is not started. (2) Kept in the command line because a new machine needs them before any app exists: `setup`, `install`, `update`, `remove`, `permit`, `list`, `help`, `line` (apps with the same jobs exist: Software Updates, Terminal, KOS Help). (3) The OS's own machinery: `run`, `open`, `go`, `ps`, `attach`, `close`, `boot`, `desktop`, `extend`, `dirs`, `admin`, `write`, `usb`, `aios`, `do`, `exec`, `backup`, `pack`, `passwd`. (4) Limits of the converted ones: Files cannot write (a write needs the exclusive administrator keyboard: `kos write`); Skill Maker previews, and `kos skills --out DIR` (which writes the files through the guarded write) stays a command; the Debian Converter still parses the package in the OS, not in the app, and writes its output with a plain create; `scan watch` stays a command because it is a watcher; the Terminal app opens other apps but shows none of their output. |
| Proof gate / no decimals | The "proof" is a **static check against a fixed rule set plus a successful compile, bound to the exact bytes**. It is not a formal proof that an app is secure or correct, and the sandbox is still what contains it. It cannot see: a float made by a standard-library call it does not list (`x ** -1`, `json.loads`, `os.stat` times), code reached by string tricks the banned names do not cover, or what an app imports from the `kos` package (OS code, not in the app's zip, not covered by its proof). Compiled binaries are refused outright, so `kos convert` output (a `.deb` binary) can no longer be installed, and an app installed before this change has no `proof.json` and must be re-packed. The OS's own code is **not** decimal-free: 1,111 uses remain in 64 files (clocks, throttle delays, the office packs). `tests/test_proof.py` holds that to a ratchet (`tests/nodecimal_baseline.json`): it may fall, never rise. OS-side modules are not proof-checked at all; they are what the proof gate is built from. |
| Verification | `list`, `ps`, `activity`, `audit`, `owed` and `cell list` now need the password (`state.view`, refused before anything prints). Still run with no password: `scan file`, `ls`, `pack`, `doctor`, `security`, `firmware`. `attach` asks for no new password. Some of these show private state (`audit`, `activity`). `doctor`, `setup` and `scan file` have a reason to be open (they run before a password exists, or are read-only). The rest do not. |
| Connections blocked | The AI is the first connection the OS makes on an app's behalf and it follows the rule: no endpoint configured means refused and logged (`net.ai` `blocked`), one endpoint only, password per ask, no redirects. Two honest limits: a model on this computer is reached over plain `http://` to a literal loopback address (the bytes never leave the machine, but it is not encrypted, and the rule as written says no plain text); and the API key sits in `<state>/ai.json` (mode 0600, refused if wider) with no cipher beyond the LUKS2 disk, because the standard library has none. The `ask` call blocks the session for up to 30 s. There is still no firewall for anything else. An app's empty network namespace blocks it by default, but the `network` permission is one yes/no at launch that gives the app every host, every port and the ability to listen. Only apps are covered: nothing yet blocks or logs connections made by the OS itself or from outside the sandbox. Privileges are decided at launch, not when first used. Encryption and certificate checks are enforced only inside the `web` example (`check_url`, `fetch`); any other app with the `network` permission can still open plain sockets until connections go through the OS. |
| Pipeline encrypted | Nothing is encrypted. The command channel is plain JSON lines over a socket (`Channel` in `kos/protocol.py`). The real exposure is the broker socket (`kos open`/`attach`: any process running as you can connect) and cell vsock. Encrypting needs a vetted library; the standard library has no authenticated encryption and KOS has no third-party dependencies yet. |
| Everything is separate | **Partly met; most of the OS is still not split.** Done: `apps/` holds the taskbar, App Library, mouse, keyboard, display, wallpaper and the split backup programs, each in its own folder, and a test refuses any shared `kos` import except `kos.sdk`. The mouse, keyboard and display apps are **read-only status screens**: the OS has no settings layer (no pointer speed, key repeat, layout, resolution or brightness), so there is nothing for them to change yet; `request status` is how they ask, it needs no password (like `apps` and `focus`) and a refused ask is not written to the audit log. The wallpaper is only a colour the taskbar fills its own screen with: apps still clear their own canvases and the OS draws no desktop of its own. The taskbar reads it only after `kos grant taskbar space:wallpaper --level read`. **Not done:** `apps/app-library` still imports the shared `kos.office.finder` and holds both the list and the search (search should be its own app); the taskbar still holds the bar, the open-apps list and the pins in one app; the password and boot prompts stay in the OS on purpose (an app could cover or fake them). Most CLI commands (`audit`, `activity`, `security`, `doctor`, `firmware`, `optimize`, `scan`, `spaces`, `permit`/`grant`, `runtimes`, `cell`, `usb`, `folders`, `passwd`, `install`) are OS code with no app in `apps/`, and the office packs in `kos/office/` and `examples/` still ship many functions per app. Apps still live in `examples/` too (`hello`, `web`, `ai`, `backup`). `kos desktop install` now installs and permits six apps, so it asks for more passwords than before. Not tested: the graphical drawing of the new apps on a real screen. |
| Pipeline encrypted | `kos/crypt.py` is a real, tested encrypted and authenticated channel (X25519 key agreement per connection, HKDF-SHA256 with a password-derived secret mixed in, ChaCha20-Poly1305 records, authenticated length, one key per direction, counters that only go up, a close record so a cut connection is detected). 21 tests try tampering, replay, reordering, dropping, reflection, truncation, a wrong password key, hostile headers and counter exhaustion; known-answer tests check the library against RFC 7748 and RFC 8439. **It is not wired in yet**: the command channel (`Channel` in `kos/protocol.py`), the broker socket (`kos open`/`attach`: any process running as you can still connect) and cell vsock are still plain JSON lines. Wiring the broker needs the password-derived key at both ends, which means `attach` would ask for the password (a behaviour change, so the owner decides). Not covered even once wired: message sizes and timing are visible; a stolen password key defeats it; Python may keep copies of keys in memory. It adds a dependency (`cryptography`, in `requirements.txt`, now `>=47` for ML-KEM); KOS had none. Its key agreement is X25519 only, which a quantum computer breaks; `kos/silent.py` (next row) is the quantum-resistant protocol. |
| KOS-SILENT/1 (the one protocol for any connection) | `kos/silent.py`: **built and tested, not wired to any connection yet.** It grants nothing (the only operations are send, receive and close; no record type carries a permission, a name or a request; it opens, binds, listens and accepts nothing, so it is handed a connection the firewall already allowed; it exposes no peer name, id or address; it imports nothing that decides anything - a test fails if that changes) and gives nothing away (no banner, version, length or type in the clear; the handshake is random-looking bytes; every handshake message is 1248 bytes and every record 1040, so a message's size shows only to the nearest record; nothing is negotiated, so nothing downgrades; a peer without the shared secret gets **no reply at all**, and every handshake failure is the same one message). It is encrypted and quantum resistant: **X25519 + ML-KEM-768 (FIPS 203) hybrid, both mandatory and both mixed into every key**, a 256-bit shared secret (`Grant.key`, from the password) mixed into the key schedule and the handshake, ChaCha20-Poly1305 records with one key and one counter per direction, fresh keys per connection (forward secrecy). Built only from the vetted `cryptography` library, which now must be >= 47 (the first with ML-KEM); if it cannot do ML-KEM the module will not import, there is no fallback to X25519 alone. 39 tests in `tests/test_silent.py` try tampering, replay, reordering, dropping, reflection, truncation, unknown record types, bad padding, oversize messages, a wrong secret, garbage and silent peers, a classical-only peer, and a lying ML-KEM or X25519 secret; three mutations of the code (ML-KEM dropped from the keys, an answer to a bad peer, unchecked padding) were each caught. Three size and padding claims are proved in Z3 with negative controls. **Not covered:** (1) nothing uses it yet: the command channel, the broker socket (`kos open`/`attach`) and cell vsock are still plain JSON lines, and wiring the broker means `attach` asks for the password (a behaviour change, the owner decides); (2) both ends must hold the same 32-byte secret, so it links KOS to KOS (and to cells), **not to an ordinary website**, which needs TLS 1.3 with an X25519MLKEM768 group; (3) it does not hide that a connection exists or the IP addresses at both ends, nor when records are sent or how many (no cover traffic): hiding who talks to whom takes a mixnet, a VPN only moves that trust to its operator; (4) a stolen password key lets its holder open new connections (it does not open recorded ones); (5) ML-KEM is young: the hybrid is there so a flaw in either half alone does not break a connection; (6) the replay memory for first messages is per process, the last 4096; (7) Python may keep copies of keys in memory; (8) the ML-KEM and X25519 code is the `cryptography` library's, which is not proved; the Z3 claims cover only the sizes and padding. |
| Fractions (no decimals) | Enforced for new code only. 680 decimal uses already exist in 44 files (mostly `kos/office/` packs: audio, ML, geo, calc, media, and clock/timeout code in `firmware.py` and `cli.py`). `tests/fractions_baseline.json` records them so they cannot grow; none is converted yet. The checker is an AST scan: it misses `a / b` between two plain names (could be a `Path` join) and floats that come from library calls. |
| Proofs | Six claims about the channel are proved with Z3 (nonce never repeats, length header round-trips, sizes fit, counter cannot wrap, replay and skip refused). They prove the model, not the `cryptography` library or Python, and nothing is proved for the sandbox, the password prompt or the firewall. Z3 is a development dependency (`requirements-dev.txt`). |
| Everything is an app | Asking for "everything an app" is **not** met: this change added the AI as an app (`examples/ai`) and the browser's `ask`, and made the core smaller to ship, but did not move any existing built-in out of the OS. `kos ai set|show|clear` is OS code (it holds the endpoint and key, which an app must never see). `kos convert` is built into the OS, not an app, and like `pack` it writes its output with a plain create rather than the guarded `file.write` path. Converted programs have no stdin, no network and no arguments yet, so only simple non-interactive programs are useful. `kos skills` is built into the OS, not an app (an app can't write files, and it needs the command list, which no `request` returns yet). With `--out`, every file is a separate guarded write, so it asks for the password once per file; the empty `kos-app-NAME/` directories are created without the guarded path. The line shell (`kos line`), `ls`/`cat`/`explore`, `scan`, `audit`, `activity`, `optimize` and `settle` are built into the OS, not apps. Only the taskbar and App Library are apps today. |
| Everything is an app | `kos convert` is built into the OS, not an app, and like `pack` it writes its output with a plain create rather than the guarded `file.write` path. Converted programs have no stdin, no network and no arguments yet, so only simple non-interactive programs are useful. `kos skills` is built into the OS, not an app (an app can't write files, and it needs the command list, which no `request` returns yet). With `--out`, every file is a separate guarded write, so it asks for the password once per file; the empty `kos-app-NAME/` directories are created without the guarded path. The line shell (`kos line`), `ls`/`cat`/`explore`, `scan`, `audit`, `activity`, `optimize` and `settle` are built into the OS, not apps. Only the taskbar and App Library are apps today. |
| Modding layers | `kos/overlay.py` merges mod files over a base in an owner-chosen load order (see `docs/MODDING.md`). Nothing reads files through it yet, the CLI's base is empty because KOS has no core file set, and the writable `user` layer is memory only. Most of the wider "modding-centric OS" list (Wasm sandbox, hot-swap with state serialization, watchdog rollback, input hooks, driver processes) is **not built**; that doc says which items and why. |
| Programs | `ask:ACTION` permissions only cover the five `request` actions that touch the backup vault, the app list and the read-only kernel status (`apps`, `backup`, `backup_add`, `backup_remove`, `kernel`). `open`, `close` and `focus` stay inside `system`, which is still all-or-nothing (and all of them at once): a program that opens other apps holds the whole `system` permission. `network` is still one yes/no per program. Programs of one app get separate data folders and share only through `owns:`/`uses:` spaces, but nothing stops you permitting every program of an app, which gives that set of programs the union of their powers. The old single-app `examples/backup` (one program, `system`) still ships and is still the one the older tests cover. `kos install FOLDER` asks the password once per program. Only ordinary apps can be programs, not extensions or mods yet. Not tested: a graphical-mode run of the split backup programs (they have a text page only). |
| Programs | `ask:ACTION` permissions only cover the four `request` actions that touch the backup vault and the app list (`apps`, `backup`, `backup_add`, `backup_remove`). `open`, `close` and `focus` stay inside `system`, which is still all-or-nothing (and all of them at once): a program that opens other apps holds the whole `system` permission. `network` is still one yes/no per program. Apps of one group get separate data folders and share only through `owns:`/`uses:` spaces, but nothing stops you permitting every app of a group, which gives that set of apps the union of their powers. Single-file apps are covered by packing, install and permit tests, but **no single-file app has been run in the real sandbox yet**, and a single-file app must be Python (`app` / `app:FUNCTION`). Permits are now pinned to the file's hash, so updating an app (new bytes) means `kos permit` again; permits made earlier have no pin and are unrestricted. The 200-character id limit is the only bound on group depth. The old single-app `examples/backup` (one program, `system`) still ships and is still the one the older tests cover. `kos install FOLDER` asks the password once per app. Only ordinary apps can live in a group, not extensions or mods yet. Nesting apps inside a folder app (the older `mail.compose.attach` layout) is now refused; use a group. Not tested: a graphical-mode run of the split backup programs (they have a text page only). |
| Org blueprint | `docs/ORG_BLUEPRINT.md` maps the "organization-centric OS" blueprint to KOS. Only the parts that fit inside one sandboxed app exist: Semantic Graph and Rule Router (`kos/office/pack_org.py`). The semantic object kernel, graph file system, matrix workspaces, state snapshots, data bus, structured pipes, component apps and the kernel event router are **not built** (they need the kernel, a window manager or cross-app access). Both apps keep data in clear, bounded, and their hash chains are not signatures. |
| Cookies and passwords | `cookies` and `passwords` are manifest permissions (`kos/kapp.py`). Each unlocks its own OS-kept store (`<state>/appdata/<app>/cookies/`, `.../passwords/`) through the `vault` command's `store` field (`secret_put/get/keys/delete` in the SDK). `storage` does not reach them and they do not reach `storage`; an app without the permission is refused and the refusal is logged, as is every use (the key name, never the value). `kos secure` lists which permitted apps hold them, and a manifest update that adds one is refused until you permit again. **Not covered:** values are stored **in clear** on the LUKS2 volume (the same gap as the vault): there is no password-sealed encryption, because KOS has no vetted authenticated cipher and adding one is the owner's decision. Reading them does not ask for the password (the run permit and the password at launch still apply). Nothing in the browser (`examples/web`) uses them yet, so there is no cookie handling or login filling. Not tested: a real sandboxed app using them. |
| File summaries | Every user file has a text summary (`kos/summary.py`): vault and shared-folder items (a `.summaries/` folder beside them, rewritten on each put, removed on delete, created on first ask for older items), `kos write` (printed, stored by content hash under `<state>/summaries/`), and backed-up files (stored the same way, shown by `kos backup list`). File search indexes the summary and shows it first. The summary is the kind, size, shape and a quoted start ("PNG image, 64x48 pixels", "text drawing, 3 lines"): it does **not** describe what a picture shows, which would need a model. Text is summarised too, with no exemption; the quoted start is untrusted and cleaned. **Not covered:** apps cannot ask for a summary (no `vault` protocol op, so no new message to validate yet); files an app only ever saw through `kos ls`/`cat`/`explore`, or anything written outside these three paths (for example `kos convert`, `pack`, and the OS's own plain writes), get none; summaries of removed backups and overwritten `kos write` files are not pruned; a summary is only as old as the last write, so a file edited outside KOS is stale until it is written again. |
| Pictures | `kos/vectorize.py` turns pixels into `rect`/`line` ops, it is not an image codec. Small, flat pictures (icons, pixel art, diagrams) are exact; a photo is posterised and blocky because it must fit 5000 ops, and the cap on input is 512x512 pixels. No antialiasing or alpha, and no file decoding (PNG/JPEG): the app hands it rows of colours. Tested through the real `Framebuffer` and the protocol validator, never on `/dev/fb0` or the terminal backend, and no existing app uses it yet (the image editor still exports files only). |
| Search box | The Ctrl-N box and the App Library's `/` search (`kos/office/finder.py`) only *show*: a command hit is the line to type, never a run, and an app hit is a `request` the OS still asks your password for. File search covers only what the app can already read (its own vault plus the shared folders it was granted), at most 200 items and 20,000 characters each per place, and never keys that look like credentials (`llm`, `api_key`, `token`, `password`, ...), the agent's chat history or exports. That filter is a **name pattern, not a classifier**: a secret stored under an ordinary key name (say `note-7`) would be searchable by that same app. The App Library has no files of its own, so it searches apps and commands only, and its "Ask the assistant" row opens the `ai-assistant` app but cannot hand it your question. The command list is a generated table (`python3 -m kos.office.cmdindex --write`); a test fails if it drifts from `kos help`. Not tested: the graphical-mode drawing of the Ctrl-N box. |
| Graphics frames | `kos/display.py`: graphical frames are queued and drawn in order onto the scene already on screen (the last frame, changed), not swapped in whole. Each render has a 30 ms drawing budget; once it runs out, only *big* ops (clipped bounding box of at least 1/16 of the screen, a `clear` always) are applied and small ones are dropped for good, so a dropped small change stays missing until the app redraws that area. Lines and text count by bounding box, so a thin line is always "small". An app that relied on each frame starting blank must now send `clear`. Not tested: timing on real hardware (`/dev/fb0`) or the terminal backend, and the 30 ms budget is a guess, not measured. |
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
| Debian conversion | `kos/debconv.py`, `kos/debshim.py`, the Debian Converter app (`kos convert`): a `.deb` becomes a `.kapp`. The package is read in memory only (never unpacked to disk), bounded and path-checked, and the result is scanned; a flagged or unconvertible package is refused **before** any password prompt. The password (`app.convert`) is needed to write the file, and `kos install` then scans again, asks again and seals. **Maintainer scripts are never run and never kept.** Only **statically linked** programs convert (dynamic ones are refused with the package's `Depends` shown); symlinks and devices are dropped; setuid bits are stripped; the app gets **no permissions**. A small shim runs the program from a sealed in-RAM file with no stdin, a 10 s limit and a 64 KiB output cap, and shows its output as a text page. |
| Skill maker | `kos/skillmaker.py`, the Skill Maker app (`kos skills`; `kos skills --out DIR` writes the files and stays a command): one skill for the commands (read from the real parser) and one per installed app. One password (`skill.make`) verifies every app's seal first; a tampered app is skipped. Each file is scanned, and a flagged app skill is left out. An app's free-text description never reaches the instructions - it sits in one inert, labelled data block. Printing writes nothing; `--out DIR` writes each file through the guarded `file.write` path. |
| Password on everything | `kos/auth.py`: scrypt-derived master key; every action (`app.run`, `device.mouse`, `file.view`, ...) needs the password typed for *that* action. All decisions go to an audit log (`kos audit`). |
| Debian conversion | `kos/debconv.py`, `kos/debshim.py`, `kos convert`: a `.deb` becomes a `.kapp`. The package is read in memory only (never unpacked to disk), bounded and path-checked, and the result is scanned; a flagged or unconvertible package is refused **before** any password prompt. The password (`app.convert`) is needed to write the file, and `kos install` then scans again, asks again and seals. **Maintainer scripts are never run and never kept.** Only **statically linked** programs convert (dynamic ones are refused with the package's `Depends` shown); symlinks and devices are dropped; setuid bits are stripped; the app gets **no permissions**. A small shim runs the program from a sealed in-RAM file with no stdin, a 10 s limit and a 64 KiB output cap, and shows its output as a text page. |
| Skill maker | `kos/skillmaker.py`, `kos skills`: one skill for the commands (read from the real parser) and one per installed app. Every app can ship a `help.json` (its own help command: `{"about", "commands": [{"name", "help"}]}`, validated in `kos/kapp.py`, never run); the skill maker puts it in the app's skill as a second inert data block. **Not enforced:** an app without `help.json` is still valid and its skill says it has none; only `examples/hello` ships one so far. `kos help APP` does not read it (reading needs the seal check and password). One password (`skill.make`) verifies every app's seal first; a tampered app is skipped. Each file is scanned, and a flagged app skill is left out. An app's free-text description never reaches the instructions - it sits in one inert, labelled data block. Printing writes nothing; `--out DIR` writes each file through the guarded `file.write` path. |
| Apps as administrators; the kernel as an app | **`admin` permission** (`kos/system.py`, `request admin` / `request write`, `examples/admin-write`): an app can ask the OS to write a file as the administrator. It is not root and cannot write itself; the OS refuses before any password unless the administrator keyboard is booted on a capable kernel, then the password prompt names the app and the file, then the guarded `write_file` runs (scan, quarantine on a hit, disk optimize, nothing owed). Paths must be absolute and free of control characters, KOS's own state and symlinks are refused, one write is 200,000 characters at most. `admin` is not part of `system`, never rides in on an extension or mod, is pinned by `kos permit`, and is recorded on the instance from the verified manifest at open time. **`kernel` app** (`examples/system/kernel`, permission `ask:kernel`): a read-only window onto what Linux protects, the cells and the administrator keyboard; it can ask that one question and nothing else. Honest limits: the kernel's *enforcement* (the sandbox, Landlock, namespaces, KVM) is not an app and cannot be, since an app cannot confine itself, so only its status is. The kernel app cannot start or stop a cell yet. **Not tested on hardware:** on a real exclusive lease the write needs the keyboards taken for the one action; if the desktop session already holds them the write is refused (fails closed), so admin writes from a running desktop are not proven to work on real hardware. Tested with the development weak lease only. An app that holds `admin` and is permitted can overwrite any file the owner types the password for; the password prompt is the only guard on what, so read the path. The command channel is still plain JSON (see the encryption gap). |
| AI in the OS | `kos/ai.py`, `request ask`, `examples/ai`, the browser's `ask`: an app never talks to a model, it asks the OS. Needs the `ai` manifest permission (an extension or mod cannot have it; it grants no `system` power). One endpoint, chosen with `kos ai set` (password): `https` with the certificate checked, or `http` to a literal loopback address for a local model. Each ask needs the password, and the prompt names the app, the host and how many characters leave; `ai.ask` and `net.ai` go in the audit log. The model has no tools and its answer is plain text lines, so nothing in it can open, run or write anything; text an app hands over (a web page) is fenced as untrusted data, which lowers prompt injection but cannot remove it, which is why the answer can do nothing. |
| Lean build | `packaging/lean.py`, `python3 packaging/build_deb.py --lean`: package `kernal-os-core` is only the OS core (`bin`, `kos/*.py`, the two system apps) with docstrings and comments stripped and xz compression. 89 KB (89,152 bytes), against 398 KB (397,602) for the whole repository. Raw stripped core source is about 345 KB. The Python interpreter and the Linux kernel are not counted: KOS is a layer on them, so the whole system is not kilobytes. The whole test suite passes against the stripped sources (`KOS_LEAN_FULL=1`). Reproducible with the same Python only. |
| Password on everything | `kos/auth.py`: scrypt-derived master key; every action (`app.run`, `device.mouse`, `file.view`, ...) needs the password typed for *that* action. All decisions go to a tamper-evident audit log: hash-chained, with every grant anchored to your password (`kos audit`, `kos audit --verify`). |
| 7 KiB core (`micro/`) | `micro/`, `make -C micro check`: a separate C99 core with the KOS rules in miniature (password for every action, bytecode apps verified at every launch, default-deny requests, audit ring, hostile-input checks) in **512 bytes of RAM** measured on the host (globals 248 + peak stack 264) against a 7,168 byte budget, fuzzed under ASan/UBSan. **Not covered:** never run on a real microcontroller or emulator; no encryption; no password hashing (the board supplies `hal_pw_check`); no network or firewall; no persistence or installer; no hardware memory protection. See `micro/README.md`. |
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
| The OS is made of apps | `kos/desktop.py`, `kos/system.py`, `apps/`: the **taskbar** and the **App Library** are ordinary sandboxed apps. They never touch the screen or other apps - they *ask* the OS with a `request` command (needs the `system` permission in the manifest + a permit; opening/closing needs your password in the OS's own prompt). The **right mouse button is the App Library**, handled by the OS from any app. |
| Elevated administrator keyboard + **requires** | `kos/admin.py`, `kos/requires.py`: *requires* is a dependency, not an action. **Unlocking requires the elevated administrator keyboard, which requires the kernel**: the unlock password boots the keyboard (a lease signed with a password-derived key, bound to this boot) and if the kernel protections are missing the computer simply does not unlock. **Writing a file requires a security scan and a disk optimize afterwards**: the write is recorded on a ledger as owing both, they are done in order under the same password, and anything left owed (a crash, a failed step) survives restarts and blocks the next write until `kos settle`. |
| Backups (the backup app) | `kos/backup.py`, `examples/backup`: **content-addressed, deduplicated** backups. A file body is stored once under its SHA-256 no matter how many names or times it is added; every file is **scanned before it is stored** (flagged files never enter the vault); `add`/`list`/`remove`/`restore` each need the password; the index is HMAC-sealed with a password-derived key and every body is re-hashed when read, so tampering is refused. **Restore is a write**, so it goes through the guarded write (admin keyboard, scan, optimize) and never overwrites. The `backup` app is a sandboxed front-end that can't read files itself - it *asks* the OS (`system` permission) and the password is typed in the OS's own prompt. |
| Standard data folders | `kos/folders.py`: `kos folders create` (password) makes 27 shared folders in four groups (user data, system, apps, security) in the permission store, owned by `@os` - not a valid app name, so no app can claim one with `owns:`. Every one is closed until you grant an app (`kos grant APP space:documents --level read`). `kos folders` lists them without a password. **Not covered:** a folder holds what an app puts in it, nothing moves in by itself; nothing reads the real keychain, boot sector or settings into the matching folder; data is plain files in a 0700 directory on the LUKS2 disk (no cipher of its own); `sensitive` is a label, the same password rule applies to all. See `docs/INTEGRITY_BLUEPRINT.md` for the bare-metal, memory and key-capture parts of the larger blueprint, which are **not built**. |
| Apps backed up as addresses | `kos/applinks.py`: `kos backup link APP https://...` stores the app's name, version, address and SHA-256 (a few hundred bytes) instead of the app. `kos backup fetch APP` downloads it, **refuses it unless the SHA-256 is the pinned one**, then installs through the normal install (scan, then the password again). Password on `link`, `links`, `unlink` and `fetch`; the index is HMAC-sealed; https only with certificate and host name checked, no redirects, 512 MiB cap, every attempt logged as `net.applink`. **Not covered:** this is the only connection KOS makes to an address an app-owner typed, and it is a per-command allow, not a firewall rule; the hash proves the bytes are the ones linked, not that they are safe; a link is not a copy, so if the server drops the file the app is gone; the address is not checked when linked, only when fetched; a fetch refuses an app that is already installed instead of updating it; tested with a fake server and the real opener's settings, **not** against a live https server. |
| AI OS: KOS is the engine | `kos/aios.py`: four layers only - the graphical button clicker (`gui`), terminal app commands (`app`), kernel commands (`kernel`, NeuroClaw's Linux permission tools) and the auto skill maker (`skill`). KOS carries a request to the NeuroClaw engine on this computer and asks for no password; the engine's own tool gate and approvals decide what happens. Nothing else of NeuroClaw is reachable, nothing autostarts, and the engine address must be loopback. |
| Security check | the Security Check app (`kos security`, `kos/secure.py`): one read-only check that changes nothing and asks for the password (`security.check`) because what it reports is private, nothing running in the background. Kernel protections, private folders and secrets, audit-chain integrity, every installed app rescanned and compared with what was installed, permissions nothing uses any more or that were never pinned, owed work, crash leftovers. Exit code 3 if anything failed. |
| Firmware control (no ME, PSP or BMC in charge) | `kos/firmware.py`, `boot/initramfs/firmware.sh`: before the disk is unlocked, and again in `kos-init`, KOS looks for management processors that run below the OS - **Intel ME/AMT, AMD PSP, server BMCs (IPMI)**, and every other chip with its own firmware (Thunderbolt/USB4, USB-C port controller, embedded controller, network, GPU, NVMe, wireless), plus a missing IOMMU. If one is running it alerts, cuts the OS's side of it (unbinds the driver, forbids rebinding) and **refuses to boot**. Only an Intel ME whose own status register says *disabled* is believed off. `kos.firmware=warn` on the signed kernel command line boots anyway. **This cannot switch them off** - see the limits in `docs/ARCHITECTURE.md`; almost no real hardware will boot under the default policy (VMs will). There is no resident checker: it runs once at boot and at each unlock. An owner-written allow list (`boot/firmware.allow`, `/etc/kos/firmware.allow`) accepts chips whose firmware you replaced yourself; KOS never flashes anything. `kos firmware` also lists which protections (IOMMU, memory encryption, LUKS2, Thunderbolt security) narrow what the remaining chips can see. |
| Hardware map (every device and connection) | `kos/hardware.py`: `kos hardware scan` (password, action `hardware.scan`, audited) reads sysfs read-only and writes `<state>/permissions/hardware/{devices,links,scan}.json`: every device with its subsystem, driver and parent, and the connections between them - `bus` (a device and what it hangs off, with PCIe link speed/width and USB port path), `dependency` (the kernel's supplier/consumer links) and `devicetree-endpoint` (declared port-to-port wiring on boards that have a device tree). Each record has a `resource` name (`hw:...`, `hwlink:...`) in the permission store's naming style. A second scan reports what appeared or went away. **It cannot see solder joints, PCB traces or pins - no kernel interface exposes them - nor what is at the far end of a port (a live network `carrier` is not an identity), nor individual GPIO lines (only the count per chip; naming a line needs an ioctl on a device file, which the OS does not open without the password), nor devices the firmware hides.** Serial numbers and MAC addresses are never read; strings a device supplies are stripped of control characters and capped. Virtual devices (`/sys/devices/virtual`) are left out. **Not done:** the `hw:` names are only names - no grant is checked against them and no app-facing command reads the map, so apps cannot use or even see it yet; it is one scan, not a resident watcher, so a device plugged in later shows up only at the next scan; the checksum in `scan.json` catches a half-written or edited map, not an attacker who can write the folder. **Tested:** a fake sysfs tree (including hostile strings, symlink escapes, caps and cut-short scans) and this VM's real sysfs (virtio, ACPI, PCI). **Not tested on real hardware:** USB sticks, Type-C ports, Thunderbolt, GPIO chips, real PCIe link speeds, the supplier/consumer (`devlink`) layout (this kernel had none) and the device-tree endpoint graph (synthetic trees only, written from the kernel's documented layout). |
| Open apps like websites | `kos/address.py`: `kos go kos://web/example.com/news` opens the app `web` and tells it the path, the way a browser opens a site. `run` and `open` take addresses too; an app can ask for one with a `request`. Addresses are checked strictly (no other schemes, `..`, `%`, `#`, whitespace or control characters) and the path is *data for the app*, never a file name or a command. |
| Mod file overlay | `kos/overlay.py`, `kos overlay`: mods ship files under `overlay/`; the OS merges them over a read-only base at read time, last in the load order wins, `X.kos-delete` hides a file, writes are copy-on-write in memory, `core/` is protected. Order changes need the password (`overlay.order`). |
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

* **Where the requirements live:** a program's `manifest.json` (name, modes, permissions) sits in its own
  folder. Its `name` must be exactly its folder path with dots (`apps/backup/add/` is `backup.add`), or
  packing is refused, so a program cannot take another program's or app's name. Up to four levels.
* **A program's zip holds only its own folder.** The folders of its sub-programs are left out. Plain
  resource folders (`assets/`) stay in.
* **Permissions are per program.** `kos permit` records what *that* program's manifest asked for; an
  update that asks for more is refused until you permit again. Permitting one program permits no
  other. Beyond `network` and the shared-folder permissions, a program may ask the OS for single
  things with `ask:ACTION`: the OS gives it a bridge that answers only those and refuses the rest
  (audited as `bridge.ask`) before any password prompt. `system` is every request and stays for apps
  like the taskbar; an extension or a mod cannot hold `system`, `admin` or any `ask:`.
* **Programs do not share anything by name.** Each has its own cache, data and run folders
  (`kos dirs backup.list`). They meet only in shared folders (`owns:` / `uses:`), which still need a
  grant for each program.
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
kos backup link APP URL      back up an app as its https address + SHA-256 instead of its bytes
kos backup links / fetch APP / unlink APP   list the links / download+verify+install one / forget one
kos folders [create]         the 27 standard data folders (create needs the password)
kos owed / kos settle        what earlier writes still owe / do it now
kos exec --code LINE         run one line of code as a sandboxed command (--lang=ruby etc.)
kos runtimes                 which languages code can run in (password); add NAME PROGRAM / remove NAME
kos do WORDS...              one line of human language, run as one command
kos line [--explain]         the line shell: every line you type is a command
kos cell                    opens the Kernel Cells app: start, list and stop cells
kos aios status             the four AI OS layers and whether NeuroClaw answers
kos aios gui|app|kernel|skill WORDS...   one request on one layer (no password)
kos usb list|check|write|test   boot from a USB stick: write an image to one safely (see below)
kos doctor                  which kernel protections this machine has
kos audit [--verify]         every password decision; --verify checks the log for tampering
kos security                 check everything KOS can verify about itself (no password, read-only)
kos firmware                management processors (Intel ME, AMD PSP, BMC) and whether the OS would boot
kos firmware plan           read-only advice: which blocking chips have open firmware, which must be disabled or allow-listed
kos hardware scan           (password) map every device and connection the kernel can see into <state>/permissions/hardware/
kos hardware [show|links] [TEXT]   (password) list the saved devices, or the connections between them
kos audit                   every password decision
```
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

**Pictures.** KOS has no image command: a frame is `clear`, `rect`, `line` and
`text` only, at most 5000 ops. An app that wants to show a picture turns the
pixels into geometry first, with `Canvas.image(rows_of_pixels, x, y, scale)`
(`kos/vectorize.py`, standard library, app side; the OS core is unchanged and
still validates every op). One background `rect`, then each row cut into runs
of one colour, identical runs on consecutive rows merged into one box, boxes
one pixel thin sent as `line`s. A picture too busy for the budget degrades
(fewer colours, then blockier) instead of overflowing; the returned
`Vectorized.lossless` says which you got.

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
kos> @ruby puts 6*7             -> ruby, in the same sandbox: 42
```

Human language: the words are only *names for existing commands*; each one
still asks for the password exactly as `kos ...` does. The first meaningful
word is looked up in the lexicon (politeness words and articles skipped,
case/accents ignored, CJK matched by prefix); otherwise "I don't know that
command" with a did-you-mean. Shell command names (`ls`, `cat`, `kill`) are
not words in the lexicon - they are code.

Code: detected by syntax, scanned, then run as a one-shot sandboxed app with a
password and a 10 s limit. Python runs as an app; every other language is a
**row in a table** (`kos/runtimes.py`): a trusted interpreter plus one argument
list. Built in: JavaScript (node), Ruby, Perl, Lua - each only if its program is
installed *and* trusted (a regular file, owned by root or you, that nobody else
can change, in a directory nobody else can change). They run directly under the
same sandbox (no files, no network, private scratch directory, 10 s limit,
64 KiB of output, control characters shown as `\x1b` not obeyed, children
killed with them), about 20-40 ms a line. Say which language with
`@ruby puts 1+1` (the line shell guesses Python/JavaScript/SQL/C... by syntax).
`kos runtimes` lists languages; `kos runtimes add NAME PROGRAM [--arg=-e --arg={code}]`
adds one (password; the program's SHA-256 is pinned and checked on every run, and
`{code}` must be one argument right after a flag so code can never be read as
a flag); `kos runtimes remove NAME` removes it (password). A language with no
runtime (C, SQL, shell...) is still a command - understood, scanned, logged - and
says so. `kos line --explain` shows how each line was understood.
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
kos desktop install       # once: packs, scans, installs and permits the six apps in apps/ (each asks)
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

Every function of the OS is its own folder in `apps/`, and each folder is one app
(rule 5): `taskbar`, `app-library`, `mouse`, `keyboard`, `display` and `wallpaper` today.
Open the mouse, keyboard or display app from the App Library to see how the OS reads
it; they only show state, because the OS has no settings to change yet. The wallpaper
app picks the desktop colour and keeps it in its own shared folder; the taskbar uses it
once you run `kos grant taskbar space:wallpaper --level read`.

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
* **Programming languages (this round):** the language table (`kos/runtimes.py`) and its
  guards (hostile argument lists, untrusted or swapped programs, a damaged registry), and
  Perl run for real inside the sandbox (reads, writes and network refused; runaway, flooding and
  terminal-escape output; children killed; a pinned custom language refused once its program
  changes); node and ruby were also run by hand through the same path. **Not covered:** C, SQL,
  shell, Java, Rust, Go (no sandboxed runtime: compiling needs a compiler inside the sandbox);
  the interpreter's own bugs (a language runtime is a large attack surface and the sandbox is the
  only wall); a program swapped *between* the SHA-256 check and its start (the check is by path,
  not by file descriptor); running as an unprivileged user (the dev container runs as root, where
  the sandbox drops to `nobody` and a scratch directory under root-only parents is unreachable for
  both Python and these languages); lines do not share variables or state.
* **Written but not yet booted:** exclusive evdev capture for the admin
* **Written but not yet booted on real hardware or QEMU:** `kos usb` end to end on a real stick (its logic, refusals, byte-for-byte verify and the QEMU argv are unit-tested), the USB kernel options, exclusive evdev capture for the admin
  keyboard, the graphical desktop (`boot desktop --graphical`), the initramfs, kos-init as real PID 1, the
  image builder (including its new bytecode precompile step, which only had its syntax and its `compileall` command checked), framebuffer/evdev on real hardware, starting KVM cells (no
  KVM in the dev container).
* The userland is Python (stdlib only) to move fast. Python can't fully wipe
  secrets from memory; the security core should be ported to Rust.

See `docs/ARCHITECTURE.md` for the threat model and `docs/IDEAS.md` for the
running backlog of what's next.
