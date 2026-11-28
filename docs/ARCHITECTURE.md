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

## Firmware control (`kos/firmware.py`, `boot/initramfs/firmware.sh`)
Rule: the OS must be in control of the machine or it does not boot. Intel's
Management Engine (with AMT), AMD's Platform Security Processor and server BMCs
are separate computers that start before the OS and keep running under it.
1. **Scan** (sysfs only): PCI `8086` class `0780` = Intel MEI, `1022` class `1080` = AMD PSP,
   DMI type 38 or `/dev/ipmi*` or `/sys/class/ipmi` = BMC. The pre-boot shell script and the
   Python module implement the same scan; `tests/test_firmware.py` runs both on the same fake
   sysfs and requires the same verdict.
2. **Alert**, then **mitigate**: unbind the driver and write a nonexistent name to
   `driver_override`. The device is *left visible* so a later scan cannot mistake "we hid it"
   for "absent". Mitigation never changes a verdict.
3. **Verdict**: an Intel ME is believed off only if HFSTS1 (PCI config 0x40) bits 19:16 read 3
   (disabled). Any other mode, an unreadable register, a PSP or a BMC is "running" and stops
   the boot (`enforce`, the default and the result of any unknown value). `kos.firmware=warn`
   in the signed command line continues after alerting. PID 1 ignores the environment; a dev
   run honours `KOS_DEV_FIRMWARE=warn`.
4. Placed twice: in `/init` before the disk or the password, and in `kos-init` before the login
   prompt; also a `before` of `session.unlock` in `requires.py`, so every unlock re-checks.

Limits, stated plainly:
* **The OS cannot disable these.** They have their own CPU and flash. KOS only detaches itself;
  the ME keeps its memory access and (with AMT) its network path. Actually disabling means the
  flash (`me_cleaner`/HAP, coreboot, a BIOS switch), done offline; the boot gate never writes flash (the separate `kos/fwflash.py` flasher can, for images you sign; see README).
* **Almost no physical machine boots under `enforce`.** Besides the ME/PSP/BMC, any chip with its own
  firmware blocks it too: Thunderbolt/USB4, USB-C port controller, embedded controller, and network, GPU,
  NVMe and wireless controllers (PCI classes in `FIRMWARE_CLASSES`), and so does DMA hardware with no
  IOMMU. These are not unbound (that would break the machine); the strict IOMMU in `kernel/cmdline.txt`
  confines them. VMs ignore the emulated ones. Use `kos.firmware=warn` to boot with the alert.
* **Power-down for optional chips.** Thunderbolt/USB4 and wireless controllers are unbound and asked for D3cold
  (`d3cold_allowed`, `power/control=auto`); they stop blocking only if `power_state` then reads D3cold, in both the
  shell and Python scanners. The ME, PSP, EC, GPU, NIC and boot NVMe cannot be powered down on a running machine.
  KOS does not erase, corrupt or overvolt anything, and the gate does not rewrite other chips' firmware. `kos/fwflash.py` is a separate, password-gated flasher that writes only the system flash; every other chip class refuses.
* **`kos firmware plan` is read-only advice**, from a static table (`PLAN`): per blocking chip, whether open firmware
  exists (coreboot + me_cleaner for some Intel boards, OpenBMC for some servers, open EC for Framework/Chromebook/
  System76; none for PSP, USB-C/Thunderbolt, NIC, GPU, NVMe), and a verdict on whether this machine can pass. The OS
  cannot verify any of it on the hardware in front of it, and flashing is a separate step (`kos/fwflash.py`, system flash only).
* **`kos.machine=framework`** (signed command line, shipped off) refuses to boot on anything whose DMI `sys_vendor` is
  not `Framework`. The vendor string is what the firmware reports: it prevents mistakes and swapped hardware, not a
  hostile BIOS. The allow list cannot waive it. Turning it on makes VMs and the QEMU flow refuse to boot.
* **No resident checker.** The gate runs once at boot and at each unlock; no daemon, loop or watcher.
* **Absence is unprovable.** A BIOS may hide the ME's PCI function; on bare-metal Intel/AMD with
  nothing visible KOS prints a caveat and boots.
* The HFSTS1 decoding follows coreboot/intelmetool and is untested on hardware here; the tests use
  synthetic config space. The kernel config also drops the in-kernel MEI, CCP and IPMI drivers.

## The KOS kernel and the services (`kernel/`, `kos/kernel.py`, `kos/firewall.py`, `kos/services.py`)
KOS runs on its own patched Linux (docs/KERNEL.md). PID 1 claims the **core** once per boot
(`init.kernel_gate`); every app launch then gets a never-reused id from `kernel.AppIds` and its
firewall rules from `firewall.prepare_launch` *before the fork*, and the child confines itself first
thing in `SandboxPolicy.preexec` (one way: inherited, survives `exec`). On exit the owner's rules for
that id are revoked and the kernel's log is copied into the audit log (`SandboxPolicy.on_exit`, run by
whoever owns the process: `cmd_run` or the broker). On a boot with `kos.require_kernel=1` a missing
module stops `init` and makes `SandboxPolicy.probe` refuse every app.
Gap: the module governs only confined tasks, so the OS's own connections, processes outside the
sandbox and kernel cells are unprotected; it cannot tell encrypted from plain traffic.

An app asks the OS for its own functions with `{"cmd":"service",...}` (`servicespec.SPECS` is the whole
list). `ServiceHost.call` runs, in this order, before any handler: the schema check, the manifest
permission `service:GROUP`, and then the handler asks for the password in the OS's own prompt before it
reads anything; the reply is scrubbed of control characters and size-bounded. The OS's own commands are
apps built on this (`kos/office/pack_system.py`); `kos/launchmap.py` says where each of the 45 commands
lives. Gap: the Python core (password check, seals, loader, protocol validation, session loop, audit chain,
drawing and input) is still there; only the enforcement of apps' network, device and ptrace access is in
the kernel.

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
fs+net+signal scoping, a seccomp denylist on x86_64, one private writable cache dir) → only a command
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
wiped cache dir. Python is the fast path. Other languages are rows in
`kos/runtimes.py` (trusted interpreter + one argv template; custom ones are
added with `kos runtimes add`, password, SHA-256 pinned); they run directly
under the same `SandboxPolicy` with a scratch dir, timeout and output cap.
A language with no row reports that and runs nothing. Everything the shell can start still passes
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

## Backups (`kos/backup.py`)
Why it is OS-side: an app is sandboxed (no file reads, nothing persists, no
network by default), so it cannot back anything up. The engine runs as KOS
itself; the `backup` app only sends `request` commands (`backup`, `backup_add`,
`backup_remove`, schema-checked in `protocol.py`, handled in `SystemBridge`).
Each one needs the `system` permission *and* the password in the OS prompt.
Vault: `<state>/backup/blobs/ab/<sha256>` (0600) + `index.json` carrying an
HMAC under `subkey(master, "backup-index")`. Items are counted, not
ref-counted: a body is deleted when no item names it. The index is written
before a body is deleted, so a crash leaves an orphan body, never a dangling
item. KOS's own state (`etc`, `state`) is never read into the vault.
Gap: bodies are plaintext on disk (protected by LUKS2 + 0700, not per-file
crypto); no off-box copy, so this is not a disaster-recovery backup yet.
## App folders, permissions and shared spaces
`appdirs.py` gives every app `<state>/appdata/<app>/{cache,data,run}`. **cache** is the per-run scratch the
sandbox may write, wiped by whoever owns the process when it ends (`cache.py`, unchanged in behaviour but now
under the app's own folder). **data** is the vault (`vault.py`): the app's private, durable text items.
**run** holds the live instance record, socket and log (`registry.py`, `system.py`); the registry globs
`appdata/*/run/*.json`. Only `cache/<run>` is ever handed to the sandbox as writable.

`permissions.py` is the one universal store, `<state>/permissions/grants.json`: entries `{app, resource, level}`
with resources `run` and `space:NAME` and levels `use < read < write < own`. The run permit (`permit.py`) is
just resource `run` plus the manifest permissions the owner approved (`declared`); `check_declared` refuses to
start an app whose manifest has since grown (e.g. gained `network`). Old `<state>/permits/*.json` files migrate
on first read.

`spaces.py` (`AppStorage`) is what a session holds for its app, built by `cli._vault_for` from the verified
manifest: `storage` opens the private data; `owns:NAME` creates/uses the shared folder
`<state>/spaces/NAME/` and records `own` for the app the first time; `uses:NAME` needs a `read`/`write` grant
in the store. Both the manifest and the grant are required, a name already owned by another app is refused,
and every access still goes through `Vault` (plain-name keys, 400k chars / 500 items / 64 MiB caps).
Wire: `{"cmd":"vault","op":"put|get|list|delete|spaces","id":N,"key":..,"value":..,"space":..}`, validated by
`protocol._vault`, executed by `Session._on_vault`, with `sdk.App.vault_*(…, space=)` as blocking round trips
that keep any other event that arrives meanwhile, and `vault_error` saying why a call was refused.
Gaps: values are clear text on the (LUKS2) volume, not sealed with the password-derived key (the session
does not hold the master key while an app runs); grants are by app *name*, so they rely on install/permit
being the trust boundary (a reinstalled app of the same name inherits them - revoke with `kos permit --revoke`
or `kos grant --revoke`); the instance socket path is now `appdata/<app>/run/<id>.sock`, which stays under
the 108-byte limit for real `/var/lib/kos` roots but can exceed it for deep dev `KOS_ROOT`s; cells get no vault.

## Audit log (`AuditLog` in `kos/auth.py`)
Every line commits to the one before it: `p` is the previous line's `h`, and `h = SHA-256(p, entry)`. Editing,
deleting or reordering a line breaks the chain from there on (`kos audit --verify`, and `kos security` without a
password). A line written while the password was in hand (a grant) also carries `m = HMAC(key, h)`, where the key
is derived from the password. Anyone running as the owner can recompute a plain chain; nobody can recompute `m`
without the password, so the likely cover-up - delete a failed attempt, re-link what follows - makes every later
grant's anchor fail. A grant whose `m` was removed is itself reported.

Appends are serialised with `flock` plus an inode re-check, because `kos optimize` trims the log by replacing the
file: without that, two processes could fork the chain and a record made during a trim could be written to the
old file and lost. Tests hold both properties (and fail within three runs if the lock is removed). `kos audit` and
`kos activity` read only the tail of the file.

Limits, stated plainly: cutting the end off the log is not detected, a forger who also relabels every grant is not
caught, and after `optimize` the chain is checked from the first line that is left. Lines from before the chain
existed stay readable and are reported as unprotected. A damaged log never blocks recording a decision; `verify`
reports the damage.

## Security check (`kos/secure.py`)
`kos security` is one read-only pass, run when asked (no daemon, same rule as everything else): kernel
protections, private folders and secrets (modes), audit-chain integrity, every installed app rescanned and its
bytes compared with the hash recorded at install, grants for apps that are not installed (a reinstalled app of the
same name would inherit them), run permits never pinned to a `declared` list, owed work, interrupted writes.
It cannot check the seals themselves or the audit anchors (HMACs under a password-derived key); `run` and
`kos audit --verify` do, with the password. A check that crashes is reported as a failure, never dropped.

## Performance notes (what was measured, and what was left alone)
Idle cost is low by design: no services, and PID 1 blocks in `wait()`. What was measured and changed:
* A background broker (`kos open`) used to wake once a second per app; it now sleeps in `select()` with no timeout,
  woken by a pidfd (app exit) and a signal wakeup pipe (SIGTERM): 1.00 -> 0.00 wakeups/s, and SIGTERM to full
  shutdown 1.31 s -> 0.05 s. Kernels without `pidfd_open` fall back to the 1 s poll. The CPU saved is below what
  the kernel reports; the gain is idle-state residency.
* Apps run with `-B` from a read-only tree, so nothing could ever cache bytecode and each launch recompiled the SDK.
  The image build now precompiles it: importing the suite modules measured ~94 ms -> ~62 ms (noise in a shared
  container is ~10%).
Measured and deliberately NOT changed: `kos optimize` recompresses every app on every call, but all 144 suite apps
total 67 KiB and it costs 80 ms; CLI start-up (~85 ms) could shed at most ~19 ms by lazy imports; the secure wipe
of an app's cache fsyncs, which is the point of it; scrypt is the security parameter, not waste (measured here:
~0.6 s of CPU and ~140 MiB of memory for every password check). The foreground session loop still wakes 4x/s
while an app is in front of you: the timeout serves the first-frame deadline for the boot prompts and a
child-exit check, and it could be made event-driven, but that loop drives the trusted password/device overlay, so
it was left alone for a saving of four wakeups a second while the screen is on.
## Addresses, extensions, mods and the three layers
**Addresses** (`address.py`). `kos://APP[/path][?query]`, or a bare name. One strict parser: only the `kos://`
scheme, an app name, then optional `/path` and `?query` from a small safe alphabet (no `%`, `#`, whitespace,
control characters, `.`/`..` segments); `mode=` is lifted out of the query. Nothing is trimmed or repaired.
The path and query travel as data: `Instance.address` (written by the OS from the checked value), then
`KOS_ADDRESS` in the app's environment (`loader.plan` re-checks it), then `App.address` in the SDK. An app may
ask for one with `{"cmd":"request","action":"open","address":...}`; `protocol._request` validates it the same way.

**Kinds** (`kapp.py`). Everything is an app, and an app has one `kind`: `app`, `extension` (adds to an ordinary
app) or `mod` (modifies a system app: `taskbar`, `app-library`). Add-ons are ordinary `.kapp`s - same install scan,
seal, permit, open and close. The manifest enforces what each may target (an extension cannot target a system
app and a mod cannot target an ordinary one), forbids the `system` permission on any add-on, and requires
`extension.json` for an add-on and forbids it on an ordinary app, so a thing is exactly what its manifest says.

**Contributions** (`extensions.py`). `extension.json` is data validated when the add-on is installed (and each
time it is read): at most 12 `entries` of `{label, address}` (label 1-24 plain characters, address canonicalised by
the same parser) and, for mods only, `colors.accent`. Unknown keys are refused. The host is never modified: its zip
and seal are untouched. `kos extend NAME` (needs install + permit; the password action is `app.extend`, and
`app.mod` for a mod) records `extend:HOST` / `mod:HOST` in the universal permission store **pinned to the sha256 of
the exact zip approved**. When a host session starts or attaches, `Session.run` sends `{"cmd":"extensions",
"items":[...],"skipped":[...]}` right after `hello`, only to the host the grant names and only if there is
something to say. An add-on whose zip no longer matches its pin, that is gone, that lost its permit, or that
stopped extending that host is reported in `skipped` with a reason and contributes nothing; at most 8 add-ons are
delivered per host and the rest are also reported as skipped. What a host does with the entries is the host's
business: the taskbar pins them (keys a-i, chips), the App Library lists them as a shelf, `web` lists extension
bookmarks. A pinned entry is only a request to open an address: it goes through the pipeline below and asks for
the password like any other open.

**The layers** (`layers.py`). `layers.traverse(paths, authority, Request(verb, target, mode))` is the one door for
using an app. Verbs: `open`/`run`, `close`, `focus` (switching, `kos attach`), `extend`/`unextend`. It runs the
three action layers of AI OS (`aios.LAYERS` minus `skill`), in this order, each one:

| layer | question | open / run | close | focus | extend |
|---|---|---|---|---|---|
| `gui` (graphical button clicker) | is there a button? | the App Library lists the app, with that mode | the taskbar lists the instance | same | the App Library lists an add-on whose host is installed |
| `app` (app commands) | is it permitted? | the run permit | - | - | the add-on's run permit |
| `kernel` (kernel commands) | what the kernel says | password for exactly this action, seal verified, manifest within the permit, network question, sandbox policy | password | the process is alive | password (`app.extend`/`app.mod`) + seal |

A refusing layer stops everything behind it, so an unpermitted app is refused by `app` and `kernel` never runs: no
password is asked and, on the command line, the authority (which opens `/dev/tty`) is never even built
(`traverse` takes a factory for that reason). Each layer writes `layer.LAYER.VERB` `pass`/`refused` to the audit
log (`kos audit` shows them all; `kos activity` shows only refusals) and a refusal carries `.layer`, which the
bridge puts in the reply (`"app layer: ..."`). `open_background` (so `kos open`, `kos go`, the desktop and an app's
`open` request), `cmd_run`, `close_instance`, the bridge's `focus`, `kos attach`, the desktop's attach and
`kos extend` all call it. `TestLayers.test_no_code_outside_layers_...` fails if the name of any of those password
actions appears outside `layers.py` (bar `auth.py`, which defines them, and `store.py`, which checks a grant is
one of them), so a new path cannot quietly skip a layer.

Gaps, stated plainly:
* **Scope.** The layers cover *using* an app. `install`, `update`, `remove`, `permit`, `grant`, device boots,
  `scan watch`, `optimize`, `admin`, `write`, `exec` and `kos aios` keep their own gates and do not pass through
  them. (`kos aios` hands a request to the NeuroClaw engine, a separate process; it is not this pipeline.)
* Some layer/verb pairs have nothing to check (`app` for close and focus). They are traversed and audited anyway.
* **A host must cooperate.** An add-on can only change what its host chooses to draw; hosts that ignore the
  `extensions` command are unaffected. Nothing is injected into a running or sealed app.
* **No live reload.** The grant takes effect the next time the host starts or is attached (`hello` is re-sent on
  each attach). It is not pushed into a host that is already attached.
* **Delivery checks the pin, not the seal.** The seal is an HMAC under the password-derived key, and no password
  is present when a session starts. The password is spent at `kos extend`, which verifies the seal and records the
  sha256; delivery recomputes the sha256 of the stored zip. Code running as the owner that can rewrite both the zip
  and `permissions/grants.json` can therefore forge a delivery - the same tamper-evident-not-tamper-proof gap as
  the rest of the owner-writable state above. It cannot make the host's own seal verify.
* The path of an address cannot contain `%` or `#`, so a URL that needs them cannot be expressed as `kos://web/...`.
* Only `colors.accent` exists; there is no way for an add-on to add behaviour, only entries and an accent.

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

## Protected directories (`kos/protect.py`)
A directory that has been `kos scan protect`ed is kept at mode 0500 (read
and list, no write) whenever nothing is watching it - the kernel's own
permission check refuses any create/write/move into it, for anyone,
including the owner. That is deliberately a real, load-bearing security
boundary, not a courtesy: mode bits are enforced by the kernel for every
process on the system, which is a stronger guarantee than anything KOS
itself could add in userspace. `kos scan watch` is the only thing that
raises it back to 0700, and only for exactly as long as it is running and
actively scanning everything written there (`held_unlock` in `protect.py`
relocks in a `finally`, so a crash, an error, or Ctrl-C all relock it the
same way). A file the scanner flags while a protected directory is unlocked
is moved to quarantine immediately, not just reported.
This only works for a process that actually respects Unix permissions -
i.e. not root. On the real system the owner's shell runs as uid 1000
(`kos-init`), so this is a genuine boundary there; a root process on a
general-purpose Linux box (including this dev container) bypasses file
mode entirely, which is *why* development testing of this feature had to
be done as a non-root user (`su nobody`) to mean anything - documented
directly in the test and verified by hand before trusting it.

## Device control (`kos/control.py`)
`kos control ID mouse|keyboard ...` builds the exact same wire commands a
real boot + physical click/keystroke would send (see `session.py`'s
`route()`), and requires the same password as booting that device, once per
invocation. It is not a second, weaker input path - it is a scriptable way
to use the one input path that already exists, gated the same way.
A password before *every single* input event was asked for at one point in
this project and is not what this implements, because it cannot be: typing
a password is itself a sequence of keystrokes, so "a password before each
keystroke" has no base case and can never complete, and mouse movement fires
far too often (hundreds of times a second) for an interactive prompt per
event to mean anything other than the OS being unusable. What *is* real
here: `kos control` asks fresh, every time you run it, for whatever
commands that one invocation sends - there is no batching that lets one
password authorize an unbounded stream of later input.

## The `kos mv` pipeline (`cli.cmd_mv`)
Three separate password prompts in sequence - move, then `optimize`, then
scan the new location - sharing one `Authority` so each of the three
`authorize()` calls asks fresh. Declining any step raises immediately and
stops the command there; whatever already completed is not undone (undoing
a declined step would itself be an unauthorized action). This works because
a file move is a single, deliberate, human-paced action - nothing like the
keystroke/mouse case above, where per-event prompting is impossible rather
than merely inconvenient.

## Autonomous action (`kos/autonomy.py`)
Everything above says "nothing happens without your password." Autonomous
action is what happens when a human still isn't there at the moment
something needs to run - a cron job, a timer, another process - without
quietly abandoning that rule. The resolution:

* **Issuing** a grant (`kos autonomy grant ACTION TARGET --for N --uses M`)
  calls the real `Authority.authorize()`, exactly like everything else - a
  human has to be present, with the password, for that one moment. What
  gets written to disk afterward is an `AutonomousGrant`: an id, the exact
  action and target it covers, an expiry, a use counter, and an HMAC tag -
  never the password, never the master key.
* The tag is computed with the **autonomy key**
  (`HMAC(master, "autonomy-mac")`), generated once on first issue and
  stored on its own at `<etc>/autonomy.key` (0600). It is derived from the
  master key but, being an HMAC output, cannot be run backward to recover
  either the master key or the password. Its only power is to verify a tag
  someone with the real password already produced.
* **Redeeming** a grant (`kos close ID --token GRANT`, run with no TTY at
  all) needs none of that: it reads the autonomy key, recomputes the tag,
  and checks it against what's stored, along with expiry and remaining
  uses. No password, no `Authority`, no human.
* **The permanent limit**: `AutonomyStore.redeem()` returns a
  `RedeemedGrant` whose `.key()` always raises. It is not an oversight to
  fix later - it is the entire safety property. `kapp-seal` and every other
  master-key subkey can only ever come from a live `authority.authorize()`
  call, so a redeemed grant, however it was obtained, structurally cannot
  install, update, run, open, or optimize (reseal) anything.
  `AUTONOMOUS_ACTIONS` is the short, explicit allowlist of what a grant can
  ever be issued for at all - everything else is refused by `issue()`
  before a password is even asked, the same "don't ask for a password for
  garbage" pattern used everywhere else.
* A **tampered or forged grant file** fails the HMAC check and is refused
  (`test_tampered_grant_file_is_rejected`); a **wrong action or target**,
  an **expired** grant, or one with **no uses left** are all refused the
  same way, each independently tested.

## The admin keyslot and privileged grants (`kos/admin.py`)
This is the one place in KOS that deliberately reverses two founding
decisions - "no root login exists" and "an autonomous grant can never
install/run/optimize" - and it does both through one mechanism, on purpose,
off by default.

**How the keyslot works.** Modeled on LUKS: the owner's password and the
admin's password are two different passwords that unlock the exact same
master key, not two different keys. `kos admin setup` calls
`authority.authorize("admin.create")` for real - a live password prompt,
using `Grant.raw_master()` (the one place outside sealing that touches the
literal master bytes, not a derived subkey) - then wraps that master under
a new password: `wrapped = master XOR HMAC(admin_slot_key, "admin-wrap")`.
Unwrapping with the correct admin password reproduces byte-identical master
key material to the owner's own unlock (`test_owner_and_admin_unlock_to_the_same_master`),
which is what lets an admin-authorized `Grant` derive `kapp-seal` exactly
like an owner-authorized one - there is no cryptographic distinction once
either password has unlocked it, only the `via_admin` flag `Authority`
attaches to the `Grant` it returns, which callers use to decide what to do
next (root shell vs owner shell; ordinary grant vs privileged one).

**The keyslot lives on tmpfs, not the encrypted disk.**
`AdminStore.file` is `paths.runtime / "admin.json"` (`/run/kos` on the real
system), never `paths.etc`. `/run` is mounted fresh and empty by
`kos-init` on every single boot (`init.py`'s `MOUNTS`), before the first
login prompt even appears, so the admin keyslot cannot survive a reboot by
construction - there is no code path that has to remember to delete it,
and no window where a stale keyslot from a previous boot could be unlocked.
`kos admin status` after a reboot correctly reports none exists;
`kos admin setup` has to be run again, deliberately, each session it's
wanted (`test_admin_lives_on_tmpfs_and_does_not_survive_a_reboot`, which
simulates the remount directly). Privileged autonomy grants are unaffected
by this: `issue_privileged` copies the real seal key into the grant file
at issuance rather than referencing the admin keyslot, so a grant already
issued keeps working across a reboot for its own remaining duration/uses,
even though the admin account that created it is gone - the two have
independent, separately-chosen lifetimes on purpose.

**`Authority.OWNER_ONLY`** is a short, hard-coded set (`admin.remove`,
`auth.change`) that never accepts the admin password, even though it's
cryptographically capable of unlocking the same master - enforced in code,
not by convention, so an admin can never erase the record of their own
elevation or change the owner's password
(`test_admin_cannot_remove_itself_owner_can`).

**Root at login.** `kos-init`'s `login_loop` reads `grant.via_admin` off
the `session.login` grant and passes it straight through as `start_shell`'s
`as_root` - the owner's own password can never produce `via_admin=True`,
by construction, so it can never reach the root path. This is the literal
reversal of "no root login exists": now real, gated behind a password that
does not exist until someone with full owner access explicitly runs
`kos admin setup`.

**Privileged autonomy** (`AutonomyStore.issue_privileged`/
`redeem_privileged`) is the other reversal: `RedeemedPrivilegedGrant.key()`
actually returns real key material, unlike a normal `RedeemedGrant`'s,
because `issue_privileged` captures `grant.key(SEAL_KEY_LABEL)` at
issuance and carries it (HMAC-tagged for tamper detection, same as a
normal grant) in the grant file. `issue_privileged` refuses outright unless
`grant.via_admin` is true - the owner's password cannot mint one no matter
how it's called (`test_issue_privileged_needs_admin_not_owner`). Redemption
still re-checks the target: `AppStore.install`'s pre-made-grant path calls
`grant.check(action, m.name)` before using it, so a grant minted for
"hello" cannot install a differently-named app just because a `.kapp` with
that name happened to be handed to the same grant id
(`test_privileged_grant_scoped_to_wrong_app_name_is_refused` - this was a
real gap caught and fixed during development, not a hypothetical: the
target for `app.install` isn't known until the file is parsed, unlike
`cell.start` or `app.close` where the caller already knows it before
redeeming).

**The honest risk, stated plainly.** A privileged grant file is close to a
bearer copy of full install/run/optimize authority until it expires -
unlike a normal grant, whose `.key()` always raises, so its file alone is
harmless. That's exactly why minting one needs the higher-trust admin
password rather than the everyday owner one, and why `kos autonomy
grant-privileged`'s own success message says to treat the grant file like
a password. Use the shortest duration and fewest uses the job needs.

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

## Local mesh (design only)
See `docs/MESH.md`. Not implemented; it records how a device mesh could satisfy the rules and where it conflicts with the firmware gate and the no-background-services rule.

## Known gaps
* Python userland: secrets may be copied by the interpreter → Rust port.
* A process running as the owner outside KOS could read `auth.json` and guess
  passwords offline (at scrypt cost). Fix: root-owned verifier + tiny setuid-free
  broker over SO_PEERCRED.
* seccomp is a short denylist (EPERM, not kill), x86_64 only. It is not an allowlist, and other
  architectures get no filter (their syscall numbers could not be tested here); `kos doctor` says so.
* The audit log's tail can be cut off undetected, and a forger who relabels every grant is not caught
  (see "Audit log"). Nothing outside the log remembers what it should say.
* Run permits granted before permission tracking existed carry no `declared` list, so an update to such an
  app can add `network`/`system` without asking. `kos security` lists them; `kos permit NAME` re-records.
* Updates are checked for version order but not for publisher signature yet.
* Background apps (`kos open`): the broker's Unix socket path is under
  `<state>/instances/`, which must fit in `sizeof(sockaddr_un.sun_path)`
  (108 bytes on Linux) - fine under the real `/var/lib/kos` root, but a very
  deeply nested `KOS_ROOT` in development can exceed it.
* While nobody is `attach`ed to a `kos open`ed app, its output is read and
  dropped by the broker rather than buffered, so a burst of output with no
  one attached is lost rather than replayed on the next attach.
* `kos scan watch --background` (and `kos open`'s broker before it) forks
  and detaches; when the process later exits (via SIGTERM from `kos scan
  stop`/`kos close`, or on its own), the OS is responsible for reaping the
  resulting zombie. The real `kos-init` PID 1 does this in a loop by
  design. A general-purpose container used only for developing KOS (not
  running it) may not, so a stopped background job can briefly show as a
  zombie in `ps` there - harmless, and unrelated to whether the KOS-visible
  state (the registry entry, the relock, the quarantine) updated correctly,
  which it does within one watch poll interval regardless.
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
* `kos control` connects to the same single-attach broker slot a real
  `kos attach` uses (see the "one attach at a time" note above), so sending
  a control command while a real terminal is attached takes that slot away
  from it. This is fine for the common case (`kos open` then drive it
  purely with `kos control`, never attaching a terminal at all) but it is
  a real conflict, not a polished feature, if you mix the two.
* `kos mv`'s three steps are not a transaction: there is no rollback. A
  decline partway through leaves whatever already happened in place. This
  is intentional (see "The kos mv pipeline" above) but worth restating
  here as a gap for anyone expecting atomic all-or-nothing semantics.
* A protected directory's lock (`kos/protect.py`) is plain Unix file mode,
  which only stops a process that honors it - a root process ignores it
  completely. It is a real boundary for the owner's own uid-1000 shell on
  the real system, not a sandbox against a root-level attacker.
* A grant file, once issued, *is* the permission for its exact
  action/target until it expires - anyone who can read
  `<state>/autonomy/<id>.json` off disk can redeem it (that's the whole
  point: no further password). Filesystem permissions on `<state>` are the
  only thing standing between "a process on this machine" and "able to
  redeem any grant that exists" - the same trust boundary as everything
  else under the owner's account, not a new one, but worth being explicit
  about: a grant is a bearer credential for its narrow purpose, and should
  be issued with the shortest duration and fewest uses that the job
  actually needs.
* `--token` support is wired into `app.close`, `cell.start`/`cell.stop`,
  `app.permit`/`app.revoke`, `scan.watch`'s start, and `device.desktop` -
  the full `AUTONOMOUS_ACTIONS` allowlist - but not into every other
  command that happens to share those action names in a different context
  (e.g. `kos attach`, `kos scan stop`); those still only take a live
  password. A multi-directory `scan.watch` grant's target must match the
  comma-joined directory list byte-for-byte, which is exact but not
  friendly to type by hand.
* `--privileged-token` is wired into `kos install` and `kos optimize` only.
  `kos run`/`kos open`/`kos update` do not accept one yet - not because
  they're any less capable of it, but because each has extra live logic
  (the `network` permission prompt, `kos update all`'s directory scan,
  `PermitStore` checks) that would need its own careful pass to keep
  correct under the token path rather than just plumbed through quickly.
* There is only ever one admin keyslot, not several named ones - `kos
  admin setup` refuses if one already exists. Multiple distinct admins
  (each removable independently) would need the keyslot storage to become
  a small list rather than one file, which `kos/admin.py` doesn't do yet.
* Nothing rate-limits `kos autonomy grant`/`grant-privileged` itself beyond
  the normal password throttle - a script with the owner's password could
  mint many grants quickly. Each still needs that real password, so this
  is the existing throttle's job, not a new gap, but worth naming since
  it's a new place password-guessing pressure could show up.

## AI OS (`kos/aios.py`)
KOS carries requests, NeuroClaw does the work and decides (no KOS password). `POST /api/ai-os/layer` to the NeuroClaw engine (`KOS_AIOS_URL`, loopback only, default
`http://127.0.0.1:7861`). The engine accepts only `gui`, `app`, `kernel`, `skill` and runs them
through its normal tool gate. Gap: the NeuroClaw engine is a separate process that must already be
running (KOS does not start it, by the no-background-services rule), and if it has a password set the
request is refused until the call is made from an admin session on this computer.

## The pipeline's six layers and their guards

Two different things are called layers here, and they are not the same list:

* **Action layers** (`layers.py`, above): `gui`, `app`, `kernel`. Every *use of an app* passes through all three,
  once, in that order. Unchanged.
* **Pipeline layers** (`guard.PIPELINE`): the path data takes between the screen and the hardware, which every
  *running session* is guarded on, continuously: **graphics, text, button clicker (input), app commands, kernel,
  hardware**. The text layer (`textsurface.py`, `run text NAME`) was added between graphics and the button clicker.

| layer | guard | where it runs | on a hit |
|---|---|---|---|
| graphics | `frame-budget` | `Session.handle_app`, after a `frame` validates | app ends (125) |
| text | `page-budget` | `Session.handle_app`, after a `screen` validates (text and tui) | app ends |
| input | `event-shape` | `Session.route`, before anything is forwarded | event dropped, audited (first 5) |
| commands | `message-budget` | `Session.handle_app`, before validation | app ends |
| commands | `prompt-budget`, `failed-requests` | `Session._on_request`, before the bridge | request answered "no", nobody is asked for a password |
| kernel | `attest-process` | session start, then every 2 s: `/proc/PID` status and namespaces | app ends |
| hardware | `no-device-handles` | the same look: `/proc/PID/fd` | app ends |

Every refusal is `guard.LAYER.CHECK` `refused` in `kos audit` (the first five of a kind; the rest are counted in
`Guard.stats`). The first successful kernel and hardware look is written as `pass`; under `KOS_DEV_WEAK_SANDBOX` the
kernel look is skipped and written as `weak`.

What each guard does not do is in the README gaps table ("Layer guards", "Text layer"). In short: the limits are
guesses, not measurements; the kernel guard cannot see Landlock and skips cells; the hardware guard only sees handles
open at the moment it looks; nothing here is encryption of the channels (see "Pipeline encrypted").

**The text layer** prints a transcript: every OS line starts `KOS| `, every app line `app| ` (each wrapped piece too),
anything unprintable becomes `?`, the password prompt is printed once and never echoed, and there is no pointer. An
app with a `tui` mode runs as text unchanged (`kapp.supports_mode`) and is told `tui` (`kapp.wire_mode`).
