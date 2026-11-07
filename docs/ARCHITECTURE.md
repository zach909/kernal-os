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
  flash (`me_cleaner`/HAP, coreboot, a BIOS switch), done offline; KOS does not write flash.
* **Almost no physical machine boots under `enforce`.** Besides the ME/PSP/BMC, any chip with its own
  firmware blocks it too: Thunderbolt/USB4, USB-C port controller, embedded controller, and network, GPU,
  NVMe and wireless controllers (PCI classes in `FIRMWARE_CLASSES`), and so does DMA hardware with no
  IOMMU. These are not unbound (that would break the machine); the strict IOMMU in `kernel/cmdline.txt`
  confines them. VMs ignore the emulated ones. Use `kos.firmware=warn` to boot with the alert.
* **Power-down for optional chips.** Thunderbolt/USB4 and wireless controllers are unbound and asked for D3cold
  (`d3cold_allowed`, `power/control=auto`); they stop blocking only if `power_state` then reads D3cold, in both the
  shell and Python scanners. The ME, PSP, EC, GPU, NIC and boot NVMe cannot be powered down on a running machine.
  KOS does not erase, corrupt or overvolt anything, and does not try to rewrite other chips' firmware.
* **`kos firmware plan` is read-only advice**, from a static table (`PLAN`): per blocking chip, whether open firmware
  exists (coreboot + me_cleaner for some Intel boards, OpenBMC for some servers, open EC for Framework/Chromebook/
  System76; none for PSP, USB-C/Thunderbolt, NIC, GPU, NVMe), and a verdict on whether this machine can pass. The OS
  cannot verify any of it on the hardware in front of it, and flashing is an offline job KOS does not do.
* **`kos.machine=framework`** (signed command line, shipped off) refuses to boot on anything whose DMI `sys_vendor` is
  not `Framework`. The vendor string is what the firmware reports: it prevents mistakes and swapped hardware, not a
  hostile BIOS. The allow list cannot waive it. Turning it on makes VMs and the QEMU flow refuse to boot.
* **No resident checker.** The gate runs once at boot and at each unlock; no daemon, loop or watcher.
* **Absence is unprovable.** A BIOS may hide the ME's PCI function; on bare-metal Intel/AMD with
  nothing visible KOS prints a caveat and boots.
* The HFSTS1 decoding follows coreboot/intelmetool and is untested on hardware here; the tests use
  synthetic config space. The kernel config also drops the in-kernel MEI, CCP and IPMI drivers.

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

## AI OS (`kos/aios.py`)
KOS carries requests, NeuroClaw does the work and decides (no KOS password). `POST /api/ai-os/layer` to the NeuroClaw engine (`KOS_AIOS_URL`, loopback only, default
`http://127.0.0.1:7861`). The engine accepts only `gui`, `app`, `kernel`, `skill` and runs them
through its normal tool gate. Gap: the NeuroClaw engine is a separate process that must already be
running (KOS does not start it, by the no-background-services rule), and if it has a password set the
request is refused until the call is made from an admin session on this computer.
