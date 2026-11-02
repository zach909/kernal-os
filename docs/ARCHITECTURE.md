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
