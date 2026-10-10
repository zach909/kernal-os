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
