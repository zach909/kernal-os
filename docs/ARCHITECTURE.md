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
