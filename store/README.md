# store/

Everything KOS ships lives here, split by level.

```
store/
  apps/      top-level apps: one folder per app (manifest.json + its own code). Python, sandboxed,
             proof-checked at install and every launch (rule 1). Moved here from the old top-level apps/.
  core/      bottom-level system pieces, built to native binaries. One folder per piece.
    boot/    kos-boot (C): verifies every file under kos/ and bin/ against a sealed manifest, then starts the core.
```

Only the **system** is a binary. User apps (calendar, notes, ...) stay ordinary apps; the OS refuses compiled code
as an app on purpose (a binary cannot be proof-checked).

## Build and use the boot binary

```
make -C store/core/boot                       # build/kos-boot (-Wall -Wextra -Werror -pedantic, PIE, RELRO)
make -C store/core/boot seal OUT=/path/img    # write CORE.sha256 for the core as it is now
kos-boot --root DIR --manifest CORE.sha256 --python /abs/python3 -- ARGS...
kos-boot --root DIR --manifest CORE.sha256 --check          # verify only; says why it would refuse
```

It refuses with one message (`kos-boot: refusing to start`, exit 1) for every cause: a changed or missing file, a file
not in the manifest, a link or special file, or a bad manifest. It starts the core as `python -I -B bin/kos ARGS`
with an allow-listed environment (`PYTHON*`, `LD_*` and the like are dropped). Tests: `tests/test_core_boot.py`.

## What is not done (said plainly)

- **The core is still Python.** `kos/` (auth, seals, sandbox launch, protocol, devices, display) is about 21,000
  lines of Python run by the interpreter; `kos-boot` only checks it and starts it. Rewriting it in C or Rust is not
  started: it is many pieces, each needing the same tests the Python version has, and a kernel-facing piece cannot
  be checked without hardware.
- **Enforcement is not an app.** The password overlay, sandbox, device reading and command validation are
  still OS code. Making them apps is against README rules 2 and 6 (an app could cover or fake the overlay); it was
  asked for and needs the owner to change those rules first, so nothing here does it.
- **About 150 apps are launchers, not folders.** The productivity suite and the packs keep their code in the shared
  `kos/office/` package, which is not "app code in its own folder". Only the 16 OS apps in `store/apps/` are
  self-contained.
- **The seal is only as good as where the manifest lives.** It must sit in the signed pre-boot image, not beside the
  files. A file can still change between `kos-boot` hashing it and Python opening it (no fd passing yet), and the
  interpreter and its libraries are not hashed.
- **Not tested** on real hardware or in the signed UEFI image; only with temporary directories on this machine.
