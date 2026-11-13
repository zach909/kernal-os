# Modding-centric OS requirements vs. KOS

The 5-part requirements list (microkernel, Wasm sandbox, hot-swapping, overlay VFS, scriptable UI)
describes a different kind of system than KOS. KOS is a Python userland on the Linux kernel with no
third-party dependencies, and its rules (README "Rules") make every action password-gated, every
feature a sandboxed `.kapp`, and every connection blocked and encrypted. This table says what each
requirement maps to **today**. "Built" means built and tested; nothing here is claimed beyond that.

| # | Requirement | Status | Where / what is missing |
|---|---|---|---|
| 1 | Pure microkernel | **Not applicable** | KOS runs on Linux; the kernel is not ours. Apps are already isolated processes (Landlock, namespaces, seccomp) and `kos/cells.py` runs apps on a separate kernel in a KVM micro-VM. |
| 1 | Userspace drivers | Not built | Devices are read by the OS process (`kos/devices.py`), not by swappable driver processes. |
| 1 | Event-driven pub/sub bus with interception | Not built | The command protocol is point-to-point app<->OS. A bus that lets a mod *block* system actions would need its own design and password action. |
| 1 | Deterministic allocator | **Not applicable** | Python and the Linux allocator; no custom allocator is possible here. |
| 2 | Wasm / eBPF sandbox | Not built | Needs a vetted runtime (a dependency; the owner must decide). The seccomp filter denies `bpf`. Mods today are *data*, not code (`kos/extensions.py`). |
| 2 | Capability tokens | Partly | Per-app permissions in one store (`kos/permissions.py`, `kos/permit.py`), pinned to the sha256 of what was approved. Not unforgeable tokens; no per-subsystem token handed to a mod. |
| 2 | Bytecode verification (SFI) | Not built | Depends on the Wasm item. |
| 2 | Version-multiplexed linker | Not built | |
| 3 | Hot-swap, state serialization | Not built | Extension changes take effect at the next host start (ARCHITECTURE "No live reload"). |
| 3 | Watchdog + automatic last-known-good rollback | Not built | Mods are pinned by sha256 and a changed one is skipped, which is a safe-by-default stop, not a rollback. |
| 4 | Immutable base, priority overlay, CoW | **Built** (this change) | `kos/overlay.py`. See below. |
| 4 | Non-destructive conflict resolution, load-order matrix | **Built** | Global load order plus per-folder rules; `kos overlay conflicts`. |
| 4 | Hardware write-protected base | Not built | The overlay never writes a layer, but the base is not write-protected on disk. |
| 5 | Declarative display server / scriptable styling | Partly | Apps already send `screen`/`frame` commands and the OS draws; mods can set `colors.accent` only. |
| 5 | Global input hook matrix | Not built | Input goes OS -> focused app only. A hook that reads keys before the app is a keylogger by another name and would need its own password action and an owner-visible indicator. |
| 5 | Introspective window API | Not built | `request` has no window-metadata call. |

## The overlay (section 4)

`kos/overlay.py`, `tests/test_overlay.py`, CLI `kos overlay order|show|conflicts`.

* A mod is an ordinary `.kapp` that ships files under `overlay/`. Its zip is read in memory, never
  extracted; paths, counts, sizes and compression ratio are checked, symlinks and encrypted entries are refused.
* The merge is computed on read. Layers are read-only (`MappingProxyType`), so no mod can alter another
  mod's bytes or the base. A test compares layer digests before and after edits.
* Load order is explicit, last wins, and a mod not in the order is off. Changing it is the password
  action `overlay.order`; looking at the merge is `overlay.view`. The order records each mod's sha256: a changed,
  removed or un-permitted mod is skipped with the reason shown, as extensions are.
* Rules give one folder its own order (longest matching prefix wins).
* `X.kos-delete` hides `X` from layers below without deleting it; a higher layer can bring it back.
* Writes (`Overlay.write/delete/revert`) are copy-on-write into an in-memory `user` layer.
* `core/` is protected: a mod with any file there is refused whole.

### Not covered by the overlay

* **The base is empty in the CLI.** KOS has no core file set to overlay yet, so `kos overlay` merges mods only.
  The library takes any base.
* **Nothing consumes the merge.** No app or OS component reads files through the overlay yet; this is the
  mechanism and its checks, not an integration.
* **The user layer is memory only.** Persisting it would be file writes, which must go through the guarded
  write (admin keyboard, scan, optimize).
* **Mod layers are not virus-scanned** by the overlay itself; the mod's `.kapp` was scanned at install.
* The seal is not re-verified at build time (no password then), only the sha256 pin, the same gap as extensions.
