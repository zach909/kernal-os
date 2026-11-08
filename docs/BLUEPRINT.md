# Hardened-OS blueprint vs. KOS

The "Hardened Security-First Operating System" blueprint (seven sections:
boot chain, verified microkernel, memory exploit elimination, object-capability
MAC, network/I/O shielding, storage, anomaly detection/self-destruct) was
checked against what KOS has today. This is a gap analysis, not a claim that
the blueprint is built. Nothing here was booted: there is no KVM, TPM or
bootable-image test in the dev container (see "Status" in `README.md`).

**Status key:** DONE (exists and has tests) / PARTIAL / CONFIG (kernel option
written in `kernel/kos.config`, never built or booted) / NO (nothing) /
UNSOUND (the blueprint's claim cannot be met as worded).

## The one decision underneath everything

The blueprint describes a **new microkernel** (<10,000 lines, formally
verified, written in Rust/assembly, no root, capabilities instead of
pointers). KOS is the opposite design: a small **Python userland on the stock
Linux kernel**. Those are different projects. Sections 2, 3 (capabilities) and
4 (global-root abolition, kernel-enforced labels) cannot be reached by adding
code to KOS; they require replacing Linux, which means writing drivers,
scheduler and memory manager from scratch (seL4 took roughly 20 person-years
to verify ~10k lines, and it has almost no drivers). KOS's practical position
is "get as close as Linux allows, and be honest about the rest", which is what
`kernel/kos.config`, `kernel/cmdline.txt` and `kos/sandbox.py` already do.

If the owner really wants the microkernel route, the realistic choice is to
**build on seL4 (or Redox/Genode on top of it)** rather than write one. That
is a separate repository and a separate decision; it is not started here.

## Section by section

### 1. Hardware root of trust and boot chain

| Blueprint item | Status | Where / note |
|---|---|---|
| Immutable fused public key, every stage signed | PARTIAL | Secure Boot with the owner's key is the mechanism; KOS signs kernel + initramfs together (`boot/mkinitramfs.sh`). The fuse is the CPU vendor's (Boot Guard / PSP), which KOS cannot set. |
| TPM measured boot into PCRs | CONFIG | TPM drivers added to `kos.config`. No code seals anything to PCRs yet. |
| Keys derived from HUK + PCRs, one bit changed means unreadable | NO | Needs TPM2 sealing of the LUKS key. The password-derived scrypt key is what exists. Also note: sealing to PCRs makes any legitimate firmware/kernel update lock the owner out unless a recovery key exists; this must be designed, not just switched on. |
| SMEP / SMAP | PARTIAL | Linux enables them whenever the CPU has them; nothing in KOS asserts it. `kos security` should read `/proc/cpuinfo` for `smep smap` and fail if absent (not done). |
| Strict IOMMU / DMA remap | DONE (config) | `intel_iommu=on amd_iommu=force_isolation iommu=force iommu.strict=1 efi=disable_early_pci_dma` in `kernel/cmdline.txt`; `kos/firmware.py` refuses to boot without an IOMMU. Not booted on hardware. |

### 2. Formally verified microkernel

| Blueprint item | Status | Note |
|---|---|---|
| Proven-correct kernel < 10k LOC in Ring 0 | NO | KOS runs on Linux (~30M lines, not verified). See the decision above. |
| Deterministic, non-leaky scheduling | NO | Linux CFS/EEVDF. Cells (`kos/cells.py`) pin separate KVM micro-VMs to their own cores, which is the closest available isolation. |
| Drivers, filesystems, network stack in Ring 3 | PARTIAL | Apps and the UI run unprivileged under Landlock + namespaces + seccomp (`kos/sandbox.py`). Drivers and the network stack are still in the Linux kernel. |
| "Mathematically prove the absence of undefined behavior" | UNSOUND as worded | Proofs hold for a specification under stated assumptions (correct hardware, compiler, boot code). Say "proved against a spec" in any claim. |

### 3. Memory sanitization and exploit elimination

| Blueprint item | Status | Note |
|---|---|---|
| No raw pointers; unforgeable capabilities | PARTIAL | Apps never see addresses: they hold only protocol commands and permits. Below that it is Linux and pointers. |
| Boot-time fine-grained code ASLR / function reordering | CONFIG | `RANDSTRUCT_FULL` (struct layout) added; KASLR already set. Per-boot function reordering is not in mainline (needs FGKASLR patches). |
| Zero pages on free | DONE (config) | `init_on_alloc=1 init_on_free=1`, `CONFIG_INIT_STACK_ALL_ZERO`. Costs a few percent of performance. Not on context switch; that has no meaning for pages. |
| Shadow stacks / CFI make ROP/JOP "completely impossible" | UNSOUND as worded | They raise the cost sharply (user shadow stack, IBT, kCFI) but data-only attacks and some JOP/COOP gadgets survive. Do not write "impossible". `CONFIG_X86_USER_SHADOW_STACK`, `CONFIG_X86_KERNEL_IBT` added. kCFI needs a Clang-built kernel. |

### 4. Object capabilities and MAC

| Blueprint item | Status | Note |
|---|---|---|
| No global root; resources passed at spawn | PARTIAL | Apps run as `nobody` and get only the grants they were launched with (`kos/permit.py`, spaces). The OS itself still runs as root; the password gate (`Authority.authorize`) is the substitute for "no root", not the removal of it. |
| Bell-LaPadula + Biba together | NO | No labels exist. Note the two models conflict if used naively (BLP forbids write-down, Biba forbids write-up, so only same-level flow survives); a lattice with separate confidentiality and integrity axes has to be designed first. |
| Unalterable cryptographic label on every file, socket, IPC | NO | Landlock is path-based, not label-based. SELinux/SMACK would give labels on Linux; neither is in `CONFIG_LSM`. |

### 5. Network and I/O shielding

| Blueprint item | Status | Note |
|---|---|---|
| Network stack in isolated compartments, per-protocol processes | NO | There is **no firewall yet** and the README gap table says so. An app's empty network namespace blocks it by default; the `network` permission is all-or-nothing. |
| Encrypted, authenticated IPC with ephemeral keys | NO | The command channel is plain JSON lines (`Channel`, `kos/protocol.py`). Needs a vetted AEAD library, which is the owner's call (README rule 4). Do not hand-roll it. |
| Input multiplexer that normalises USB input | PARTIAL | Apps never open a device; the OS reads evdev and emits only `key/pointer/button` commands. USB firmware attacks (BadUSB) happen below that layer and need device allow-listing (USBGuard-style). |

### 6. Storage

| Blueprint item | Status | Note |
|---|---|---|
| Per-zone keys, full-disk encryption | PARTIAL | LUKS2 root, apps sealed with password-derived keys. Zones are not separate volumes. |
| Merkle-tree verified filesystem | CONFIG | `CONFIG_DM_VERITY` added. dm-verity is for a **read-only** volume; the OS image could use it, user data cannot. |
| Halt the machine on any file tamper | PARTIAL | Sealed `.kapp`s refuse to run when modified and the audit chain is hash-linked. An automatic system halt is a denial-of-service lever and is deliberately not done. |
| User data only in encrypted RAM; keys blown on session end | PARTIAL | Per-run app cache is wiped on exit (`kos/cache.py`). Python cannot reliably wipe secrets from memory (README: port the security core to Rust). A RAM-only user profile loses all data at power-off; that is a product decision. |

### 7. Anomaly detection and the self-destruct interrupt

| Blueprint item | Status | Note |
|---|---|---|
| Performance-counter monitoring for Spectre/Rowhammer | NO | `perf_event_open` is denied to apps by seccomp. Counter-based detection has high false-positive rates and is a research topic. Realistic mitigations: kernel Spectre defaults, ECC RAM, `pti=on` (already set). |
| Any out-of-CFG instruction raises an unmaskable exception | NO | That is CFI/IBT/shadow-stack hardware (see section 3), not a static CFG check. |
| Panic: freeze cores, scrub, fill RAM, reset | PARTIAL | `oops=panic` and `lockdown=confidentiality` are set; `init_on_free` handles freed memory. Overwriting all RAM on panic is not possible from a crashed kernel, and a reset already clears the TPM volatile registers. Stronger and cheaper: `CONFIG_MEM_ENCRYPT`/`mem_encrypt=on` (set), so RAM is useless without the CPU key, and UEFI "clear memory on reset" (MOR bit). A self-destruct that fires on a false alarm destroys the owner's session; require the password to disarm. |

## What changed in the repo for this

* `kernel/kos.config`: a short block of new hardening options (TPM drivers,
  dm-verity, user shadow stack, kernel IBT, struct randomisation, zeroed
  call-used registers). **Not built, not booted.** `make olddefconfig` drops
  symbols the kernel version does not have, so a wrong name is silent;
  confirm with `grep` on the resulting `.config` before relying on any line.
* This document, and a pointer to it from the README gap table.

## Suggested order for real work (smallest first)

1. `kos security` checks for SMEP/SMAP, IOMMU active, TPM present, Secure Boot
   on, and each protection in `kos.config` actually enabled in
   `/proc/config.gz` or `/proc/cmdline`. Read-only, testable here.
2. TPM2-sealed LUKS key with a recovery passphrase, so the PCR lock-out in
   section 1 cannot brick the owner's disk.
3. The firewall app (README rule 3): the largest real gap.
4. Authenticated encryption on the broker socket and cell vsock (needs the
   owner's approval of a vetted library).
5. Port the security core to Rust.
6. Only then decide whether to leave Linux (seL4).
