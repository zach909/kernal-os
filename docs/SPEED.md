# Speed-first blueprint vs. KOS

A "speed-first OS" checklist was reviewed against KOS as it is in this repo.
This file records, item by item, what is already true, what could be adopted
without breaking a KOS rule, and what is refused and why. **No code changed
with this review; nothing here was benchmarked.** Every "gain" below is a
hypothesis to measure, not a result.

## The short version

The blueprint describes a dedicated-workload appliance: one trust domain, one
binary, no isolation boundary. KOS is the opposite product: a password-first
system whose whole value is the boundary between OS and apps
(`README.md` rules 1-4). Items that remove that boundary are not "optimizations
we have not got to yet"; they are a different operating system. KOS is also a
stdlib-only Python userland over a stock Linux kernel, so the language, PGO,
allocator, bootloader and driver items do not apply to the code that exists.

Where speed is cheap and safe, it already lives in the places that matter:
cells (the only place raw performance is the point) are KVM micro-VMs pinned
to dedicated cores.

## Item by item

Verdicts: **Have** (already true) / **Possible** (fits the rules, needs a
measurement first) / **Refused** (breaks a rule or does not apply).

### 1. Architecture and kernel

| Blueprint item | Verdict | Reason |
|---|---|---|
| Unikernel / single address space, no user-kernel switch | **Refused** | Apps are hostile by design: Landlock + namespaces + seccomp (`kos/sandbox.py`) exist *because* app and kernel are separate. A single address space removes rule 1's enforcement and rule 4's "apps never touch the kernel". The legitimate version of this idea is a cell (below): a dedicated workload gets its own kernel and cores, and the isolation is the VM boundary. |
| Monolithic over microkernel | **Have** | KOS runs on Linux. |
| Bare-metal multi-stage bootloader into long mode | **Refused / n.a.** | Boot is UEFI -> Linux -> LUKS2 initramfs -> `kos-init`. Skipping probing would mean skipping the measured/locked-down boot (`lockdown=confidentiality`, signed modules, IOMMU). Boot time is dominated by the LUKS unlock and the password, not by probing. Not measured; do that first if boot time matters. |

### 2. Memory

| Blueprint item | Verdict | Reason |
|---|---|---|
| Huge pages (2 MB / 1 GB) pre-allocated | **Possible, cells only** | A cell's guest RAM (`kos/cells.py`, `-m`) is a long-lived, large, pinned mapping: the one place huge pages reliably cut TLB misses. Would be a `-mem-path` / hugetlbfs option on `CellSpec`, off by default, and it needs hugepages reserved on the host. Everything else is small and short-lived; do not bother. |
| Bump / pool allocators, ban generic allocators | **Refused / n.a.** | The userland is CPython. The kernel is configured with `init_on_alloc=1 init_on_free=1`, `slab_nomerge`, `page_alloc.shuffle` (`kernel/cmdline.txt`) *on purpose*: they cost speed and buy memory-safety hardening. Swapping them for speed contradicts the project's stance. |
| Flat memory model, direct physical mapping | **Refused** | KASLR (`CONFIG_RANDOMIZE_BASE/MEMORY`) is enabled deliberately. Linux is already flat-segmented on x86_64. |

### 3. Concurrency and scheduling

| Blueprint item | Verdict | Reason |
|---|---|---|
| Per-core run queues, core affinity | **Have (cells)** | `kos/cells.py` pins each cell with `taskset -c` and refuses overlapping cores; its docs point at `isolcpus=`/`nohz_full=` for the host. Linux's scheduler already keeps per-core run queues. App processes are not pinned and should not be: they are interactive and idle. |
| Lock-free queues, CAS ring buffers | **Refused / n.a.** | There is no contended shared queue in KOS: one app, one OS, one socket. In Python the GIL decides, not CAS. |
| Polling instead of interrupts | **Refused** | KOS already moved the opposite way and measured it: the broker went from 1 wakeup/s to 0 (`docs/ARCHITECTURE.md`, "Performance notes"), because idle residency is the metric for a desktop/laptop OS. Busy-polling is the right trade only on a dedicated server core; inside a cell it is the guest's own choice. |

### 4. I/O and file systems

| Blueprint item | Verdict | Reason |
|---|---|---|
| io_uring-style async I/O | **Refused** | `CONFIG_IO_URING` is deliberately **off** and `io_uring` is in the seccomp denylist (`README.md`, `kernel/kos.config`): it is a large, repeatedly exploited kernel attack surface. The command channel is already asynchronous message passing. |
| Zero-copy, mmap, DMA straight to app buffers | **Refused** | Apps do not touch hardware or share memory with the OS; every file access is a guarded, password-gated `request`. Zero-copy to an app is exactly the bypass rule 4 forbids. IOMMU strict mode is on for the same reason. |
| Log-structured / in-memory file system | **Not now** | Backups are already content-addressed and deduplicated (`kos/backup.py`). A new FS is a large change with no measured bottleneck behind it. |

### 5. Toolchain and hardware

| Blueprint item | Verdict | Reason |
|---|---|---|
| C/Rust/Zig, inline asm | **Partially agreed** | The README already says the security core should move to Rust (secret wiping). That is for correctness, not speed. |
| `-O3 -march=native`, LTO, PGO | **Possible, only for the Python interpreter or a future native core** | `-march=native` also makes the image non-portable across CPUs, which hurts a distro. A PGO/LTO CPython build is a packaging decision; measure the ~85 ms CLI start first (`docs/ARCHITECTURE.md` measured at most ~19 ms to gain from lazy imports). |
| Hard-coded drivers for specific chipsets | **Refused** | `kernel/kos.config` is a minimal config already; hard-coding target chipsets trades away the ability to boot on arbitrary hardware for a negligible saving. |

## What is actually worth measuring (if speed is the goal)

In rough order of expected payoff versus rule risk, each needing a number
before any change:

1. **Password check cost.** scrypt measured ~0.6 s CPU and ~140 MiB per
   check. That is the single biggest latency a user feels, and it is the
   security parameter. Tune only with an explicit decision from the owner;
   never to hit a speed target.
2. **Cell startup and steady-state**: huge-page-backed guest RAM, `isolcpus` /
   `nohz_full` on the cell cores, virtio-blk/vsock queue settings. Cells are
   where throughput matters; the benefit is real only on KVM hardware, which
   the dev container does not have (`README.md` lists cells as written but not
   booted).
3. **Cold start of an app**: bytecode is already precompiled at image build
   (94 -> 62 ms). The next cost is the sandbox setup per launch; profile it
   before touching it.
4. **Boot**: time `init` -> first prompt on a real image. Not measured here.

## Rules check for this change

* Rule 1 (verification): this file changes no action and adds no command. No
  test was added because no behavior changed; `python3 -m unittest discover -s
  tests` was not re-run for a docs-only change.
* Rules 2-4: nothing connects, listens or fetches. The pipeline is untouched.
* README gaps table: unchanged. This review closes none of the listed gaps and
  claims no new rule is met.
