# Organization-centric OS blueprint: what KOS has, what it added, what it cannot do

The blueprint asks for an operating system built around the organization of a person's work: typed objects
instead of byte streams, a graph instead of a directory tree, matrix workspaces, composable applications and
event-driven automation. This page maps each bullet to the code, says what is real, and says what is not.

KOS runs on the Linux kernel and every feature must be a sandboxed app that talks to the OS only through the
command protocol (README rule 2). That decides what could be built: **anything that lives inside one app's own
data can be an app; anything that needs the kernel, the window system or other apps' data cannot.**

Added in `kos/office/pack_org.py` (tests: `tests/test_pack_org.py`):

* **Semantic Graph** (partial): nodes with the shared metadata (kind, status, context, project, validity window,
  dependencies, relations, created/edited); content stored once by SHA-256; a dependency DAG that refuses cycles;
  a query line (`project:alpha edited:today`, `valid:today`, `needs:n3`, ...); project-by-state matrix;
  critical-path planner (earliest/latest start, slack, due-date check); history as a hash chain with "as of a date".
* **Rule Router** (partial): event-condition-action rules in a small declarative text, saved as numbered,
  hash-chained versions that are never overwritten (a rollback is a new version). Loops are cut off.

## Section by section

| Blueprint item | Status | Where / why |
|---|---|---|
| 1. Semantic Object Kernel (typed objects instead of POSIX bytes) | **Not buildable as an app** | Linux I/O is bytes. The app-to-OS channel already carries schema-checked JSON commands (`kos/protocol.py`); that is as far as KOS goes. |
| 1. ACID state persistence | **Partly** | One app's data is saved with an atomic whole-file write, and Semantic Graph builds each change on a copy and saves nothing if it fails. There are no multi-file or kernel-wide transactions. |
| 1. Microkernel isolation of workflow engines | **Partly, by design** | Each app is a sandboxed process (Landlock, namespaces, seccomp) and `kos cell` runs code in KVM micro-VMs. There are no organizational daemons to separate from drivers. |
| 1. Deterministic per-workspace CPU/RAM allocation | **Not built** | Limits are per app and fixed (`kos/sandbox.py`). No workspace scheduler. |
| 2. Semantic Graph File System | **Not a file system** | Semantic Graph is a graph of one app's own items in its private vault. `kos ls` still shows folders. |
| 2. Global metadata on every entity | **In the app only** | Every Semantic Graph node has it. Files, processes and windows do not. |
| 2. Content-addressable, deduplicated storage | **In the app only** | Identical content in Semantic Graph is stored once under its SHA-256; a body that does not hash to its key is dropped on load. The OS does not deduplicate files. |
| 2. Zero-latency kernel indexing | **In the app only** | Semantic Graph rebuilds its index inside every change, so a query never sees a stale one. No kernel hook exists. |
| 3. Matrix workspaces, dynamic layouts | **Not built** | No window manager (`kos boot desktop` lists apps one at a time). The matrix view counts Semantic Graph nodes by project and state. |
| 3. Hibernate / fork / restore whole workspaces (registers, memory) | **Not built** | Running apps cannot be paused or forked. Semantic Graph can show its own data as of a past date. |
| 3. Universal tagging and query pipeline across the desktop | **In the app only** | The query line works over Semantic Graph. Other apps keep separate data; they share records only through granted shared folders (`kos grant`). |
| 4. Atomic component applications | **Not built** | An app is a whole program with its own screen; one cannot embed another's view. |
| 4. Universal data bus (rich copy/paste, drag and drop) | **Not built** | Shared folders are the only app-to-app path. |
| 4. Sandboxed stateless runtimes, mutation only through the graph | **Already true, differently** | Apps run sandboxed and their private vault is the only place they write. It is a plain vault, not a graph. |
| 4. Structured terminal pipelines | **Not built** | `kos line` runs one command per line and has no pipes. |
| 5. Declarative, version-controlled OS state | **Not built for the OS** | Rule Router versions its own rules. OS state is spread over several files and the kernel command line. |
| 5. Kernel ECA router | **Not built** | No OS event bus. Rule Router reacts only to events you fire inside it, and its actions change only its own state and log. It cannot mute alerts, commit code or switch views. |
| 5. Temporal audit log | **Partly** | `kos audit --verify` is a hash-chained log of password decisions (OS level). Semantic Graph has its own change chain. Neither records every file change. |
| 5. Dependency resolution and critical path | **Done for tasks in the app** | Semantic Graph: topological order, earliest/latest times, slack, lateness. Calendar days; no working-day calendar or resources. |

## Honest limits of what was built

* Nothing is encrypted yet (README, "Pipeline encrypted"). Semantic Graph and Rule Router data sit in clear in the
  app's vault on the encrypted volume.
* The history and version chains catch accidental damage and naive edits. They are not signed: whoever can rewrite
  the app's whole data can recompute them.
* Limits are small on purpose (150 nodes, 4,000 characters per node, 100,000 characters of kept content,
  200 history entries before the oldest are folded, 40 rules, 30 config versions). A change that would exceed one is
  refused and nothing is saved.
* Not tested: a run inside the real Landlock sandbox with a real screen (the tests drive the screens with a scripted
  host, as the other packs do).
