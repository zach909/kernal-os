# sync

A group of apps that keep one folder the same on two linked devices, without losing a byte. Each app has its
own manifest and asks only for what it needs; the group has no permissions.

| program | folder | asks the OS for |
|---|---|---|
| `sync.folders` | `folders/` | `service:sync` (the folders chosen for syncing) |
| `sync.share` | `share/` | `service:sync` (choose a folder, under a name) |
| `sync.unshare` | `unshare/` | `service:sync` (stop syncing one; its files stay) |
| `sync.run` | `run/` | `service:sync` (sync one folder with a linked device that is waiting) |
| `sync.serve` | `serve/` | `service:sync` (wait for one linked device and let it sync) |

Run `sync.serve` on one device, then `sync.run` on the other. A connection is **blocked by default**: each side
needs a firewall rule for the app `sync` (tcp, connect or listen, that one address and port), and the OS says so
and logs it when there is none.

Nothing is lost: a file that changed on both sides is kept both ways (`name (conflict ... ).ext`); a file that
goes away is moved to `.kos-trash/` under its content hash; an edit beats a delete; a file changed after it was
listed is refused and re-planned, never overwritten. A linked device names a *folder* you chose, never a path.
See `kos/syncer.py` for the exact rules and what it does not do (no rename detection, whole files only,
no timestamps or permissions, symlinks skipped).
