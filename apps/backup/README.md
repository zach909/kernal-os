# backup

A group of apps. This folder has no `manifest.json`, so **the group itself has no permissions**;
each app below has its own manifest and asks only for what it needs.

| program | folder | asks the OS for |
|---|---|---|
| `backup.list` | `list/` | `ask:backup` (the list and the savings) |
| `backup.add` | `add/` | `ask:backup_add` (back up one path) |
| `backup.remove` | `remove/` | `ask:backup`, `ask:backup_remove` (see the list, forget one item) |

```
kos pack apps/backup -o dist/backup      # one .kapp per app
kos install dist/backup                  # each asks for the password
kos permit backup.list                   # one app at a time; `kos permit backup` is refused
run backup.list
```

`backup.add` cannot list or remove, `backup.list` cannot add or remove, and none of them can open,
close or switch to other apps. The OS still asks for your password in its own prompt for every
action, exactly as for the single-app version in `examples/backup`.
