# migrate

Two apps that move everything you have to another computer or another operating system. Each has its own
manifest; the group has no permissions.

| program | folder | asks the OS for |
|---|---|---|
| `migrate.export` | `export/` | `service:migrate` (pack folders, apps and permissions into one encrypted bundle) |
| `migrate.import` | `import/` | `service:migrate` (unpack a bundle, verified completely first) |

The bundle is one `.kmig` file, encrypted under a passphrase you choose (not your KOS password: it has to work where
KOS is not installed). Import reads the whole bundle once to check every chunk and every file's SHA-256, and only
then writes: a wrong passphrase, a flipped bit, a cut-short or reordered bundle changes nothing. It never overwrites
(a different file already there is kept and the migrated copy goes beside it), never converts bytes, and renames
only what the target cannot hold (Windows: `a:b`, `con`, a trailing dot; macOS and Windows: names that differ only
by case or accents), listing every rename in `MIGRATION-REPORT.txt`.

Not carried, on purpose: your password, the audit log, firewall rules, the AI key, and this device's link
identity. Apps and the old permission list arrive in `kos-staging/` for you to install and re-grant.
It does not install an operating system: install the new one, then import. See `kos/migrate.py`.
