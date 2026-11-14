# kosync - migrate and sync your data across operating systems

Two separate programs, one encrypted format. Runs on **Linux, macOS and Windows** (Python 3.9+, `pip install
cryptography`). iPhone and Android: see [what is and is not here](#what-is-and-is-not-here).

```
python -m kosync migrate export --root documents=~/Documents --root pictures=~/Pictures --apps --out move.kmig
python -m kosync migrate inspect move.kmig --target-os windows        # verifies everything, writes nothing
python -m kosync migrate import  move.kmig                            # on the new OS: default folders
python -m kosync migrate import  move.kmig --dest documents=D:\Docs --overwrite

python -m kosync sync init   /mnt/usb/vault                           # once, on a shared folder
python -m kosync sync run    /mnt/usb/vault ~/Documents --device laptop
python -m kosync sync run    Z:\vault       C:\Users\me\Documents --device desktop --dry-run
```

The password is asked for (or read from `--password-file`), never put on the command line.

## Migration: keep everything, change the OS

`export` writes one encrypted, checksummed bundle of the folders you name (documents, pictures, music, videos,
downloads, desktop, config, other) and, with `--apps`, the list of installed apps. `import` on the new OS:

* verifies the **whole** bundle before it puts a single file in place (a damaged or cut bundle changes nothing);
* fixes names the new OS cannot hold (`a:b.txt`, `CON`, trailing dots, case-only differences) and **prints every
  rename**; two names that collide both survive (`name (copy 2)`);
* never overwrites: a different file already there means both are kept (`name (imported 1).ext`), an identical one is
  left alone; `--overwrite` is the only way to replace;
* never follows or writes through a symbolic link, never writes outside the folder you gave it;
* prints (never runs) install commands for apps it knows by name on the new OS, and lists the rest.

## Sync: one folder on many machines

The shared folder is a dumb mailbox - a USB stick, an SMB share, a cloud-drive folder, a Syncthing folder. It holds
only ciphertext (it learns sizes and when you sync, not names or contents). Each machine runs `sync run`; there is
no server and no network code in kosync itself. A conflict never loses data: the other machine's version keeps the
name and yours is kept beside it as `name (conflict DEVICE DATE).ext`.

## What is and is not here

Tested (60 tests, `python3 -m unittest tests.test_kosync`, plus deliberate-breakage checks of the safety rules):
the format, tampering and truncation refusals, name translation, symlink and traversal refusals, multi-device sync
with conflicts, deletes and a third device, the command line.

**Not done, and not claimed:**

* **No iPhone or Android app.** There is no Xcode, Android SDK or device here. [PROTOCOL.md](PROTOCOL.md) and
  `vectors.json` are the byte-exact contract for writing one in Swift/Kotlin. Running this Python client on a phone
  (Termux on Android, a-Shell/Pythonista on iOS) was **not tried**; whether `cryptography` installs there is unknown.
* **Only run on Linux.** The Windows and macOS rules are written from their documented file-name limits and tested
  as pure functions and simulated (a fake case-insensitive disk), not on a real Windows or macOS machine. The app
  lists use `winget`/`brew`/`apt` and were tested with fake command runners only.
* Not covered: file permissions beyond the mode bits, extended attributes, Windows ACLs and alternate streams, macOS
  resource forks and Finder tags, empty folders in sync, hard links, files over 1 GiB in sync (skipped and reported).
* Sync does not delete unused objects (the shared folder only grows), does not detect an old copy of the *whole*
  shared folder that this machine has never seen, and its `at` times rely on each machine's clock only to pick between
  two other machines' changes.
* Not a KOS app. See the gap in the main README: KOS apps cannot read or write arbitrary files, so a KOS front-end
  needs new OS services first.
* The encryption is vetted primitives used as documented, but has had **no independent review**.
