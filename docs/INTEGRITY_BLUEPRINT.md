# "Zero-state disruption" system integrity blueprint: what KOS does, what it does not

The blueprint asks for a backup that captures every layer of a machine - flash cells, firmware variables, live
kernel memory, the registry, home folders, app sandboxes, keys and attached devices - so that a restore leaves
nothing disturbed. This page maps each section to the code and says plainly what is real and what is not.
**KOS cannot meet the goal as written, and nothing here claims it does.**

The deciding facts (README rules 1-5): every KOS app is sandboxed and cannot read your files, devices or other
apps' data; only the OS touches hardware; every action needs the password; and KOS keeps no key lying around.
A "capture everything" feature fights all four. What can be built is the part that lives in files, behind the
password.

## What exists now

| Blueprint idea | KOS | Where |
|---|---|---|
| A place for every kind of data, with permissions | 27 standard folders in 4 groups, owned by the OS, closed to every app until granted with the password | `kos folders create`, `kos/folders.py` |
| Files and folders, deduplicated, scanned, sealed | Content-addressed backup vault; restore is a guarded write that never overwrites | `kos backup add/list/restore/remove`, `kos/backup.py` |
| Applications and licenses inventory, without the bulk | An app is backed up as its https address and SHA-256, not its bytes; restore downloads, checks the hash, scans, then installs with the password | `kos backup link/links/fetch/unlink`, `kos/applinks.py` |
| Tamper evidence | Both indexes are HMAC-sealed under a password-derived key; every blob is re-hashed on read | `kos/backup.py`, `kos/applinks.py` |
| Permission bits and ACL rules | The permission store (`grants.json`) is the one list of who may touch which folder | `kos grant`, `kos spaces` |

## Section by section

**Bare-metal and low-level hardware state** (raw sector images, MBR/GPT, HPA/DCO, NVRAM/CMOS, UEFI keys, SMM,
DRAM timings). *Not built.* Reading these needs root on the machine or firmware tools, and an app cannot have
that. KOS writes a GPT only when it makes a boot stick (`kos usb`) and only looks at firmware management
processors (`kos firmware`); it does not image a disk. A raw image of a LUKS2 disk is also a copy of the
encrypted volume's header, which is an attack surface; that is a decision for the owner, not a default.

**Live execution, volatile memory and kernel space** (hibernation image, page files, thread contexts, open
sockets, unlocked encryption keys, DMA maps). *Not built, and not wanted in part.* Capturing live memory
would copy the unlocked disk key and every password-derived key out of the places KOS works to keep them. KOS
holds keys only while an action runs (`kos/secret.py`) so that there is nothing to capture. Checkpointing a
process is a kernel feature (CRIU, kdump) and would be an OS component with the password, not an app.

**Operating system configuration** (registry, dconf, GPO, SIDs, routing and ARP tables, `/etc/hosts`, firewall
state, audio graphs, locales, update state). *Folders only.* `os-settings`, `appearance`, `locale`,
`hardware-config` and `scheduled-tasks` exist as places to keep exported settings. Nothing reads the live
settings for you. KOS has no firewall yet (README gaps table).

**Low-level user space** (home folders, environment, shell history, SSH/GPG keys, package managers, `.git`,
cron). *Partly.* `kos backup add PATH` backs up any files you name, scanned first, and skips KOS's own state
(password verifier, seals, vault). It does not know which dotfiles matter, does not follow symlinks, and stops at
5,000 files per add and at the scanner's file size limit. Private keys are ordinary files to it; if you add them
they are stored in the vault unencrypted beyond the LUKS2 disk. Think before adding them.

**Application sandboxes and state** (app databases, saved window layouts, browser profiles, messaging
databases, game saves, licenses). *Folders and apps.* An app keeps its own data in its private vault and in the
shared folders it is granted (`app-data`, `game-saves`, `web-offline`, `browser-addons`, `app-inventory`).
Apps are restored from their links. Another app's private data is not reachable by design.

**Security infrastructure and identity** (keychains, TPM keys, MFA seeds, biometric templates, 802.1X and VPN
secrets, ACLs, SELinux contexts). *Folders only, for good reason.* The folders `keychain`, `biometrics`,
`cloud-identity`, `boot-partitions`, `access-rules`, `network-profiles` and `accounts` are marked `sensitive` and
need a grant like any other. TPM endorsement and storage root keys cannot be exported by design; biometric
templates and MFA seeds are things you re-enroll, not copy. KOS does not read any of them.

**Peripherals and inter-device state** (Bluetooth keys, CNC and printer calibration, drone ground-station data,
input-device profiles, camera LUTs, USB mount maps). *Folders only* (`peripherals`, `hardware-config`).

## How the folders map to the lists you gave

| Group | Folders |
|---|---|
| User data and media | `media` `documents` `messages` `contacts` `bookmarks` `calendar` `voice-notes` `notes` |
| System and environment | `appearance` `os-settings` `network-profiles`* `hardware-config` `scheduled-tasks` `peripherals` `locale` `shell-env` |
| Application ecosystem | `app-inventory` `app-data` `game-saves` `browser-addons` `accounts`* `web-offline` |
| Security and identity | `keychain`* `biometrics`* `cloud-identity`* `boot-partitions`* `access-rules`* |

\* sensitive. `contacts` and `calendar` are also names that Contact Manager and Calendar Manager *own* as
app-created shared folders. `kos folders create` leaves a name an app already owns alone and reports it.

## What would be needed to get closer

1. A privileged OS component (not an app) for disk, firmware and memory capture, behind the password and the
   administrator keyboard, with its own scan and audit entries.
2. The encryption layer the README says is missing, so a vault holding keys is not plain files on LUKS2. This
   needs a vetted library; adding a dependency is the owner's call.
3. A firewall, so the download in `kos backup fetch` is one rule among many rather than the one place KOS
   itself opens a connection to an app-chosen host.
