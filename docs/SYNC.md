# KOS linked devices and sync: the wire format

**Status: implemented and tested in KOS (`kos/linkdev.py`, `kos/syncer.py`, `kos/migrate.py`). There is no
native iPhone, Android, Windows or macOS client in this repository.** This document is what such a client must
implement, with test vectors produced by the real code, so one can be written in Swift, Kotlin, C# or anything
else that has Ed25519, X25519, HKDF-SHA256 and ChaCha20-Poly1305. `tests/test_sync_spec.py` implements sections 2
to 4 of this document from scratch, using only those primitives, and checks that the result talks to the real code
and reproduces the vectors below byte for byte.

## What a non-KOS client does and does not get

A KOS machine confines what a linked device may do: a password on the *receiving* device, an audit line, a firewall
rule, a sandbox. **A phone or desktop that is not KOS gets none of that on its own side.** It is a remote party
holding a key (`docs/MESH.md`, "Scope limit"). Everything a KOS peer receives from it is hostile input and is
checked; everything it receives from a KOS peer is its own business to protect. A non-KOS client that wants the same
promises has to build them itself: ask its owner before applying changes, keep the trash, never follow a path out of
the folder. The sections below say what is *required* of a client for the link to work.

## 1. Vocabulary

* **Device identity**: one Ed25519 key pair per device, made once. `device_id` is the first 32 hex characters of
  SHA-256(public key). The public key is what is pinned when two devices are linked.
* **Platform**: one of `kos`, `linux`, `windows`, `macos`, `android`, `ios`.
* **Link**: two devices that have each pinned the other's public key, made in person (section 4).
* **Initiator** opens the TCP connection; **responder** accepts it. Either device can be either.

All numbers in messages are whole numbers. **A message with a decimal point, an exponent, `NaN` or `Infinity` is
refused.** All text is UTF-8.

## 2. The channel: handshake and records

One TCP connection is one session. `LABEL` is the 11 ASCII bytes `kos:link:v1`.

### 2.1 Handshake (three messages, mutually authenticated, forward secret)

```
I -> R   eph_i (32)  id_i (32)  nonce_i (16)                       80 bytes
R -> I   eph_r (32)  id_r (32)  nonce_r (16)  sig_r (64)           144 bytes
I -> R   sig_i (64)                                                64 bytes

eph_*    fresh X25519 public key, new for every connection
id_*     the sender's Ed25519 identity public key
nonce_*  16 random bytes
T        = eph_i || eph_r || id_i || id_r || nonce_i || nonce_r    176 bytes
sig_r    = Ed25519_sign(id_r private, LABEL || "R" || T)
sig_i    = Ed25519_sign(id_i private, LABEL || "I" || T)
```

Both signatures cover both ephemeral keys, so a signature cannot be moved into another exchange.

```
shared   = X25519(own eph private, peer eph public)
salt     = SHA-256(LABEL || T)
okm      = HKDF-SHA256(ikm = shared, salt = salt, info = LABEL || "keys", length = 64)
key_i2r  = okm[0:32]           (what the initiator sends with)
key_r2i  = okm[32:64]          (what the responder sends with)
sas      = HKDF-SHA256(ikm = shared, salt = salt, info = LABEL || "sas", length = 4)
code     = (big-endian integer of sas) mod 1000000, written as 6 digits with leading zeros
```

Checks, in this order. **On any failure, close the connection at once.**

1. The peer's identity public key must not equal your own.
2. If you mean to reach a linked device, the peer's identity must equal the key you pinned. A different key is a
   refusal ("not the device this link was made with"). A responder reads the first 80 bytes, looks the claimed
   `id_i` up among its pinned keys, and closes if it is not there, before sending anything.
3. The peer's signature must verify.

Handshake timeout: 15 seconds per read.

### 2.2 Records (after the handshake)

```
record      = length (4 bytes, big endian) || ciphertext
length      = number of bytes in ciphertext (plaintext length + 16)
ciphertext  = ChaCha20-Poly1305(key, nonce, aad = the 4 length bytes, plaintext)
nonce       = 0x00 0x00 0x00 0x00 || counter (8 bytes, big endian)
plaintext   = type (1 byte) || payload
type        0 = DATA (the payload is one JSON message)     1 = CLOSE (payload empty)
```

* Each direction has its own key (`key_i2r` for what the initiator sends) and its own counter, starting at 0 and
  going up by exactly one per record. A record whose counter is not the next expected one fails to decrypt: that is
  how replay, reordering and dropped records are caught. **Any failure ends the session. There is no recovery.**
* `length` must be between 17 and 1 048 593. A payload is at most 1 048 576 bytes.
* The sender ends a session by sending a CLOSE record. A connection that ends without one was cut, and must be
  treated as an error, not as "finished".

### 2.3 Test vectors (handshake and one record)

```
initiator identity seed     000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
responder identity seed     202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f
initiator identity public   03a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8
responder identity public   29acbae141bccaf0b22e1a94d34d0bc7361e526d0bfe12c89794bc9322966dd7
initiator device_id         56475aa75463474c0285df5dbf2bcab7
responder device_id         24f6ed6acbfe1009c030d7ca567c33ca
initiator eph private       404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f
responder eph private       606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f
nonce_i                     808182838485868788898a8b8c8d8e8f
nonce_r                     909192939495969798999a9b9c9d9e9f

message 1 (I -> R)          79a631eede1bf9c98f12032cdeadd0e7a079398fc786b88cc846ec89af85a51a03a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8808182838485868788898a8b8c8d8e8f
message 2 (R -> I)          675dd574ed7789310b3d2e7681f3790b466c773b1521fecf36577958371ea52f29acbae141bccaf0b22e1a94d34d0bc7361e526d0bfe12c89794bc9322966dd7909192939495969798999a9b9c9d9e9f0b192043302b1767f68387144900f818137559c8da98dfbd4affc548a37e23809eb837fc700a9612ec0766ef41494a97a61afb6f1ebbbd744f9aa209b912ae0a
message 3 (I -> R)          cf5c97b42a8ecf88579bd5373b02d8b7463057d451c272b936a7b6cf1ba8ab54bf3b63062faffde8e76143b7fd5e54a52f52fc38ec7b71e4e5233d8b1fabe802
code (both screens)         389285

first record, I -> R, counter 0, plaintext = 0x00 followed by this JSON (127 bytes, no spaces):
  {"t":"req","id":1,"action":"sync.read","target":"space docs","args":{"space":"docs","mode":"manifest","after":"","limit":1500}}
record on the wire          0000009022c9bcd397a85c936f8b1164976caf0df5be66553ae6f01ed494b870df90346a7c238ae48de37bcf7ca1e3211b3e6492cb5493a380ab449c1884fa3e306a7addfd1878a38f85cc0ed6493c452e3c29708e3ad34a21fc015d5a740ba93a8c23e68e152d8fba5a363aa1c931818fded8ba6e0a68234faae92742c790875e8b7cbcdeb31654d6b64bf25469d69a904e1511
```

The identity "seed" is the 32-byte Ed25519 private key in RFC 8032 form. The ephemeral private keys are fixed here
only so that the vectors are reproducible; a real client draws fresh ones for every connection.

## 3. Messages

Every message is one JSON object in one DATA record.

### 3.1 Request and response

```
request   {"t":"req","id":N,"action":"file.view","target":"notes","args":{...}}
response  {"t":"res","id":N,"ok":true,"detail":"","data":{...}}
          {"t":"res","id":N,"ok":false,"detail":"why, in words fit to show a person","data":{}}
```

* `id`: a whole number from 1 to 2 147 483 647, chosen by the asker and echoed back. One request at a time.
* `action`: lowercase letters, digits and dots, at most 64 characters. It must be one of KOS's action names.
* `target`: text, at most 200 characters, no control characters. It is what the *other owner's password prompt
  shows*, so say what it is for (for example `space docs`).
* `args`: an object (may be empty or omitted).
* A request with extra fields, a bad `id`, or anything that is not a request **ends the session**.
* `detail` is at most 300 characters.

### 3.2 Who may ask for what

A link grants scope `all`: a linked device may ask for **any action** KOS has, except these, which are **always
refused** because they would let one device take over the other for good, or need a person at the machine:

```
auth.change  session.login  admin.boot  device.mouse  device.keyboard  device.desktop
link.add  link.remove  link.list  link.connect  link.listen  link.identity  link.scope
```

An owner can **pause** a link (scope `paused`): every request is then refused until it is resumed.

**Asking is not getting.** The device that holds the resource types its own password before it answers: once per
(action, target) for the life of a connection, and **every time** for every action whose name starts with `app.`
except `app.list` (which only reads), and for these:

```
file.write  code.run  space.grant  space.revoke  firewall.change  backup.restore  disk.optimize
cell.start  cell.stop  runtime.add  runtime.remove  scan.watch  migrate.import
```

A KOS device also limits how often a linked device can make its owner type the password: at most 6 password
requests a minute per connection, and after 5 refused requests every further request is answered "no" without a
prompt. A message flood ends the connection.

**A client must therefore expect a long wait for a response** (a person is typing a password) and must not time out
in under several minutes. An owner who says no gets `ok:false` and a `detail` beginning "the owner of this device
said no".

Which actions a KOS device *answers* is a separate matter: an action with no handler is refused as "cannot do ...
yet". Today a KOS device answers `sync.read` and `sync.apply` (section 5) for linked devices; wiring more of the
OS's actions to linked devices is future work, and nothing here pretends otherwise.

## 4. Linking two devices (pairing)

In person, with both screens in view.

1. Open a connection. Run the handshake (2.1) with **no pinned key** on either side.
2. Each side sends `{"t":"hello","name":"...","platform":"..."}`. The name is 1 to 40 printable characters and the
   platform is from the list in section 1. Anything else is refused. Show the name as *text*: the other device chose it.
3. **Both screens show `code`.** The owner compares them. A man in the middle is a different endpoint on each side, so
   the codes differ. **A client must never accept on its own.**
4. Each owner types their own device's password. On a device with no password concept, a platform passcode or
   biometric is the closest thing, and is a weaker promise.
5. Each side sends `{"t":"pair","ok":true}` (or `false` if its owner said no). **Pin the other device only after
   receiving `ok:true` from it and having sent `ok:true`.** If either said no, or the connection drops first, store
   nothing.
6. What is pinned: the public key, the name, the platform, scope `all`, and the time. Keep it where an attacker with
   the unlocked app cannot quietly edit it (KOS seals it under the password with an HMAC and treats a mismatch as "no
   links at all").

## 5. Sync

Sync keeps one named folder the same on two devices. A linked device names a **folder the owner chose**, never a path.
There are two actions: `sync.read` (the holder of the folder lists and serves it) and `sync.apply` (the holder is told
to change its files). `target` is always `space NAME`, so the owner's prompt says which folder.

### 5.1 Paths (hostile input; all of this is checked on receipt)

A synced path is relative, uses `/`, and is **refused** (not repaired) if it:

* is empty or not text, is over 1024 bytes, has a part over 255 bytes, or has more than 64 parts;
* has an empty part, a `.` part or a `..` part;
* contains a control character or a bidirectional-override character, or contains a backslash;
* starts with `/`, or starts with a drive letter (`C:`; this includes the single-letter-then-colon form `a:b`, which
  Windows reads as a drive-relative path);
* has any part that starts with `.kos-`.

Never follow a symlink anywhere on the way down to a file, and never write through one.

A **Windows** device cannot hold names containing `<>:"|?*\`, a part that is `con prn aux nul com1`..`com9`
`lpt1`..`lpt9` (with or without an extension), or a part ending in a space or dot. A **macOS or Windows** device also
cannot hold two paths that are equal after Unicode NFC and case folding. A KOS device does **not send** such paths to
a device of that platform and reports them. A Windows or macOS client must likewise refuse such a path rather than
rename it: a rename would make the two sides disagree for ever.

### 5.2 `sync.read`

```
manifest page   args {"space":"docs","mode":"manifest","after":"","limit":1500}
                data {"files":{"a/b.txt":{"h":"<sha256 hex>","n":1234}},"next":"<last path, or empty>","skipped":["..."]}
chunk           args {"space":"docs","mode":"chunk","path":"a/b.txt","offset":0,"length":196608}
                data {"data":"<base64>","eof":true}
```

* A manifest is **paged**: `limit` is 1 to 1500. Start with `after` empty, then ask again with `after` set to the
  previous `next` until `next` is empty. Paths are in byte order. At most 100 000 files, each at most 1 GiB.
* `h` is the lowercase hex SHA-256 of the whole file; `n` is its size in bytes.
* A chunk is at most 196 608 bytes (192 KiB, so base64 stays far under the 1 MiB record limit). `eof` is true when the
  bytes sent reach the end of the file.
* Symlinks, devices, and the folder's own bookkeeping (`.kos-trash`, `.kos-tmp-*`) are not listed.

### 5.3 `sync.apply`

Every call takes `{"space":"docs","op":...,"path":...}` plus:

```
begin   "size":N, "hash":"<sha256>", "replaces":"<sha256 of the file you expect to replace>" or null
chunk   "offset":N, "data":"<base64, at most 196608 bytes>"     (in order: offset = bytes sent so far)
end                                                             response data {"hash":"..."}
trash   "hash":"<sha256 the file must still have>"              response data {"trashed":true}
```

* **Nothing is written until the bytes are right.** The receiver writes a temporary file in the same folder, checks
  size **and** SHA-256, and only then moves it into place. Wrong bytes: nothing is written.
* **Compare-and-swap.** `replaces` must equal the SHA-256 of what is there now (null if nothing is). If the file
  changed since the manifest was read, the receiver refuses ("changed since it was listed") and the asker plans again.
  The old file is moved to `.kos-trash/<its sha256>` before the new one takes its place.
* **No deletes.** `trash` moves a file to `.kos-trash/<sha256>` only if it still has that hash. Keep the trash
  (recommended: at least the newest 1000 items).
* At most 8 files are open at once. A failed file is abandoned and its temporary file deleted; a connection that ends
  mid-file leaves no partial file behind.

### 5.4 Deciding what to do (the asker does this, from three manifests)

For each path, with local hash L, remote hash R, and the hash at the last successful sync B (absent means none):

| situation | action |
|---|---|
| L = R | nothing (it becomes the new B) |
| L = B, R differs | take the remote: pull it, or move the local file to the trash if the remote removed it |
| R = B, L differs | send ours: push it, or ask the remote to trash its copy if we removed it |
| removed on one side, edited on the other | **the edit wins** |
| both changed, differently | **keep both**: save the remote's version beside ours as `name (conflict <peer id first 8> <remote hash first 8>).ext` (no extension: `name (conflict ...)`), then push ours |

After a pass, B for each path that finished is the agreed hash. A path that failed is left out of B, so the next pass
sees it as unfinished.

## 6. Migration bundle (`.kmig`)

For moving everything to another computer or operating system. One file: a header, then records.

```
header   "KOSMIG1\n" (8) || salt (16) || scrypt N (4, BE) || r (4, BE) || p (4, BE)       = 36 bytes
         N is a power of two from 2^10 to 2^17 (default 2^15); r = 8; p = 1
key      = scrypt(passphrase as UTF-8, salt, N, r, p, 32 bytes)        passphrase at least 12 characters
record   = length (4, BE) || ChaCha20-Poly1305(key, nonce = 4 zero bytes || counter (8, BE),
                                               aad = SHA-256(header) || counter (8, BE), type || payload)
types    1 META      {"v":1,"created":int,"source_os":text,"files":int}     first, once
         2 BEGIN     {"p":"files/<root>/<path>" | "kos/apps/<name>.kapp" | "kos/permissions/grants.json",
                      "n":size, "m":mode bits, "t":mtime in seconds}
         3 DATA      at most 196608 bytes
         4 END_FILE  {"h":"<sha256 of that file's bytes>"}
         5 END       {"files":int, "bytes":int, "digest":hex, "skipped":[text, ...]}     last; nothing may follow
digest   = SHA-256 over, for each file in archive order, "<path>" NUL "<sha256>" newline
```

A reader must verify **everything** before writing a single file: every record's authentication, every file's size
and SHA-256, the file count, the byte total, the digest, that END exists and is last, and that no path appears twice.
A bundle with no END, extra data after END, or any failed check is refused in full. Paths are checked as in 5.1.
Never overwrite: a different file already there is kept and the migrated copy goes beside it as
`name (migrated <hash first 8>).ext`. Never convert bytes (line endings, encodings). Drop setuid, setgid and
world-write from modes.

## 7. What is not covered

* No client for iPhone, Android, Windows or macOS exists here. This is the specification and the vectors only.
* No discovery (mDNS, Bluetooth, QR) and no NAT traversal. A link needs an address and a port, and on KOS a firewall
  rule for it. A phone on a carrier network is not reachable without something more.
* No rename detection (a rename is a delete plus a new file), no delta transfer (whole files), no resume of a
  half-sent file across connections, and no timestamps, permissions, extended attributes or symlinks in sync.
* Private identity keys on KOS are sealed under the password, not held in a TPM or secure enclave. On other platforms use
  the platform keystore (Keychain, Keystore, DPAPI); that is a stronger or weaker promise depending on the device.
* Message sizes and timing are visible to anyone watching the network. Content is not.
