# kosync format, version 1

Everything a client on another platform (Swift on iPhone/macOS, Kotlin on Android, C# on Windows) needs to
read and write the same data. `vectors.json` holds known answers; a new client must reproduce them before it
touches real data. All integers are big-endian. Primitives: **scrypt**, **HKDF-SHA256**, **ChaCha20-Poly1305**
(RFC 8439, 12-byte nonce, 16-byte tag), **HMAC-SHA256**. Nothing else.

## Keys

```
master  = scrypt(NFC(password) as UTF-8, salt, n, r, p, length 32)
subkey(label) = HKDF-SHA256(ikm=master, salt=none, info="kosync/v1/" + label, length 32)
```

A reader must refuse settings outside: `n` a power of two in 4096..1048576, `r` 1..16, `p` 1..4, and
`128*n*r <= 512 MiB` (the file is attacker-controlled; this stops a memory bomb). Default for new files:
`n=32768, r=8, p=1`. Passwords shorter than 8 characters are refused when creating.

## The encrypted stream (used by bundles, objects and lists)

```
stream  = salt(16 random bytes) | chunk+
chunk   = u32 length | ciphertext          (length = plaintext length + 16, at most 1 MiB + 16)
streamkey = HKDF-SHA256(ikm=key, salt=salt, info="kosync/v1/stream", length 32)
nonce   = 0x00000000 | u64 chunk counter   (counter starts at 0)
AAD     = caller's aad | u64 counter | 0x01 if this is the LAST chunk else 0x00
```

Plaintext is cut into 1 MiB chunks; the last chunk may be any size from 0 to 1 MiB (an empty file is one empty
chunk). Because the "last" flag is authenticated, a stream that was cut, extended, reordered or had a chunk
repeated fails. A reader must reject a stream whose last chunk is missing, with bytes after the last chunk,
or with a chunk length outside 16..1 MiB+16. **Do not use decrypted output until the whole stream has verified.**

## Bundle (`*.kmig`) - migration

```
"KOSMIG1\n" | u32 header_length (2..4096) | header | stream
header = JSON {"v":1,"kdf":{"alg":"scrypt","n":..,"r":..,"p":..},"salt":"<32 hex>"}  (exact bytes are the AAD tail)
key    = subkey(master, "bundle");   stream AAD = "KOSMIG1\n" | header
plaintext = u32 manifest_length (1..64 MiB) | manifest JSON | file bodies, in manifest order, concatenated
manifest  = {"format":1,"created":int,"source_os":str,"entries":[...],"apps":[{"manager","name"}],"skipped":[...]}
entry     = {"role":one of documents|pictures|music|videos|downloads|desktop|config|other,
             "path":"relative/with/forward/slashes","kind":"file"|"dir","mode":int,"mtime":int(seconds),
             and for files "size":int,"sha256":"<64 hex>"}
```

An importer must: reject any path that is empty, absolute, contains a `.` or `..` part, an empty part, a
control character, or is longer than 4096 bytes; check every body against its size and SHA-256; verify the
whole stream before moving any file into place; never write through a symbolic link; never overwrite a
different existing file (keep both); make names legal for the target OS and report every change.

## Shared folder (`sync`)

```
kosync.json   {"format":1,"vault":"<32 hex>","kdf":{...},"salt":"<32 hex>","check":"<hex of a stream>"}
              keys: enc=subkey("vault-enc"), id=subkey("vault-id"), index=subkey("vault-index")
              check = stream(key=index, aad="check:"+vault, plaintext="kosync vault check")
objects/<first 2 hex of id>/<id>   stream(key=enc, aad="object:"+id, plaintext=file bytes)
              id = HMAC-SHA256(key=id-key, file bytes) as 64 hex; a reader recomputes it after decrypting
index/<device>.idx   stream(key=index, aad="index:"+device, plaintext=JSON)
              {"device":dev,"vault":vault,"seq":int,"entries":{path:{"id":hex|null,"at":int,"size":int,"mtime":int}}}
```

`device` is `[a-z0-9][a-z0-9-]{0,31}`. A device only ever writes its own `index/` file and never edits an
object (write to a temporary name, then rename). `id: null` is a deletion. `at` is the time (nanoseconds) the
change was made. `seq` goes up by one each run; a reader that has seen sequence *n* from a device must refuse a
list with a lower one (this detects an old copy of the folder being put back).

### Merge rule (per path, per run)

`L` = this device's file now, `B` = what this device last agreed on, `R` = the entry with the highest `(at,
device)` from the *other* devices (or `B` if none). Compare by `id`:

| case | action |
|---|---|
| `L == R` | nothing |
| `L == B` | take `R` (download, or delete if `R` is null) |
| `R == B` | publish `L` (upload, or a null entry if deleted) |
| both changed, one is a deletion | the edit wins (the file comes back) |
| both changed | `R` takes the name; `L` is renamed `name (conflict DEVICE YYYYMMDD-HHMMSS).ext` and published |

A name that is illegal on this OS, or that already belongs to a different local file, is skipped and reported.
