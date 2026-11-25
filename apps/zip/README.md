# zip

One app: drop in a zip, its program runs. The group has no permissions; the app asks for `service:zip` only.

| program | folder | asks the OS for |
|---|---|---|
| `zip.run` | `run/` | `service:zip` (scan, check and run a zip's program in the sandbox with no permissions) |

Type the path of a zip file. The OS scans it, inspects it (no `..` or absolute names, no symlinks, no encrypted entries,
no zip bomb, at most 300 entries and 24 MiB unpacked), proves it (a packed `.kapp` carries its own `proof.json`; a plain
source zip gets its proof worked out from the exact bytes, as `kos pack` does; code with a decimal, a banned call or that
does not compile is refused), asks your password **once** naming the program, the zip's SHA-256 and what it *asked* for,
and runs it sandboxed like a line of code: no network, no files, no devices, no OS functions, 30 seconds. Every line it
prints starts `app| `. Whatever its manifest lists under `permissions` is shown and **not granted**.

It needs a `manifest.json` at the top (or in the one folder that holds everything) with `"runtime": "python"` and a
`cmd` mode. A zip whose program needs the network, a shared folder or the OS's functions is installed the usual way
(`kos install`), where each grant has its own password. Not tested here: the real sandbox (this container's Python cannot
seal a memfd); `tests/test_ziprun.py` says what was.
