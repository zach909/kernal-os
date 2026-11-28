# KOS-micro

The KOS rules in a core that fits a **7 KiB RAM budget** (7,168 bytes: globals + peak stack).
Portable C99, no libc, no malloc, no recursion, no floats. The board supplies five functions (`hal_*` in
`kmicro.h`); the core never touches hardware itself.

```
make -C micro check     # build, run the tests plain and under ASan+UBSan, print the RAM figure
make -C micro           # also builds build/kos-micro, a demo console on stdin/stdout (password: open-sesame)
```

## Measured (x86-64, gcc -Os)

| | bytes |
|---|---|
| Globals (`.data`+`.bss`, one struct) | 248 |
| Peak stack in the full scenario (painted-stack probe) | 264 |
| **Total** | **512 of 7,168** |
| Code (`.text`) | 3,147 (flash, not RAM) |

The stack figure is from a real run on a separate 16 KiB painted stack; pointers are 8 bytes here, so a 32-bit
MCU should use less. The core object needs nothing but the `hal_*` functions (`nm -u` is checked in `make check`).

## How the KOS rules map

| KOS rule | Here |
|---|---|
| Everything needs verification | `run`, `grant`, `revoke` each ask for the password on the admin console, every time. 3 wrong passwords lock the console until reset. Apps never see the console. |
| Nothing runs unproven | `km_verify` runs at **every** launch (`km_exec` calls it itself): valid opcodes, operands present, jump targets on instruction boundaries, memory slots and actions in range, cannot run off the end. A bad image is refused before any password prompt. Whole numbers only (16-bit, wrapping; `DIV` by zero and `INT16_MIN/-1` fault). |
| Everything is an app | Apps are bytecode images. The only thing an app can do besides compute is `REQ action`: print, LED, sense. No memory access outside its 32 scratch words (zeroed at each launch), no I/O of its own. |
| Blocked by default | An app has no permits until a password-gated `grant`. An unpermitted `REQ` kills the app. Allowed and blocked requests, logins, refusals and faults go in a 32-entry audit ring (`audit`). |
| Hostile input | Console lines: 31 bytes max, printable ASCII only, longer or odd lines are dropped whole (`?`). Overlong passwords count as a failed attempt. Fuzzed: 40,000 random images, ~9,500 passed verify and ran with no sanitizer error. |

## Instruction set

`HALT PUSH n ADD SUB MUL DIV DUP DROP SWAP LOAD a STORE a JMP t JZ t LT EQ REQ act`. Stack of 16, a fuel limit of
4,096 instructions per run. Images are up to 255 bytes. Samples and hostile inputs: `apps.h`.

## Not covered (said plainly)

- **Not run on a real microcontroller or an emulator.** This container has only host `gcc`/`clang`. The RAM
  figure is from the host build. Porting means writing the five `hal_*` functions and checking `size` on the
  real toolchain.
- **No encryption anywhere.** The admin console is plain bytes. A UART/USB console is not encrypted or
  authenticated beyond the password. Same open gap as the main README.
- **No password hashing.** `hal_pw_check` is the board's job; the demo compares to a fixed string in constant
  time. A real board needs a vetted KDF and tamper-resistant storage, which I did not invent here.
- **No network, no firewall.** There is no connection layer to block.
- **No persistence.** Permits and the audit ring live in RAM and vanish at reset. Apps are compiled in
  (`km_app` table); there is no installer, so no sealed or signed install step yet.
- **No hardware memory protection.** On a part without an MMU/MPU the isolation is the VM's bounds checks plus
  `km_verify`, not the silicon. A bug in the core itself can break it.
- **Not a security proof.** "Verified" is a static rule check plus fuzzing under sanitizers.
- **Not the Python KOS.** This is a separate small core with the same ideas. The Python system is untouched.
