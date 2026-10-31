---
name: kos-graphics
description: How KOS draws - the graphics layer between an app's draw commands and the screen. Use when changing or debugging screen output, frames, the trusted password overlay, the text/graphical/cmd surfaces, fonts, or the framebuffer/terminal/headless backends in kernal-os.
---

# KOS graphics

An app never draws. It sends `screen` (text page) or `frame` (shapes) commands;
the OS rasterizes them into a framebuffer **it owns**, then draws the things
only the OS may draw on top: the mouse pointer and the trusted password overlay.

```
app --screen/frame--> protocol.py (validated) --> surface --> backend --> screen
                                                   ^ OS draws pointer + overlay last
```

## Where things are

| Piece | File |
|---|---|
| Framebuffer, pointer, overlay (`Modal`), backends | `kos/display.py` |
| Text page surface (`run NAME`) | `kos/tui.py` |
| Raw command stream, no drawing (`run cmd NAME`) | `kos/cmdsurface.py` |
| Built-in bitmap font | `kos/font.py` |
| What an app may send | `kos/protocol.py` |

Backends: `FbdevBackend` (real `/dev/fb0`), `TerminalBackend` (truecolor
terminal, two pixels per cell), `HeadlessBackend` (memory; tests).

## What an app may send

`frame` ops only: `clear`, `rect`, `line`, `text`, each with a `#rrggbb` color.
Limits live in `protocol.py` (`MAX_OPS`, `MAX_COORD`, `MAX_LINES`,
`MAX_LINE_CHARS`). Text is stripped of control characters so an app cannot
inject terminal escape sequences. `cmd` mode refuses `screen`/`frame` entirely.

## Rules that apply here

- **The password overlay is the OS's.** It is drawn last, the app receives no
  input while it is up, and the app cannot draw over it. Never add a path that
  lets app pixels land after the overlay, or that lets an app read the overlay.
- Any new draw op needs schema validation in `validate_app_message`, a size
  bound, and a hostile-input test (wrong types, huge values, control chars).
- Never trust an app-supplied string on screen; run it through `clean_text`.
- Encryption: the frame channel is plain JSON today (see `kos-rules`).

## Testing without hardware

Use `HeadlessBackend` and `GraphicalSurface` (see `TestDisplayAndInput` in
`tests/test_kos.py`). This container has no `/dev/fb0`.
