---
name: kos-text
description: The KOS text layer - non-graphical, plain-text output between the graphical layer and the button clicker (run text NAME). Use when changing or debugging kos/textsurface.py, the text mode, the KOS| / app| line prefixes, the plain terminal, or anything that decides how an app's screen commands become characters on a terminal in kernal-os.
---

# KOS text layer

**This does:** shows an app as a plain transcript of characters - no colours, no
cursor movement, no alternate screen, no pointer - so it works on a serial
console, with a screen reader, or piped to a file.

**So the AI:** keeps every line labelled with who wrote it, never lets app text
reach the terminal unprintable-stripped, and tests with a pipe because this
container has no real terminal or screen reader.

```
app --screen--> protocol.py (validated, mode "text" = tui) --> TextSurface --> plain lines --> terminal
```

Where it sits: `guard.PIPELINE` is graphics, **text**, button clicker (input), app commands,
kernel, hardware. `tui.py` is "non-graphical but kind of graphical" (full screen, colours, cursor
addressing); this is the layer under it.

## Where things are

| Piece | File |
|---|---|
| The surface | `kos/textsurface.py` (`TextSurface`, `plain`, `wrap`) |
| Terminal without escape sequences | `kos/term.py` (`RawTerminal(plain=True)`) |
| Mode helpers | `kos/kapp.py` (`RUN_MODES`, `supports_mode`, `wire_mode`) |
| The guard | `kos/guard.py` (`page-budget`) |
| Tests | `tests/test_guard.py` |

## How it is a mode

`text` is a way to *show* an app, not a kind of app. Any app with a `tui` mode runs as `text` with no
repack (`supports_mode`); the app is told `tui` (`wire_mode`, in `loader.plan` and the cell header)
and keeps sending `screen`. A manifest cannot declare `text` (not in `kapp.MODES`) and no app can be
named `text` (`RESERVED_NAMES`). `protocol.validate_app_message` takes `screen` in `text` and refuses
`frame`.

## Rules that apply here

- **Every line says who wrote it.** OS lines start `KOS| `, app lines `app| `, including every wrapped
  piece. App text can hold no newline (`clean_text`, then `plain` again here), so an app cannot write a
  line that starts `KOS| `. Never print app text without the `app| ` prefix, and never print OS text
  that contains app text (the app's title is an `app| ` line, not part of a `KOS| ` line).
- **Plain characters only.** `plain()` turns everything not `isprintable()` into `?`: escapes, bidi
  controls, zero-width characters, tabs, a non-breaking space.
- **The password prompt is printed once, by the OS, never echoed**, and typing prints nothing (not even a
  count). Never route a typed password to `render`.
- **No pointer.** `has_pointer = False`: the session never offers the mouse to boot and the input guard
  drops pointer events. Do not add a mouse path here.
- **Hold back, do not queue.** A changed page is printed at most every 250 ms (latest wins);
  `deferred` tells the session to render again. An unchanged page is never printed twice.
- `RawTerminal(plain=True)` must send the terminal nothing: no alternate screen, no hidden cursor, no
  mouse reporting (`enable_mouse` does nothing).
- New output needs a test that every line is `KOS| ` or `app| ` and that no `\x1b` appears.

## Not covered (say so, do not claim it)

Not tested on a real terminal, a serial console or a screen reader. The prefix stops forging an OS line
but not an app writing text that *describes* a prompt; the real one starts `KOS| == SECURE PROMPT`.
