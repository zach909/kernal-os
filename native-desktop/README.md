# KOS native desktop

The top-panel-and-floating-dock layout, with KOS Blue (`#0078D4`) as the accent, running **natively on your own X11
session** - no virtual desktop, no container, no nested shell. It configures real programs that talk to your
real display server and your real root filesystem's fonts, icons and settings.

| Piece | Program | What it does |
|---|---|---|
| Top panel | **polybar** | KOS menu, active window title, CPU/memory, network, audio, clock; KOS Blue underline on the clock |
| Floating dock | **plank** | centered at the bottom, rounded glass, zoom on hover, auto-hides when a window needs the space (`hide-mode='intelligent'`) |
| Glass / corners / shadows | **picom** | blur behind translucent surfaces, 12px rounded corners, soft shadows, short fades |
| Launcher | **rofi** | search box with a KOS Blue border and selection |
| Icons | **Papirus** | the icon pack (GTK is told to use `Papirus-Dark`) |
| Font | **Inter** | clean modern sans-serif; fontconfig makes it the default `sans-serif` with light hinting |
| Accent in GTK apps | `gtk.css` | `#0078D4` for selection, focus, links (GTK 3 and GTK 4 / libadwaita) |

## 1. Install the dependencies

```bash
cd native-desktop
./install.sh --dry-run        # read what it would do
./install.sh                  # asks before using sudo for packages (apt, dnf or pacman)
```

It installs `polybar picom plank rofi feh papirus-icon-theme`, the Inter font, `dconf` and `fontconfig`, and links
`kos-desktop` into `~/.local/bin`. Only the package step uses sudo. If one package does not exist on your
release it tells you and carries on; the kit degrades (no dock, no blur, ...) rather than failing.

## 2. Where everything goes

```
~/.config/polybar/config.ini                top panel
~/.config/picom/picom.conf                  compositor
~/.config/rofi/kos.rasi                     launcher theme
~/.config/gtk-3.0/{settings.ini,gtk.css}    GTK 3: font, icons, accent
~/.config/gtk-4.0/gtk.css                   GTK 4 / libadwaita accent
~/.config/fontconfig/conf.d/60-kos.conf     Inter + rendering
~/.local/share/plank/themes/KOS/dock.theme  dock look
dconf  /net/launchpad/plank/docks/dock1/    dock behaviour (centered, bottom, auto-hide, zoom, theme KOS)
~/.config/autostart/kos-desktop.desktop     only if you apply with --autostart
~/.local/state/kos-desktop/original/        YOUR files as they were, recorded the first time you apply
```

The sources are in `native-desktop/config/`. Everything is per-user; nothing is written under `/etc`.

## 3. Apply, preview, reload - without breaking your system

```bash
kos-desktop status               # what is installed / applied / running
kos-desktop preview 30           # run it for 30 s using the kit's own files; touches NONE of yours, stops after
kos-desktop apply --autostart    # record your originals, install the configs, start at login
kos-desktop reload               # restart panel, dock and compositor (picom re-reads on SIGUSR1)
kos-desktop revert               # restore your originals exactly, remove what apply added
```

Safety properties (each one was exercised in a throwaway `$HOME`):

* `apply` records what was there first (the file, or "nothing") in a baseline later runs never overwrite, so
  applying three times and then `revert` still gives back **your** original. `revert` twice refuses the second time.
* `KOS_DRY_RUN=1` makes every command print instead of act.
* It refuses on Wayland (these are X11 programs) unless you set `KOS_FORCE=1`.
* If another compositor (compton, xcompmgr) is already running it does not start picom, since two compositors fight.
* It never kills or replaces your window manager or display manager; `revert`/`stop` only stop polybar, plank and picom.
* `preview` gives Plank its own dock id (`kospreview`) and deletes it again on exit, so your Plank settings are untouched.

## Honest limits

* **I could not look at the result.** The environment this was built in has no X server, no polybar/picom/plank
  and no GPU. What was verified: the shell scripts parse (`bash -n`), dry-run output, apply/revert/idempotence,
  the Wayland/DISPLAY/argument guards, in a throwaway home. What was *not*: that polybar, picom, plank and rofi
  accept these exact config files on your versions. Run `kos-desktop preview` first; if something looks wrong,
  `kos-desktop revert` puts everything back.
* Needs an X11 session. On Wayland (GNOME, KDE Plasma default) log in to the X11/Xorg session.
* picom's `glx` backend with `dual_kawase` blur needs a working GPU driver; on a VM or old hardware change
  `backend = "xrender"` and `blur-method = "none"` in `picom.conf` for a flat (non-blurred) look.
* Plank's theme file keys come from Plank's documented theme format; if your Plank version rejects the KOS
  theme it falls back to its default theme, and the dock still works.
* Wallpaper is yours (`feh --bg-fill image.jpg`); the KOS compositor's own code-drawn wallpaper only exists
  inside KOS (`kos boot desktop`).
