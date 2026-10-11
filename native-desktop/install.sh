#!/usr/bin/env bash
# KOS native desktop: install the pieces (panel, dock, compositor, launcher, icons, font) and the kos-desktop tool.
#
#   ./install.sh [--dry-run] [--yes] [--no-packages] [--apply]
#
#   --dry-run      print everything it would do, change nothing
#   --yes          do not ask before installing packages
#   --no-packages  skip the package step (you installed them yourself)
#   --apply        afterwards run `kos-desktop apply --autostart` (backs up your files first)
#
# What it installs: polybar (top panel), plank (floating dock), picom (blur, rounded corners), rofi (launcher),
# feh (wallpaper), Papirus (icon pack), Inter (font), dconf + fontconfig (settings). Only the package step uses
# sudo. It links kos-desktop into ~/.local/bin. It never touches your window manager or display manager.
set -euo pipefail

KIT="$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")" && pwd)"
DRY=0 YES=0 PKGS=1 APPLY=0
for a in "$@"; do
  case "$a" in
    --dry-run) DRY=1 ;;
    --yes|-y) YES=1 ;;
    --no-packages) PKGS=0 ;;
    --apply) APPLY=1 ;;
    -h|--help) sed -n '2,14p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "unknown option: $a" >&2; exit 2 ;;
  esac
done

say() { printf '%s\n' "$*"; }
warn() { printf 'install.sh: %s\n' "$*" >&2; }
run() { if [ "$DRY" = 1 ]; then say "  would run: $*"; else "$@"; fi; }
have() { command -v "$1" >/dev/null 2>&1; }

[ "$(id -u)" != 0 ] || [ "$DRY" = 1 ] || { warn "run this as your normal user (it asks for sudo only to install packages)"; exit 1; }

# --- which package manager, which package names
MGR="" PACKAGES=()
if have apt-get; then
  MGR=apt; PACKAGES=(polybar picom plank rofi feh papirus-icon-theme fonts-inter dconf-cli fontconfig)
elif have dnf; then
  MGR=dnf; PACKAGES=(polybar picom plank rofi feh papirus-icon-theme rsms-inter-fonts dconf fontconfig)
elif have pacman; then
  MGR=pacman; PACKAGES=(polybar picom plank rofi feh papirus-icon-theme inter-font dconf fontconfig)
fi

SUDO=""
[ "$(id -u)" = 0 ] || { have sudo && SUDO=sudo || true; }

# the install command as an array, so names are never re-split
install_argv() {
  local y=()
  case "$MGR" in
    apt) [ "$YES" = 1 ] && y=(-y); INSTALL=($SUDO apt-get install "${y[@]}" "$@") ;;
    dnf) [ "$YES" = 1 ] && y=(-y); INSTALL=($SUDO dnf install "${y[@]}" "$@") ;;
    pacman) [ "$YES" = 1 ] && y=(--noconfirm); INSTALL=($SUDO pacman -S --needed "${y[@]}" "$@") ;;
  esac
}

if [ "$PKGS" = 1 ]; then
  if [ -z "$MGR" ]; then
    warn "no apt, dnf or pacman found. Install these yourself, then re-run with --no-packages:"
    warn "  polybar picom plank rofi feh Papirus icon theme, the Inter font, dconf, fontconfig"
  else
    say "Package manager: $MGR"
    missing=()
    for p in "${PACKAGES[@]}"; do
      case "$MGR" in
        apt) dpkg -s "$p" >/dev/null 2>&1 || missing+=("$p") ;;
        dnf) rpm -q "$p" >/dev/null 2>&1 || missing+=("$p") ;;
        pacman) pacman -Qi "$p" >/dev/null 2>&1 || missing+=("$p") ;;
      esac
    done
    if [ "${#missing[@]}" = 0 ]; then
      say "All packages are already installed."
    else
      say "To install: ${missing[*]}"
      if [ "$DRY" = 1 ]; then
        install_argv "${missing[@]}"; say "  would run: ${INSTALL[*]}"
      else
        install_argv "${missing[@]}"
        [ -n "$SUDO" ] || { warn "sudo is not available. As root, run: ${INSTALL[*]}"; exit 1; }
        if [ "$YES" = 0 ]; then
          read -r -p "Install them with: ${INSTALL[*]}  [y/N] " ans
          case "$ans" in y|Y|yes) ;; *) say "Skipped packages."; missing=() ;; esac
        fi
        if [ "${#missing[@]}" -gt 0 ]; then
          [ "$MGR" = apt ] && $SUDO apt-get update
          # all at once; if one name does not exist on this release, fall back to one by one so the rest still install
          install_argv "${missing[@]}"
          if ! "${INSTALL[@]}"; then
            warn "bulk install failed; trying one package at a time"
            for p in "${missing[@]}"; do
              install_argv "$p"
              "${INSTALL[@]}" || warn "could not install $p (skipping; the kit degrades without it)"
            done
          fi
        fi
      fi
    fi
  fi
fi

# --- the tool on your PATH
say "Linking kos-desktop into ~/.local/bin"
run mkdir -p "$HOME/.local/bin"
run ln -sf "$KIT/bin/kos-desktop" "$HOME/.local/bin/kos-desktop"
case ":$PATH:" in *":$HOME/.local/bin:"*) ;; *) warn "~/.local/bin is not on your PATH; use $KIT/bin/kos-desktop" ;; esac

say ""
say "Installed. Next, safely:"
say "  kos-desktop status        what is present"
say "  kos-desktop preview 30    look at it for 30 seconds; your files are untouched"
say "  kos-desktop apply --autostart   back up your files, install the configs, start at login"
say "  kos-desktop reload        restart panel/dock/compositor"
say "  kos-desktop revert        undo apply"

if [ "$APPLY" = 1 ]; then
  say ""
  if [ "$DRY" = 1 ]; then KOS_DRY_RUN=1 "$KIT/bin/kos-desktop" apply --autostart; else "$KIT/bin/kos-desktop" apply --autostart; fi
fi
