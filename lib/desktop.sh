#!/usr/bin/env bash
set -euo pipefail

install_desktop_launcher() {
  local app_dest="$HOME/.local/share/applications/watchdogvpn.desktop"
  local desktop_dir desktop_dest

  install_user_file "$ROOT_DIR/desktop/watchdogvpn.desktop" "$app_dest" 0644

  desktop_dir="$(xdg-user-dir DESKTOP 2>/dev/null || true)"
  if [[ -z "$desktop_dir" || "$desktop_dir" == "$HOME" || "$desktop_dir" == "$HOME/" ]]; then
    desktop_dir=""
  fi
  if [[ -z "$desktop_dir" && -d "$HOME/Desktop" ]]; then
    desktop_dir="$HOME/Desktop"
  fi
  if [[ -z "$desktop_dir" && -d "$HOME/Escritorio" ]]; then
    desktop_dir="$HOME/Escritorio"
  fi
  if [[ -d "$desktop_dir" ]]; then
    desktop_dest="$desktop_dir/watchdogvpn.desktop"
    install_user_file "$ROOT_DIR/desktop/watchdogvpn.desktop" "$desktop_dest" 0755
    if command -v gio >/dev/null 2>&1 && [[ "${INSTALL_DRY_RUN:-0}" != "1" ]]; then
      gio set "$desktop_dest" metadata::trusted true >/dev/null 2>&1 || true
    fi
  else
    warn "desktop folder not detected; application-menu launcher was installed only"
  fi
}
