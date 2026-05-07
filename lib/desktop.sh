#!/usr/bin/env bash
set -euo pipefail

install_desktop_launcher() {
  local dest="$HOME/.local/share/applications/watchdogvpn.desktop"
  install_user_file "$ROOT_DIR/desktop/vpn-control-center.desktop" "$dest" 0644
}
