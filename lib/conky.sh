#!/usr/bin/env bash
set -euo pipefail

install_conky_files() {
  local dest="$HOME/.conky/WatchdogVPN"
  run_step install -d -m 0755 "$dest"
  run_step cp -a "$ROOT_DIR/conky/." "$dest/"
}
