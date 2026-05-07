#!/usr/bin/env bash
set -euo pipefail

required_commands() {
  printf '%s\n' bash python3 curl ip systemctl sudo logrotate awk sed
}

optional_commands() {
  printf '%s\n' notify-send conky
}

package_hint_header() {
  case "${DISTRO_ID:-unknown}" in
    ubuntu|debian)
      printf 'sudo apt install '
      ;;
    arch)
      printf 'sudo pacman -S '
      ;;
    *)
      printf 'Install packages for your distribution: '
      ;;
  esac
}
