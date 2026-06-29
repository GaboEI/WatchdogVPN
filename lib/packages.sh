#!/usr/bin/env bash
set -euo pipefail

required_commands() {
  printf '%s\n' bash python3 curl tar ip systemctl sudo logrotate awk sed
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

install_package_set() {
  local packages=("$@")
  ((${#packages[@]} > 0)) || return 0

  case "${DISTRO_PACKAGE_MANAGER:-}" in
    apt)
      run_step sudo apt-get update
      run_step sudo apt-get install -y "${packages[@]}"
      ;;
    pacman)
      run_step sudo pacman -S --needed --noconfirm "${packages[@]}"
      ;;
    *)
      warn "unsupported package manager: ${DISTRO_PACKAGE_MANAGER:-unknown}"
      print_package_hint "${packages[@]}"
      return 1
      ;;
  esac
}
