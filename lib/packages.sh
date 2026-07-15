#!/usr/bin/env bash
set -euo pipefail

required_commands() {
  printf '%s\n' bash python3 curl tar ip systemctl sudo logrotate awk sed openvpn setpriv
}

optional_commands() {
  printf '%s\n' notify-send
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

python_cryptography_available() {
  python3 -c 'import cryptography' >/dev/null 2>&1
}

# Encrypted backup support (Phase 17, config/backup_manager.py) treats
# `cryptography` as an optional dependency at import time and reports a clear
# error if it is missing, so this check is best-effort: it warns and tries to
# install, but it never fails the installer or updater.
validate_python_runtime_dependencies() {
  if python_cryptography_available; then
    ok "python cryptography module available"
    return 0
  fi

  warn "python cryptography module missing; encrypted backups (watchdog backup --encrypt-backup) will not work"
  if [[ -z "${DISTRO_PYTHON_CRYPTOGRAPHY_PACKAGE:-}" ]]; then
    printf 'Install the cryptography Python package for your distribution to enable it.\n'
    return 0
  fi

  install_package_set "$DISTRO_PYTHON_CRYPTOGRAPHY_PACKAGE" || true

  if python_cryptography_available; then
    ok "python cryptography module installed"
  else
    warn "python cryptography module still unavailable after install attempt"
  fi
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
