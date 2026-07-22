#!/usr/bin/env bash
set -euo pipefail

required_commands() {
  printf '%s\n' \
    bash git python3 curl tar ip ss systemctl systemd-run sudo logrotate awk sed \
    grep find sort sha256sum install getent useradd usermod openvpn setpriv \
    sysctl modinfo nmcli nft iptables ip6tables ping pgrep resolvectl
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
    fedora|rhel|centos|rocky|almalinux)
      printf 'sudo dnf install '
      ;;
    opensuse|opensuse-leap|opensuse-tumbleweed)
      printf 'sudo zypper --non-interactive install --no-recommends '
      ;;
    *)
      printf 'Install packages for your distribution: '
      ;;
  esac
}

python_cryptography_available() {
  python3 -c 'import cryptography' >/dev/null 2>&1
}

# Encrypted backup support is shipped product functionality. A successful
# install/update must not leave it disabled merely because the development or
# certification host happened to have cryptography preinstalled.
validate_python_runtime_dependencies() {
  if python_cryptography_available; then
    ok "python cryptography module available"
    return 0
  fi

  warn "python cryptography module missing; installing the required distro package"
  if [[ -z "${DISTRO_PYTHON_CRYPTOGRAPHY_PACKAGE:-}" ]]; then
    fail "the distro adapter does not define the required Python cryptography package"
    return 1
  fi

  if ! install_package_set "$DISTRO_PYTHON_CRYPTOGRAPHY_PACKAGE"; then
    fail "failed to install the required Python cryptography package"
    return 1
  fi

  if [[ "${INSTALL_DRY_RUN:-0}" == "1" ]]; then
    printf '[DRY-RUN] verify the Python cryptography module after package installation\n'
    return 0
  fi

  if python_cryptography_available; then
    ok "python cryptography module installed"
  else
    fail "python cryptography module still unavailable after package installation"
    return 1
  fi
}

validate_required_commands() {
  local missing=() cmd

  if ! declare -p DISTRO_BASE_PACKAGES >/dev/null 2>&1 \
    || ((${#DISTRO_BASE_PACKAGES[@]} == 0)); then
    fail "the distro adapter does not define its required runtime package set"
    return 1
  fi

  # Always reconcile the complete package set. Installing it only when some
  # unrelated command is absent lets pre-existing developer state mask a
  # missing firewall, protocol, notification, or recovery dependency.
  info "ensuring the complete distro runtime package set"
  if ! install_package_set "${DISTRO_BASE_PACKAGES[@]}"; then
    fail "failed to install the complete distro runtime package set"
    return 1
  fi

  if [[ "${INSTALL_DRY_RUN:-0}" == "1" ]]; then
    printf '[DRY-RUN] verify all required runtime commands after package installation\n'
    return 0
  fi

  for cmd in $(required_commands); do
    have_cmd "$cmd" || missing+=("$cmd")
  done
  if ((${#missing[@]} > 0)); then
    fail "required commands remain unavailable after package installation: ${missing[*]}"
    return 1
  fi

  if [[ ! -c /dev/net/tun ]]; then
    fail "the running kernel does not expose /dev/net/tun; VPN capture cannot operate"
    return 1
  fi

  ok "required runtime packages, commands and kernel TUN device available"
}

validate_polkit_runtime_dependency() {
  if have_cmd pkaction; then
    ok "polkit runtime available"
    return 0
  fi

  if [[ -z "${DISTRO_POLKIT_PACKAGE:-}" ]]; then
    fail "polkit is required for the unprivileged daemon to invalidate system DNS caches"
    return 1
  fi
  install_package_set "$DISTRO_POLKIT_PACKAGE"
  if [[ "${INSTALL_DRY_RUN:-0}" == "1" ]]; then
    printf '[DRY-RUN] verify pkaction after installing %s\n' "$DISTRO_POLKIT_PACKAGE"
    return 0
  fi
  if ! have_cmd pkaction; then
    fail "polkit installation completed but pkaction is unavailable"
    return 1
  fi
  ok "polkit runtime installed"
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
    dnf)
      run_step sudo dnf install -y "${packages[@]}"
      ;;
    zypper)
      run_step sudo zypper --non-interactive install --no-recommends "${packages[@]}"
      ;;
    *)
      warn "unsupported package manager: ${DISTRO_PACKAGE_MANAGER:-unknown}"
      print_package_hint "${packages[@]}"
      return 1
      ;;
  esac
}
