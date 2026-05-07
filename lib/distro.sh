#!/usr/bin/env bash
set -euo pipefail

detect_distro() {
  DISTRO_ID="unknown"
  DISTRO_NAME="Unknown Linux"

  if [[ -r /etc/os-release ]]; then
    # shellcheck disable=SC1091
    . /etc/os-release
    DISTRO_ID="${ID:-unknown}"
    DISTRO_NAME="${PRETTY_NAME:-${NAME:-Unknown Linux}}"
  fi

  case "$DISTRO_ID" in
    ubuntu|debian|arch)
      DISTRO_SUPPORTED=1
      ;;
    fedora)
      DISTRO_SUPPORTED=0
      DISTRO_FUTURE=1
      ;;
    *)
      DISTRO_SUPPORTED=0
      DISTRO_FUTURE=0
      ;;
  esac
}

distro_adapter_path() {
  local root="$1"
  printf '%s/distros/%s.sh' "$root" "$DISTRO_ID"
}
