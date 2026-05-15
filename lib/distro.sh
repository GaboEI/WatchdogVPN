#!/usr/bin/env bash
set -euo pipefail

detect_distro() {
  DISTRO_ID="unknown"
  DISTRO_ID_LIKE=""
  DISTRO_NAME="Unknown Linux"
  DISTRO_ADAPTER_ID="unknown"
  DISTRO_FAMILY="unknown"
  DISTRO_SUPPORTED=0
  DISTRO_FUTURE=0

  local os_release="${OS_RELEASE_FILE:-/etc/os-release}"
  if [[ -r "$os_release" ]]; then
    unset ID ID_LIKE NAME PRETTY_NAME
    # shellcheck disable=SC1090,SC1091
    . "$os_release"
    DISTRO_ID="${ID:-unknown}"
    DISTRO_ID_LIKE="${ID_LIKE:-}"
    DISTRO_NAME="${PRETTY_NAME:-${NAME:-Unknown Linux}}"
  fi

  case "$DISTRO_ID" in
    ubuntu|debian|arch)
      DISTRO_SUPPORTED=1
      DISTRO_ADAPTER_ID="$DISTRO_ID"
      DISTRO_FAMILY="$DISTRO_ID"
      ;;
    fedora)
      DISTRO_SUPPORTED=0
      DISTRO_ADAPTER_ID="$DISTRO_ID"
      DISTRO_FAMILY="$DISTRO_ID"
      DISTRO_FUTURE=1
      ;;
    *)
      case " $DISTRO_ID_LIKE " in
        *" arch "*)
          DISTRO_SUPPORTED=1
          DISTRO_ADAPTER_ID="arch"
          DISTRO_FAMILY="arch"
          ;;
        *)
          DISTRO_SUPPORTED=0
          DISTRO_ADAPTER_ID="$DISTRO_ID"
          DISTRO_FAMILY="$DISTRO_ID"
          ;;
      esac
      ;;
  esac
}

distro_adapter_path() {
  local root="$1"
  printf '%s/distros/%s.sh' "$root" "${DISTRO_ADAPTER_ID:-$DISTRO_ID}"
}
