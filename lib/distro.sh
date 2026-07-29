#!/usr/bin/env bash
set -euo pipefail

# Distro detection for WatchdogVPN bootstrap.
#
# PRIMARY SOURCE OF TRUTH (preferred):
#   tools/compat_distro_classify.py reads compat/compatibility.json and the
#   compat.detection engine. It returns a stable JSON shape with
#   support_classification, adapter_id, family_id, etc.
#
# FALLBACK (bootstrap only, no support classification):
#   If Python or the engine is unavailable, this file falls back to a minimal
#   pure-Bash reader of /etc/os-release. The fallback resolves identity,
#   adapter/family and a package-manager seed, but it NEVER decides
#   support_classification, NEVER marks a distro as supported, and NEVER
#   produces DISTRO_FUTURE=1. When the fallback is active the distro is
#   considered undetermined/unsupported until the engine can be run.


# Reset all exported variables so repeated calls are idempotent.
detect_distro() {
  DISTRO_ID="unknown"
  DISTRO_ID_LIKE=""
  DISTRO_NAME="Unknown Linux"
  DISTRO_ADAPTER_ID="unknown"
  DISTRO_FAMILY="unknown"
  DISTRO_PACKAGE_MANAGER="unknown"
  DISTRO_SUPPORTED=0
  DISTRO_FUTURE=0
  DISTRO_UNSUPPORTED=0
  DISTRO_UNDETERMINED=0

  local os_release="${OS_RELEASE_FILE:-/etc/os-release}"

  if _detect_distro_with_engine "$os_release"; then
    return 0
  fi

  _detect_distro_fallback "$os_release"
}


# Try the engine first. Returns 0 on success, 1 on any failure.
_detect_distro_with_engine() {
  local os_release="$1"
  local root_dir
  if [[ -n "${_WATCHDOGVPN_ROOT_DIR:-}" ]]; then
    root_dir="$_WATCHDOGVPN_ROOT_DIR"
  else
    # Use only bash builtins so this works even when PATH is empty.
    root_dir="$(cd "${BASH_SOURCE[0]%/*}/.." 2>/dev/null && pwd)"
  fi

  local python_cmd="${WATCHDOGVPN_PYTHON:-python3}"
  if ! command -v "$python_cmd" >/dev/null 2>&1; then
    return 1
  fi

  local classify_output classify_rc
  classify_rc=0
  classify_output="$(timeout 5 "$python_cmd" \
    "$root_dir/tools/compat_distro_classify.py" \
    --os-release "$os_release" \
    classify 2>/dev/null)" || classify_rc=$?

  if [[ "$classify_rc" != "0" || -z "$classify_output" ]]; then
    return 1
  fi

  # Parse the stable JSON output with Python (the engine already required it).
  local parsed
  parsed="$(printf '%s\n' "$classify_output" | "$python_cmd" -c '
import json, sys
try:
    d = json.load(sys.stdin)
except Exception:
    sys.exit(1)
if d.get("status") != "ok":
    sys.exit(1)
for key in (
    "distro_id", "distro_name", "adapter_id", "family_id",
    "package_manager", "support_classification", "resolution_status"
):
    print(d.get(key, ""))
' 2>/dev/null)" || return 1

  if [[ -z "$parsed" ]]; then
    return 1
  fi

  local distro_id distro_name adapter_id family_id package_manager support resolution
  {
    IFS= read -r distro_id
    IFS= read -r distro_name
    IFS= read -r adapter_id
    IFS= read -r family_id
    IFS= read -r package_manager
    IFS= read -r support
    IFS= read -r resolution
  } <<<"$parsed"

  if [[ -z "$distro_id" || -z "$support" ]]; then
    return 1
  fi

  DISTRO_ID="$distro_id"
  DISTRO_NAME="${distro_name:-Unknown Linux}"
  DISTRO_ADAPTER_ID="${adapter_id:-$distro_id}"
  DISTRO_FAMILY="$(_family_short_from_technical "${family_id:-$distro_id}")"
  DISTRO_PACKAGE_MANAGER="${package_manager:-unknown}"

  case "$support" in
    certified|supported|family_inferred)
      DISTRO_SUPPORTED=1
      ;;
    experimental)
      DISTRO_FUTURE=1
      ;;
    unsupported)
      DISTRO_UNSUPPORTED=1
      ;;
    *)
      return 1
      ;;
  esac

  return 0
}


# Minimal pure-Bash fallback for bootstrap identity only.
_detect_distro_fallback() {
  local os_release="$1"

  DISTRO_SUPPORTED=0
  DISTRO_FUTURE=0
  DISTRO_UNSUPPORTED=0
  DISTRO_UNDETERMINED=1

  if [[ ! -r "$os_release" ]]; then
    DISTRO_UNSUPPORTED=1
    DISTRO_UNDETERMINED=0
    return 0
  fi

  unset ID ID_LIKE NAME PRETTY_NAME
  # shellcheck disable=SC1090,SC1091
  . "$os_release"

  DISTRO_ID="${ID:-unknown}"
  DISTRO_ID_LIKE="${ID_LIKE:-}"
  DISTRO_NAME="${PRETTY_NAME:-${NAME:-Unknown Linux}}"

  # Mechanical adapter/family derivation. This is NOT a support decision.
  case "$DISTRO_ID" in
    ubuntu)
      DISTRO_ADAPTER_ID="ubuntu"
      DISTRO_FAMILY="ubuntu"
      DISTRO_PACKAGE_MANAGER="apt"
      ;;
    debian)
      DISTRO_ADAPTER_ID="debian"
      DISTRO_FAMILY="debian"
      DISTRO_PACKAGE_MANAGER="apt"
      ;;
    arch)
      DISTRO_ADAPTER_ID="arch"
      DISTRO_FAMILY="arch"
      DISTRO_PACKAGE_MANAGER="pacman"
      ;;
    fedora|rhel|centos|rocky|almalinux)
      DISTRO_ADAPTER_ID="fedora"
      DISTRO_FAMILY="redhat"
      DISTRO_PACKAGE_MANAGER="dnf"
      ;;
    opensuse|opensuse-leap|opensuse-tumbleweed)
      DISTRO_ADAPTER_ID="opensuse"
      DISTRO_FAMILY="suse"
      DISTRO_PACKAGE_MANAGER="zypper"
      ;;
    *)
      case " $DISTRO_ID_LIKE " in
        *" arch "*)
          DISTRO_ADAPTER_ID="arch"
          DISTRO_FAMILY="arch"
          DISTRO_PACKAGE_MANAGER="pacman"
          ;;
        *" ubuntu "*)
          DISTRO_ADAPTER_ID="ubuntu"
          DISTRO_FAMILY="ubuntu"
          DISTRO_PACKAGE_MANAGER="apt"
          ;;
        *" debian "*)
          DISTRO_ADAPTER_ID="debian"
          DISTRO_FAMILY="debian"
          DISTRO_PACKAGE_MANAGER="apt"
          ;;
        *" rhel "*|*" centos "*|*" fedora "*)
          DISTRO_ADAPTER_ID="fedora"
          DISTRO_FAMILY="redhat"
          DISTRO_PACKAGE_MANAGER="dnf"
          ;;
        *" suse "*|*" opensuse "*)
          DISTRO_ADAPTER_ID="opensuse"
          DISTRO_FAMILY="suse"
          DISTRO_PACKAGE_MANAGER="zypper"
          ;;
        *)
          DISTRO_ADAPTER_ID="$DISTRO_ID"
          DISTRO_FAMILY="$DISTRO_ID"
          DISTRO_PACKAGE_MANAGER="unknown"
          ;;
      esac
      ;;
  esac

  return 0
}


# Map a technical family id (e.g. redhat_dnf) to the short legacy family
# identifier used by doctor.sh and other shell consumers. This is purely a
# compatibility shim; the engine remains the source of truth for support.
_family_short_from_technical() {
  case "$1" in
    arch_pacman) printf 'arch' ;;
    debian_apt)  printf 'debian' ;;
    ubuntu_apt)  printf 'ubuntu' ;;
    redhat_dnf)  printf 'redhat' ;;
    suse_zypper) printf 'suse' ;;
    *)           printf '%s' "$1" ;;
  esac
}


distro_adapter_path() {
  local root="$1"
  printf '%s/distros/%s.sh' "$root" "${DISTRO_ADAPTER_ID:-$DISTRO_ID}"
}
