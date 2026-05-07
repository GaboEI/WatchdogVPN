#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# shellcheck source=lib/common.sh
. "$ROOT_DIR/lib/common.sh"
# shellcheck source=lib/distro.sh
. "$ROOT_DIR/lib/distro.sh"
# shellcheck source=lib/packages.sh
. "$ROOT_DIR/lib/packages.sh"
# shellcheck source=lib/install_files.sh
. "$ROOT_DIR/lib/install_files.sh"
# shellcheck source=lib/systemd.sh
. "$ROOT_DIR/lib/systemd.sh"
# shellcheck source=lib/runtime.sh
. "$ROOT_DIR/lib/runtime.sh"
# shellcheck source=lib/desktop.sh
. "$ROOT_DIR/lib/desktop.sh"
# shellcheck source=lib/conky.sh
. "$ROOT_DIR/lib/conky.sh"
# shellcheck source=lib/adguard_home.sh
. "$ROOT_DIR/lib/adguard_home.sh"

ASSUME_YES=0
RUN_DOCTOR=1
INSTALL_DESKTOP=""
INSTALL_CONKY=""
ENABLE_ADVANCED_DNS=""

usage() {
  cat <<'USAGE'
WatchdogVPN installer

Usage:
  ./install.sh [--dry-run] [--yes] [--skip-doctor]

Options:
  --dry-run       Show what would be installed without changing the system.
  --yes           Use product defaults for prompts.
  --skip-doctor   Do not run the read-only preflight first.
  --help          Show this help.
USAGE
}

while (($#)); do
  case "${1:-}" in
    --dry-run)
      INSTALL_DRY_RUN=1
      ;;
    --yes|-y)
      ASSUME_YES=1
      ;;
    --skip-doctor)
      RUN_DOCTOR=0
      ;;
    --help|-h)
      usage
      exit 0
      ;;
    *)
      fail "unknown argument: $1"
      usage >&2
      exit 64
      ;;
  esac
  shift
done

prompt_yes_no() {
  local question="$1" default="$2" answer prompt

  if ((ASSUME_YES == 1)); then
    [[ "$default" == "yes" ]]
    return
  fi

  case "$default" in
    yes) prompt="[Y/n]" ;;
    no) prompt="[y/N]" ;;
    *) prompt="[y/n]" ;;
  esac

  while true; do
    read -r -p "$question $prompt " answer
    answer="${answer:-$default}"
    case "$answer" in
      y|Y|yes|YES|Yes|s|S|si|SI|Si)
        return 0
        ;;
      n|N|no|NO|No)
        return 1
        ;;
    esac
  done
}

require_supported_distro() {
  detect_distro
  info "distro: $DISTRO_NAME ($DISTRO_ID)"

  if [[ "${DISTRO_SUPPORTED:-0}" != "1" ]]; then
    fail "unsupported distro for this release"
    exit 1
  fi

  local adapter
  adapter="$(distro_adapter_path "$ROOT_DIR")"
  if [[ ! -r "$adapter" ]]; then
    fail "missing distro adapter: $adapter"
    exit 1
  fi

  # shellcheck disable=SC1090
  . "$adapter"
}

require_system_shape() {
  if [[ "$(ps -p 1 -o comm= 2>/dev/null || true)" != "systemd" ]]; then
    if [[ "${INSTALL_DRY_RUN:-0}" == "1" ]]; then
      warn "systemd is required; dry-run continues without validating init PID 1"
    else
      fail "systemd is required"
      exit 1
    fi
  fi

  if ! command -v systemctl >/dev/null 2>&1; then
    fail "systemd is required"
    exit 1
  fi

  if ! command -v sudo >/dev/null 2>&1; then
    fail "sudo is required"
    exit 1
  fi
}

adguard_cli_available() {
  command -v adguardvpn-cli >/dev/null 2>&1 || [[ -x /usr/local/bin/adguardvpn-cli ]]
}

validate_required_commands() {
  local missing=() cmd
  for cmd in $(required_commands); do
    have_cmd "$cmd" || missing+=("$cmd")
  done

  if ((${#missing[@]} == 0)); then
    ok "required commands available"
    return 0
  fi

  warn "missing required commands: ${missing[*]}"
  install_package_set "${DISTRO_BASE_PACKAGES[@]}"
}

validate_repo_runtime() {
  python3 -m py_compile "$ROOT_DIR/tui/VPN"
  bash "$ROOT_DIR/tests/syntax.sh" >/dev/null
  ok "repository runtime validated"
}

install_optional_integrations() {
  if [[ "$ENABLE_ADVANCED_DNS" == "1" ]]; then
    install_adguard_home_integration
  fi

  if [[ "$INSTALL_CONKY" == "1" ]]; then
    if [[ -n "${DISTRO_CONKY_PACKAGE:-}" ]] && ! have_cmd conky; then
      install_package_set "$DISTRO_CONKY_PACKAGE"
    fi
    install_conky_files
  fi

  if [[ "$INSTALL_DESKTOP" == "1" ]]; then
    install_desktop_launcher
  fi
}

final_report() {
  cat <<'EOF'

WatchdogVPN installation finished.

Open the TUI with:
  VPN

Useful checks:
  doctor.sh
  vpnctl status
  systemctl status adguardvpn.service vpn-watchdog.timer vpn-rotate.timer --no-pager
EOF
}

printf '%s - Installer\n' "$PROJECT_NAME"
printf 'This installs the WatchdogVPN runtime around an existing AdGuard VPN CLI setup.\n'

require_supported_distro
require_system_shape

if ((RUN_DOCTOR == 1)); then
  "$ROOT_DIR/doctor.sh"
fi

validate_required_commands

if ! adguard_cli_available; then
  fail "adguardvpn-cli is required before installing WatchdogVPN"
  printf 'Install and log in to the official AdGuard VPN CLI first, then rerun ./install.sh.\n'
  exit 1
fi

if prompt_yes_no "Enable advanced DNS with AdGuard Home?" no; then
  ENABLE_ADVANCED_DNS=1
else
  ENABLE_ADVANCED_DNS=0
fi

if prompt_yes_no "Install desktop launcher?" yes; then
  INSTALL_DESKTOP=1
else
  INSTALL_DESKTOP=0
fi

if prompt_yes_no "Install Conky integration?" no; then
  INSTALL_CONKY=1
else
  INSTALL_CONKY=0
fi

if [[ "${INSTALL_DRY_RUN:-0}" == "1" ]]; then
  warn "dry-run mode: no system changes will be made"
else
  sudo -v
fi

validate_repo_runtime
install_runtime_files
verify_systemd_units
install_optional_integrations
enable_systemd_units
final_report
