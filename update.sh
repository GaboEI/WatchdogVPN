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
# shellcheck source=lib/config.sh
. "$ROOT_DIR/lib/config.sh"
# shellcheck source=lib/systemd.sh
. "$ROOT_DIR/lib/systemd.sh"
# shellcheck source=lib/desktop.sh
. "$ROOT_DIR/lib/desktop.sh"
# shellcheck source=lib/runtime.sh
. "$ROOT_DIR/lib/runtime.sh"

ASSUME_YES=0
RUN_DOCTOR=1

usage() {
  cat <<'USAGE'
WatchdogVPN updater

Usage:
  ./update.sh [--dry-run] [--yes] [--skip-doctor]

Options:
  --dry-run       Show what would be updated without changing the system.
  --yes           Do not ask for update confirmation.
  --skip-doctor   Do not run the read-only preflight first.
  --help          Show this help.

The updater validates the repository, backs up replaced product files, and
preserves user configuration, logs and runtime state.
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

prompt_continue() {
  local answer
  if ((ASSUME_YES == 1)); then
    return 0
  fi

  read -r -p "Continue updating WatchdogVPN runtime? [y/N] " answer
  case "$answer" in
    y|Y|yes|YES|Yes|s|S|si|SI|Si) return 0 ;;
    *) return 1 ;;
  esac
}

require_supported_distro() {
  detect_distro
  info "distro: $DISTRO_NAME ($DISTRO_ID)"

  if [[ "${DISTRO_SUPPORTED:-0}" != "1" ]]; then
    print_unsupported_distro
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

validate_repo_runtime() {
  python3 -m compileall -q "$ROOT_DIR/tui"
  bash "$ROOT_DIR/tests/syntax.sh" >/dev/null
  ok "repository runtime validated"
}

require_existing_installation() {
  local found=0 path
  for path in \
    /usr/local/bin/vpn_backend \
    /usr/local/bin/vpn_truth_check \
    /usr/local/bin/vpnctl \
    /usr/local/sbin/vpn_watchdog.sh \
    /usr/local/sbin/vpn_rotate.sh \
    "$HOME/.local/bin/VPN"
  do
    [[ -e "$path" ]] && found=1
  done

  if ((found == 0)); then
    fail "no existing WatchdogVPN installation detected"
    printf 'Run ./install.sh first.\n'
    exit 1
  fi
}

print_preservation_contract() {
  print_section "Preserved by update"
  printf '/etc/adguardvpn.env\n'
  printf '/etc/vpn-domain-bypass.conf\n'
  printf '/var/lib/vpn-rotate/\n'
  printf '/var/log/myvpn/\n'
  printf 'user Conky configuration\n'
  printf '\nOnly product-managed runtime files are replaced after validation and backup.\n'
}

final_report() {
  print_title "WatchdogVPN update completed"
  print_field "Preserved config" "/etc/adguardvpn.env"
  print_field "Preserved bypass" "/etc/vpn-domain-bypass.conf"
  print_field "Preserved state" "/var/lib/vpn-rotate/"
  print_field "Preserved logs" "/var/log/myvpn/"

  print_section "Recommended checks"
  printf './doctor.sh\n'
  printf 'vpnctl status\n'
  printf 'VPN\n'
}

print_update_plan() {
  print_title "WatchdogVPN update plan"
  print_field "Target distro" "$DISTRO_NAME ($DISTRO_ID)"
  print_field "Runtime commands" "/usr/local/bin"
  print_field "Privileged scripts" "/usr/local/sbin"
  print_field "Systemd units" "refreshed and enabled"
  print_field "Backups" "$BACKUP_ROOT"
  print_field "Dry run" "$(yes_no_word "${INSTALL_DRY_RUN:-0}")"
}

print_title "$PROJECT_NAME Update"
print_preservation_contract

require_supported_distro
require_existing_installation

if ((RUN_DOCTOR == 1)); then
  print_section "Read-only preflight"
  "$ROOT_DIR/doctor.sh"
fi

if [[ "${INSTALL_DRY_RUN:-0}" == "1" ]]; then
  warn "dry-run mode: no system changes will be made"
else
  print_section "Privilege check"
  sudo -v
fi

print_section "Runtime validation"
validate_repo_runtime
print_update_plan

if ! prompt_continue; then
  warn "update cancelled"
  exit 0
fi

print_section "Replace product files"
install_runtime_files
print_section "Systemd verification"
verify_systemd_units
print_section "Refresh launchers and services"
refresh_installed_desktop_launcher
enable_systemd_units
ensure_user_local_bin_path
final_report
