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
  --yes           Do not ask for confirmation.
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

validate_repo_runtime() {
  python3 -m py_compile "$ROOT_DIR/tui/VPN"
  bash "$ROOT_DIR/tests/syntax.sh" >/dev/null
  ok "repository runtime validated"
}

require_existing_installation() {
  local found=0 path
  for path in \
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
  cat <<'EOF'
The updater preserves:
  /etc/adguardvpn.env
  /etc/vpn-domain-bypass.conf
  /var/lib/vpn-rotate/
  /var/log/myvpn/
  user AdGuard Home configuration
  user Conky configuration

It replaces only product-managed runtime files after validation and backup.
EOF
}

final_report() {
  cat <<'EOF'

WatchdogVPN update finished.

Useful checks:
  doctor.sh
  vpnctl status
  systemctl status adguardvpn.service vpn-watchdog.timer vpn-rotate.timer --no-pager
EOF
}

printf '%s - Update\n' "$PROJECT_NAME"
print_preservation_contract

require_supported_distro
require_existing_installation

if ((RUN_DOCTOR == 1)); then
  "$ROOT_DIR/doctor.sh"
fi

if [[ "${INSTALL_DRY_RUN:-0}" == "1" ]]; then
  warn "dry-run mode: no system changes will be made"
else
  sudo -v
fi

validate_repo_runtime

if ! prompt_continue; then
  warn "update cancelled"
  exit 0
fi

install_runtime_files
verify_systemd_units
refresh_installed_desktop_launcher
enable_systemd_units
final_report
