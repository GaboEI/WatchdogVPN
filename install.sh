#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# shellcheck source=lib/common.sh
. "$ROOT_DIR/lib/common.sh"
# shellcheck source=lib/distro.sh
. "$ROOT_DIR/lib/distro.sh"
# shellcheck source=lib/packages.sh
. "$ROOT_DIR/lib/packages.sh"
# shellcheck source=lib/adguard_vpn_cli.sh
. "$ROOT_DIR/lib/adguard_vpn_cli.sh"
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
PATH_UPDATED=0

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

auth_state() {
  local raw
  raw="$(ADGUARDVPN_CLI="${ADGUARDVPN_CLI:-/usr/local/bin/adguardvpn-cli}" "$ROOT_DIR/bin/vpn_auth_check" 2>/dev/null || true)"
  printf '%s\n' "$raw" | awk -F= '$1 == "AUTH" {print $2; exit}'
}

ensure_adguard_service_login() {
  local state
  state="$(auth_state)"

  if [[ "$state" == "OK" ]]; then
    ok "AdGuard VPN service user authenticated"
    return 0
  fi

  warn "AdGuard VPN service user is not authenticated"
  printf 'WatchdogVPN runs AdGuard VPN as user: adgvpn\n'
  printf 'The service user must log in once before automatic VPN recovery can work.\n'

  if [[ "${INSTALL_DRY_RUN:-0}" == "1" ]]; then
    printf '[DRY-RUN] sudo -u adgvpn -H /usr/local/bin/adguardvpn-cli login\n'
    return 0
  fi

  if prompt_yes_no "Log in to AdGuard VPN now as adgvpn?" yes; then
    sudo -u adgvpn -H "${ADGUARDVPN_CLI:-/usr/local/bin/adguardvpn-cli}" login
  else
    fail "AdGuard VPN login for adgvpn is required"
    printf 'Run manually:\n'
    printf '  sudo -u adgvpn -H /usr/local/bin/adguardvpn-cli login\n'
    exit 1
  fi

  state="$(auth_state)"
  if [[ "$state" != "OK" ]]; then
    fail "AdGuard VPN service user is still not authenticated"
    exit 1
  fi

  ok "AdGuard VPN service user authenticated"
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

wait_for_services() {
  if [[ "${INSTALL_DRY_RUN:-0}" == "1" ]]; then
    printf '[DRY-RUN] wait for services to settle\n'
    return 0
  fi

  info "waiting briefly for services to settle"
  sleep 8
}

post_install_validation() {
  local doctor_rc=0 dns_rc=0

  if [[ "${INSTALL_DRY_RUN:-0}" == "1" ]]; then
    printf '[DRY-RUN] ./doctor.sh\n'
    [[ "$ENABLE_ADVANCED_DNS" == "1" ]] && printf '[DRY-RUN] vpn_dnsctl local-test\n'
    return 0
  fi

  printf '\n== Final validation ==\n'
  "$ROOT_DIR/doctor.sh" || doctor_rc=$?

  if [[ "$ENABLE_ADVANCED_DNS" == "1" ]]; then
    printf '\n== DNS validation ==\n'
    /usr/local/bin/vpn_dnsctl local-test || dns_rc=$?
  fi

  if ((doctor_rc != 0 || dns_rc != 0)); then
    fail "installation finished with validation errors"
    printf 'Review the output above. You can rerun diagnostics with:\n'
    printf '  cd %s\n' "$ROOT_DIR"
    printf '  ./doctor.sh\n'
    printf '  vpnctl status\n'
    printf '  vpn_dnsctl local-test\n'
    exit 1
  fi
}

final_report() {
  cat <<'EOF'

WatchdogVPN installation finished.

Open the TUI with:
  VPN

Useful checks:
  ./doctor.sh
  vpnctl status
  vpn_dnsctl local-test
  systemctl status adguardvpn.service vpn-watchdog.timer vpn-rotate.timer --no-pager
EOF

  if ((PATH_UPDATED == 1)); then
    printf '\nA shell PATH update was added. Open a new terminal or run:\n'
    case "${SHELL:-}" in
      */zsh) printf '  source ~/.zshrc\n' ;;
      */bash) printf '  source ~/.bashrc\n' ;;
      *) printf '  export PATH="$HOME/.local/bin:$PATH"\n' ;;
    esac
  fi
}

printf '%s - Installer\n' "$PROJECT_NAME"
printf 'This installs WatchdogVPN and guides the required AdGuard VPN CLI setup.\n'

require_supported_distro
require_system_shape

if ((RUN_DOCTOR == 1)); then
  "$ROOT_DIR/doctor.sh" || warn "preflight reported issues; continuing with guided installer checks"
fi

validate_required_commands

install_official_adguard_vpn_cli

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
ensure_adguard_service_login
verify_systemd_units
install_optional_integrations
enable_systemd_units
ensure_user_local_bin_path
wait_for_services
post_install_validation
final_report
