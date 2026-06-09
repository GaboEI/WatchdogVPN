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
# shellcheck source=lib/config.sh
. "$ROOT_DIR/lib/config.sh"
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
BACKEND_MODE="adguard"
BACKEND_ACTIVE="adguard"
CUSTOM_VPS_ENABLED="false"
CUSTOM_VPS_NAME=""
CUSTOM_VPS_HOST=""
CUSTOM_VPS_SSH_USER=""
CUSTOM_VPS_SSH_PORT="22"
CUSTOM_VPS_PROTOCOL=""
CUSTOM_VPS_PROFILE_PATH=""
CUSTOM_VPS_SERVICE_NAME=""
CUSTOM_VPS_INTERFACE=""
ENABLE_ADGUARD_BACKEND=1
ENABLE_VPN_AUTOMATION=1
PATH_UPDATED=0

usage() {
  cat <<'USAGE'
WatchdogVPN installer

Usage:
  ./install.sh [--dry-run] [--yes] [--skip-doctor]

Options:
  --dry-run       Show what would be installed without changing the system.
  --yes           Use product defaults: backend AdGuard, DNS off, desktop on, Conky off.
  --skip-doctor   Do not run the read-only preflight first.
  --help          Show this help.

What this installer manages:
  - WatchdogVPN runtime commands and privileged scripts.
  - WatchdogVPN systemd units and timers.
  - Backend selection for AdGuard VPN, Custom VPS or both.
  - Optional AdGuard Home DNS integration.
  - Optional desktop launcher and Conky integration.

It does not remove the official AdGuard VPN CLI or account/license state.
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

prompt_backend_mode() {
  local answer

  if ((ASSUME_YES == 1)); then
    BACKEND_MODE="adguard"
    BACKEND_ACTIVE="adguard"
    CUSTOM_VPS_ENABLED="false"
    ENABLE_ADGUARD_BACKEND=1
    ENABLE_VPN_AUTOMATION=1
    return 0
  fi

  printf '\nSelect VPN backend:\n'
  printf '  1. AdGuard VPN\n'
  printf '  2. Custom VPS\n'
  printf '  3. Both\n'
  printf '\n'

  while true; do
    read -r -p "Backend choice [1/2/3, default 1]: " answer
    answer="${answer:-1}"
    case "$answer" in
      1|adguard|AdGuard|ADGUARD)
        BACKEND_MODE="adguard"
        BACKEND_ACTIVE="adguard"
        CUSTOM_VPS_ENABLED="false"
        ENABLE_ADGUARD_BACKEND=1
        ENABLE_VPN_AUTOMATION=1
        return 0
        ;;
      2|custom-vps|custom|vps|VPS)
        BACKEND_MODE="custom-vps"
        BACKEND_ACTIVE="custom-vps"
        CUSTOM_VPS_ENABLED="true"
        ENABLE_ADGUARD_BACKEND=0
        ENABLE_VPN_AUTOMATION=0
        printf 'Custom VPS backend setup is experimental and uses a user-configured local service.\n'
        printf 'No passwords, private keys or server secrets will be requested.\n'
        return 0
        ;;
      3|both|Both|BOTH)
        BACKEND_MODE="both"
        BACKEND_ACTIVE="adguard"
        CUSTOM_VPS_ENABLED="true"
        ENABLE_ADGUARD_BACKEND=1
        ENABLE_VPN_AUTOMATION=1
        printf 'Both mode keeps AdGuard active now and prepares Custom VPS config for later.\n'
        return 0
        ;;
    esac
  done
}

prompt_text() {
  local question="$1" default="${2:-}" answer
  if [[ -n "$default" ]]; then
    read -r -p "$question [$default]: " answer
    printf '%s\n' "${answer:-$default}"
  else
    read -r -p "$question: " answer
    printf '%s\n' "$answer"
  fi
}

prompt_custom_vps_config() {
  local port

  [[ "$CUSTOM_VPS_ENABLED" == "true" ]] || return 0

  if ((ASSUME_YES == 1)); then
    return 0
  fi

  printf '\nCustom VPS configuration stores only non-secret local metadata.\n'
  printf 'Do not enter passwords, private keys, tokens or certificate pins here.\n'
  printf 'You can leave fields empty and complete them later in /etc/watchdogvpn/config.toml.\n\n'

  CUSTOM_VPS_NAME="$(prompt_text "Display name" "$CUSTOM_VPS_NAME")"
  CUSTOM_VPS_HOST="$(prompt_text "VPS host or IP" "$CUSTOM_VPS_HOST")"
  CUSTOM_VPS_SSH_USER="$(prompt_text "SSH user" "$CUSTOM_VPS_SSH_USER")"
  port="$(prompt_text "SSH port" "$CUSTOM_VPS_SSH_PORT")"
  if [[ "$port" =~ ^[0-9]+$ ]] && ((port >= 1 && port <= 65535)); then
    CUSTOM_VPS_SSH_PORT="$port"
  else
    warn "invalid SSH port; keeping 22"
    CUSTOM_VPS_SSH_PORT="22"
  fi
  CUSTOM_VPS_PROTOCOL="$(prompt_text "Protocol label (example: awg, wireguard, openvpn, hysteria2)" "$CUSTOM_VPS_PROTOCOL")"
  CUSTOM_VPS_PROFILE_PATH="$(prompt_text "Local profile path" "$CUSTOM_VPS_PROFILE_PATH")"
  CUSTOM_VPS_SERVICE_NAME="$(prompt_text "Local service name" "$CUSTOM_VPS_SERVICE_NAME")"
  CUSTOM_VPS_INTERFACE="$(prompt_text "Tunnel interface (example: wg0, awg0, tun0)" "$CUSTOM_VPS_INTERFACE")"
}

config_write_installed_key() {
  local key="$1" value="$2" section name formatted tmp
  section="${key%%.*}"
  name="${key#*.}"

  if [[ "$value" == "true" || "$value" == "false" || "$value" =~ ^[0-9]+$ ]]; then
    formatted="$value"
  else
    value="${value//\\/\\\\}"
    value="${value//\"/\\\"}"
    formatted="\"$value\""
  fi

  if [[ "${INSTALL_DRY_RUN:-0}" == "1" ]]; then
    printf '[DRY-RUN] set %s = %s in %s\n' "$key" "$formatted" "$WATCHDOGVPN_CONFIG_FILE"
    return 0
  fi

  tmp="$(mktemp)"
  awk -v section="$section" -v name="$name" -v value="$formatted" '
    $0 ~ "^[[:space:]]*\\[" section "\\][[:space:]]*$" {in_section=1; print; next}
    $0 ~ "^[[:space:]]*\\[[^]]+\\][[:space:]]*$" {in_section=0}
    in_section && $0 ~ "^[[:space:]]*" name "[[:space:]]*=" {
      print name " = " value
      changed=1
      next
    }
    {print}
    END {exit changed ? 0 : 1}
  ' "$WATCHDOGVPN_CONFIG_FILE" >"$tmp"
  run_step sudo install -m 0644 -o root -g root "$tmp" "$WATCHDOGVPN_CONFIG_FILE"
  rm -f "$tmp"
}

apply_backend_install_selection() {
  print_section "Backend configuration"
  config_write_installed_key backend.mode "$BACKEND_MODE"
  config_write_installed_key backend.active "$BACKEND_ACTIVE"
  config_write_installed_key custom_vps.enabled "$CUSTOM_VPS_ENABLED"
  config_write_installed_key custom_vps.name "$CUSTOM_VPS_NAME"
  config_write_installed_key custom_vps.host "$CUSTOM_VPS_HOST"
  config_write_installed_key custom_vps.ssh_user "$CUSTOM_VPS_SSH_USER"
  config_write_installed_key custom_vps.ssh_port "$CUSTOM_VPS_SSH_PORT"
  config_write_installed_key custom_vps.protocol "$CUSTOM_VPS_PROTOCOL"
  config_write_installed_key custom_vps.profile_path "$CUSTOM_VPS_PROFILE_PATH"
  config_write_installed_key custom_vps.service_name "$CUSTOM_VPS_SERVICE_NAME"
  config_write_installed_key custom_vps.interface "$CUSTOM_VPS_INTERFACE"
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

require_system_shape() {
  if [[ "$(ps -p 1 -o comm= 2>/dev/null || true)" != "systemd" ]]; then
    if [[ "${INSTALL_DRY_RUN:-0}" == "1" ]]; then
      warn "systemd is required; dry-run continues without validating init PID 1"
    else
      fail "systemd is required"
      printf 'WatchdogVPN installs system services and timers. Run it on a systemd-based distro.\n'
      exit 1
    fi
  fi

  if ! command -v systemctl >/dev/null 2>&1; then
    fail "systemd is required"
    printf 'Missing command: systemctl\n'
    exit 1
  fi

  if ! command -v sudo >/dev/null 2>&1; then
    fail "sudo is required"
    printf 'Install sudo or run from an environment where privileged setup is available.\n'
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
  printf 'WatchdogVPN will ask the distro package manager to install missing prerequisites.\n'
  install_package_set "${DISTRO_BASE_PACKAGES[@]}"
}

validate_repo_runtime() {
  python3 -m compileall -q "$ROOT_DIR/tui"
  bash "$ROOT_DIR/tests/syntax.sh" >/dev/null
  ok "repository runtime validated"
}

auth_state() {
  local raw
  raw="$(ADGUARDVPN_CLI="${ADGUARDVPN_CLI:-/usr/local/bin/adguardvpn-cli}" "$ROOT_DIR/bin/vpn_auth_check" 2>/dev/null || true)"
  printf '%s\n' "$raw" | awk -F= '$1 == "AUTH" {print $2; exit}'
}

auth_detail() {
  local raw
  raw="$(ADGUARDVPN_CLI="${ADGUARDVPN_CLI:-/usr/local/bin/adguardvpn-cli}" "$ROOT_DIR/bin/vpn_auth_check" 2>/dev/null || true)"
  printf '%s\n' "$raw"
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
    auth_detail
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

truth_status() {
  /usr/local/bin/vpn_truth_check 2>/dev/null | awk -F= '$1 == "STATUS" {print $2; exit}'
}

wait_for_vpn_truth() {
  local timeout="${1:-30}" elapsed=0 status=""

  while ((elapsed < timeout)); do
    status="$(truth_status || true)"
    [[ "$status" == "UP" ]] && return 0
    sleep 3
    elapsed=$((elapsed + 3))
  done

  [[ -n "$status" ]] && printf '%s\n' "$status"
  return 1
}

settle_vpn_after_install() {
  local status=""

  if [[ "$ENABLE_ADGUARD_BACKEND" != "1" ]]; then
    printf '[SKIP] AdGuard VPN settle check; selected backend is %s\n' "$BACKEND_MODE"
    return 0
  fi

  if [[ "${INSTALL_DRY_RUN:-0}" == "1" ]]; then
    printf '[DRY-RUN] validate VPN tunnel after install\n'
    return 0
  fi

  print_section "VPN settle check"
  if wait_for_vpn_truth 30 >/dev/null; then
    ok "VPN truth state is UP"
    return 0
  fi

  status="$(truth_status || true)"
  if [[ "$status" == "DEGRADED" ]]; then
    warn "VPN truth state is DEGRADED after initial service start"
    warn "restarting adguardvpn.service once before final validation"
    sudo systemctl restart adguardvpn.service || true
    if wait_for_vpn_truth 30 >/dev/null; then
      ok "VPN truth state recovered after service restart"
      return 0
    fi
    status="$(truth_status || true)"
  fi

  warn "VPN truth state after install: ${status:-UNKNOWN}"
  printf 'If the dashboard stays degraded, reboot once and rerun:\n'
  printf '  cd %s\n' "$ROOT_DIR"
  printf '  ./doctor.sh\n'
  printf '  vpnctl status\n'
}

post_install_validation() {
  local doctor_rc=0 dns_rc=0

  if [[ "$ENABLE_ADGUARD_BACKEND" != "1" ]]; then
    printf '\n== Final validation ==\n'
    printf '[SKIP] AdGuard runtime validation; selected backend is %s\n' "$BACKEND_MODE"
    printf '[INFO] Custom VPS backend is experimental and controlled through custom_vps.service_name.\n'
    return 0
  fi

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
  print_title "WatchdogVPN installation completed"
  print_field "TUI command" "VPN"
  print_field "Diagnostics" "./doctor.sh"
  print_field "Runtime status" "vpnctl status"
  print_field "DNS test" "vpn_dnsctl local-test"
  if [[ "$ENABLE_ADGUARD_BACKEND" == "1" ]]; then
    print_field "Service status" "systemctl status adguardvpn.service vpn-watchdog.timer vpn-rotate.timer --no-pager"
  else
    print_field "Backend status" "watchdogvpn backend status"
  fi

  print_section "Next steps"
  printf '1. Open the TUI with: VPN\n'
  printf '2. Check the dashboard state.\n'
  printf '3. Run ./doctor.sh if anything looks wrong.\n'

  if ((PATH_UPDATED == 1)); then
    printf '\nA shell PATH update was added. Open a new terminal or run:\n'
    case "${SHELL:-}" in
      */zsh) printf '  source ~/.zshrc\n' ;;
      */bash) printf '  source ~/.bashrc\n' ;;
      *) printf '  export PATH="$HOME/.local/bin:$PATH"\n' ;;
    esac
  fi
}

print_install_plan() {
  print_title "WatchdogVPN installation plan"
  print_field "Target distro" "$DISTRO_NAME ($DISTRO_ID)"
  print_field "Runtime commands" "/usr/local/bin"
  print_field "Privileged scripts" "/usr/local/sbin"
  print_field "Systemd units" "enabled"
  print_field "Backend mode" "$BACKEND_MODE"
  print_field "Active backend" "$BACKEND_ACTIVE"
  print_field "Advanced DNS" "$(yes_no_word "$ENABLE_ADVANCED_DNS")"
  print_field "Desktop launcher" "$(yes_no_word "$INSTALL_DESKTOP")"
  print_field "Conky integration" "$(yes_no_word "$INSTALL_CONKY")"
  print_field "Backups" "$BACKUP_ROOT"
  print_field "Dry run" "$(yes_no_word "${INSTALL_DRY_RUN:-0}")"
}

print_title "$PROJECT_NAME Installer"
printf 'Installs WatchdogVPN and guides backend setup.\n'

require_supported_distro
require_system_shape

if ((RUN_DOCTOR == 1)); then
  print_section "Read-only preflight"
  "$ROOT_DIR/doctor.sh" || warn "preflight reported issues; continuing with guided installer checks"
fi

print_section "Prerequisites"
validate_required_commands

prompt_backend_mode
prompt_custom_vps_config

if [[ "$ENABLE_ADGUARD_BACKEND" == "1" ]]; then
  install_official_adguard_vpn_cli
else
  printf '[SKIP] AdGuard VPN CLI installation; selected backend is %s\n' "$BACKEND_MODE"
fi

printf '\nAdvanced DNS with AdGuard Home is optional. It enables DNS profile management\n'
printf 'with preflight checks, backup and rollback. You can skip it and enable it later.\n'
if prompt_yes_no "Enable advanced DNS mode with AdGuard Home?" no; then
  ENABLE_ADVANCED_DNS=1
else
  ENABLE_ADVANCED_DNS=0
fi

printf '\nThe desktop launcher adds WatchdogVPN to the applications menu and user desktop.\n'
if prompt_yes_no "Install desktop launcher for this user?" yes; then
  INSTALL_DESKTOP=1
else
  INSTALL_DESKTOP=0
fi

printf '\nConky integration is optional and only useful if this desktop uses Conky widgets.\n'
if prompt_yes_no "Install Conky integration for this user?" no; then
  INSTALL_CONKY=1
else
  INSTALL_CONKY=0
fi

print_install_plan

if [[ "${INSTALL_DRY_RUN:-0}" == "1" ]]; then
  warn "dry-run mode: no system changes will be made"
else
  print_section "Privilege check"
  sudo -v
fi

print_section "Runtime validation"
validate_repo_runtime
print_section "Install runtime"
install_runtime_files
apply_backend_install_selection
print_section "AdGuard VPN login"
if [[ "$ENABLE_ADGUARD_BACKEND" == "1" ]]; then
  ensure_adguard_service_login
else
  printf '[SKIP] AdGuard VPN login; selected backend is %s\n' "$BACKEND_MODE"
fi
print_section "Systemd verification"
verify_systemd_units
print_section "Optional integrations"
install_optional_integrations
print_section "Enable services"
enable_systemd_units
ensure_user_local_bin_path
wait_for_services
settle_vpn_after_install
post_install_validation
final_report
