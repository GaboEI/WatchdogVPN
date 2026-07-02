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
# shellcheck source=lib/runtime.sh
. "$ROOT_DIR/lib/runtime.sh"
# shellcheck source=lib/desktop.sh
. "$ROOT_DIR/lib/desktop.sh"
# shellcheck source=lib/conky.sh
. "$ROOT_DIR/lib/conky.sh"
# shellcheck source=lib/singbox.sh
. "$ROOT_DIR/lib/singbox.sh"

ASSUME_YES=0
RUN_DOCTOR=1
INSTALL_DESKTOP=""
INSTALL_CONKY=""
BACKEND_MODE="custom-vps"
BACKEND_ACTIVE="custom-vps"
CUSTOM_VPS_ENABLED="true"
CUSTOM_VPS_NAME=""
CUSTOM_VPS_HOST=""
CUSTOM_VPS_SSH_USER=""
CUSTOM_VPS_SSH_PORT="22"
CUSTOM_VPS_PROTOCOL=""
CUSTOM_VPS_PROFILE_PATH=""
CUSTOM_VPS_SERVICE_NAME=""
CUSTOM_VPS_INTERFACE=""
ENABLE_VPN_AUTOMATION=0
PATH_UPDATED=0

usage() {
  cat <<'USAGE'
WatchdogVPN installer

Usage:
  ./install.sh [--dry-run] [--yes] [--skip-doctor]

Options:
  --dry-run       Show what would be installed without changing the system.
  --yes           Use product defaults: Custom VPS backend, desktop on, Conky off.
  --skip-doctor   Do not run the read-only preflight first.
  --help          Show this help.

What this installer manages:
  - WatchdogVPN runtime commands and privileged scripts.
  - WatchdogVPN systemd units and timers.
  - Custom VPS backend configuration.
  - Optional desktop launcher and Conky integration.
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
  BACKEND_MODE="custom-vps"
  BACKEND_ACTIVE="custom-vps"
  CUSTOM_VPS_ENABLED="true"
  ENABLE_VPN_AUTOMATION=0

  if ((ASSUME_YES == 1)); then
    return 0
  fi

  printf '\nWatchdogVPN backend: Custom VPS (a user-configured local service).\n'
  printf 'No passwords, private keys or server secrets will be requested.\n'
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

install_optional_integrations() {
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

settle_vpn_after_install() {
  printf '[SKIP] automatic VPN settle check; selected backend is %s\n' "$BACKEND_MODE"
  printf 'If the dashboard stays degraded, reboot once and rerun:\n'
  printf '  cd %s\n' "$ROOT_DIR"
  printf '  ./doctor.sh\n'
  printf '  vpnctl status\n'
}

post_install_validation() {
  printf '\n== Final validation ==\n'
  printf '[SKIP] automatic runtime validation; selected backend is %s\n' "$BACKEND_MODE"
  printf '[INFO] Custom VPS backend is experimental and controlled through custom_vps.service_name.\n'
}

final_report() {
  print_title "WatchdogVPN installation completed"
  print_field "TUI command" "VPN"
  print_field "Diagnostics" "./doctor.sh"
  print_field "Runtime status" "vpnctl status"
  print_field "Backend status" "watchdogvpn backend status"

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

if [[ "$CUSTOM_VPS_ENABLED" == "true" ]]; then
  install_official_singbox
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
