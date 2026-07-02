#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# shellcheck source=lib/common.sh
. "$ROOT_DIR/lib/common.sh"
# shellcheck source=lib/install_files.sh
. "$ROOT_DIR/lib/install_files.sh"
# shellcheck source=lib/config.sh
. "$ROOT_DIR/lib/config.sh"
# shellcheck source=lib/systemd.sh
. "$ROOT_DIR/lib/systemd.sh"

ASSUME_YES=0
PURGE_CONFIG=0
PURGE_LOGS=0
PURGE_STATE=0
PURGE_CONKY=0
RUN_DNS_RESCUE=1

usage() {
  cat <<'USAGE'
WatchdogVPN uninstaller

Usage:
  ./uninstall.sh [--dry-run] [--yes] [--purge-config] [--purge-logs] [--purge-state] [--purge-conky] [--skip-dns-rescue]

Options:
  --dry-run       Show what would be removed without changing the system.
  --yes           Do not ask for confirmation for the basic uninstall.
  --purge-config  Also remove WatchdogVPN config files.
  --purge-logs    Also remove WatchdogVPN logs.
  --purge-state   Also remove WatchdogVPN rotation state.
  --purge-conky   Also remove WatchdogVPN Conky files.
  --skip-dns-rescue
                  Do not reset system DNS before removing product files.
  --help          Show this help.

This script never removes the official AdGuard VPN CLI or account/license state.
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
    --purge-config)
      PURGE_CONFIG=1
      ;;
    --purge-logs)
      PURGE_LOGS=1
      ;;
    --purge-state)
      PURGE_STATE=1
      ;;
    --purge-conky)
      PURGE_CONKY=1
      ;;
    --skip-dns-rescue)
      RUN_DNS_RESCUE=0
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

print_contract() {
  print_section "Removed by uninstall"
  printf 'product commands and privileged scripts\n'
  printf 'TUI launcher\n'
  printf 'product systemd units and timers\n'
  printf 'NetworkManager dispatcher\n'
  printf 'logrotate policy\n'
  printf 'desktop launcher\n'

  print_section "Preserved unless explicitly purged"
  printf '/etc/adguardvpn.env\n'
  printf '/etc/vpn-domain-bypass.conf\n'
  printf '/etc/watchdogvpn/\n'
  printf '/var/log/myvpn/\n'
  printf '/var/lib/vpn-rotate/\n'
  printf '/var/lib/watchdogvpn/\n'
  printf 'Conky configuration\n'

  print_section "Never removed"
  printf 'official AdGuard VPN CLI\n'
  printf 'AdGuard account/license state\n'
}

remove_runtime_files() {
  remove_root_path /usr/local/bin/no_vpn
  remove_root_path /usr/local/bin/vpn_auth_check
  remove_root_path /usr/local/bin/vpn_dns_rescue
  remove_root_path /usr/local/bin/vpn_backend
  remove_root_path /usr/local/bin/vpn_manual_state
  remove_root_path /usr/local/bin/vpn_notify
  remove_root_path /usr/local/bin/vpn_truth_check
  remove_root_path /usr/local/bin/vpnctl
  remove_root_path /usr/local/bin/watchdog
  remove_root_path /usr/local/bin/watchdogvpn
  remove_root_path /usr/local/bin/watchdogvpn-daemon

  remove_root_path /usr/local/sbin/vpn_domain_bypass_apply.sh
  remove_root_path /usr/local/sbin/vpn_rotate.sh
  remove_root_path /usr/local/sbin/vpn_set
  remove_root_path /usr/local/sbin/vpn_watchdog.sh

  remove_user_path "$HOME/.local/bin/VPN"
  remove_user_path "$HOME/.local/bin/watchdogvpn"
  remove_user_path "$HOME/.local/share/watchdogvpn"
  remove_user_path "$HOME/.local/share/applications/watchdogvpn.desktop"
  remove_user_path "$HOME/.local/share/applications/vpn-control-center.desktop"
  desktop_dir="$(xdg-user-dir DESKTOP 2>/dev/null || true)"
  [[ -n "$desktop_dir" ]] || desktop_dir="$HOME/Desktop"
  remove_user_path "$desktop_dir/watchdogvpn.desktop"

  remove_root_path /etc/NetworkManager/dispatcher.d/99-vpn-rotate
  remove_root_path /etc/logrotate.d/myvpn
}

remove_optional_user_data() {
  if ((PURGE_CONFIG == 1)); then
    remove_root_path /etc/adguardvpn.env
    remove_root_path /etc/vpn-domain-bypass.conf
    remove_root_path "$WATCHDOGVPN_CONFIG_DIR"
  else
    printf '[KEEP] config: /etc/adguardvpn.env\n'
    printf '[KEEP] config: /etc/vpn-domain-bypass.conf\n'
    printf '[KEEP] config: %s\n' "$WATCHDOGVPN_CONFIG_DIR"
  fi

  if ((PURGE_LOGS == 1)); then
    remove_root_path /var/log/myvpn
  else
    printf '[KEEP] logs: /var/log/myvpn\n'
  fi

  if ((PURGE_STATE == 1)); then
    remove_root_path /var/lib/vpn-rotate
    remove_root_path /var/lib/watchdogvpn
  else
    printf '[KEEP] state: /var/lib/vpn-rotate\n'
    printf '[KEEP] state: /var/lib/watchdogvpn\n'
  fi

  if ((PURGE_CONKY == 1)); then
    remove_user_path "$HOME/.conky/WatchdogVPN"
  else
    printf '[KEEP] conky: %s\n' "$HOME/.conky/WatchdogVPN"
  fi
}

rescue_system_dns() {
  if ((RUN_DNS_RESCUE == 0)); then
    printf '[SKIP] DNS rescue disabled\n'
    return 0
  fi

  if [[ -x "$ROOT_DIR/bin/vpn_dns_rescue" ]]; then
    if [[ "${INSTALL_DRY_RUN:-0}" == "1" ]]; then
      INSTALL_DRY_RUN=1 "$ROOT_DIR/bin/vpn_dns_rescue" auto --no-reconnect || true
    else
      "$ROOT_DIR/bin/vpn_dns_rescue" auto --no-reconnect || true
    fi
    return 0
  fi

  if [[ -x /usr/local/bin/vpn_dns_rescue ]]; then
    if [[ "${INSTALL_DRY_RUN:-0}" == "1" ]]; then
      INSTALL_DRY_RUN=1 /usr/local/bin/vpn_dns_rescue auto --no-reconnect || true
    else
      /usr/local/bin/vpn_dns_rescue auto --no-reconnect || true
    fi
    return 0
  fi

  printf '[WARN] DNS rescue tool not found; if DNS breaks, restore DHCP DNS manually.\n'
}

final_report() {
  print_title "WatchdogVPN uninstall completed"
  print_field "AdGuard VPN CLI" "preserved"
  print_field "Account/license state" "preserved"
  print_field "Config purged" "$(yes_no_word "$PURGE_CONFIG")"
  print_field "Logs purged" "$(yes_no_word "$PURGE_LOGS")"
  print_field "Rotation state purged" "$(yes_no_word "$PURGE_STATE")"
  print_field "Conky files purged" "$(yes_no_word "$PURGE_CONKY")"

  print_section "Recovery"
  printf 'To reinstall, run: ./install.sh\n'
  printf 'If DNS looks wrong, run: vpn_dns_rescue auto --no-reconnect\n'
}

print_uninstall_plan() {
  print_title "WatchdogVPN uninstall plan"
  print_field "Product files" "remove"
  print_field "Systemd units" "disable and remove"
  print_field "DNS rescue" "$(yes_no_word "$RUN_DNS_RESCUE")"
  print_field "Purge config" "$(yes_no_word "$PURGE_CONFIG")"
  print_field "Purge logs" "$(yes_no_word "$PURGE_LOGS")"
  print_field "Purge state" "$(yes_no_word "$PURGE_STATE")"
  print_field "Purge Conky" "$(yes_no_word "$PURGE_CONKY")"
  print_field "Dry run" "$(yes_no_word "${INSTALL_DRY_RUN:-0}")"
  print_field "Backups" "$BACKUP_ROOT"
}

print_title "$PROJECT_NAME Uninstall"
print_contract

if [[ "${INSTALL_DRY_RUN:-0}" == "1" ]]; then
  warn "dry-run mode: no system changes will be made"
else
  print_section "Privilege check"
  sudo -v
fi

if ((ASSUME_YES == 0)); then
  printf '\nThis removes WatchdogVPN product files but keeps the official AdGuard VPN CLI.\n'
  if ! prompt_yes_no "Remove WatchdogVPN product files from this system?" no; then
    warn "uninstall cancelled"
    exit 0
  fi
fi

printf '\nThe next options control whether user data is purged. Defaults preserve data.\n'
if ((PURGE_CONFIG == 0)) && prompt_yes_no "Also remove WatchdogVPN config files?" no; then
  PURGE_CONFIG=1
fi

if ((PURGE_LOGS == 0)) && prompt_yes_no "Also remove WatchdogVPN logs?" no; then
  PURGE_LOGS=1
fi

if ((PURGE_STATE == 0)) && prompt_yes_no "Also remove WatchdogVPN rotation state?" no; then
  PURGE_STATE=1
fi

if ((PURGE_CONKY == 0)) && prompt_yes_no "Also remove WatchdogVPN Conky files?" no; then
  PURGE_CONKY=1
fi

print_uninstall_plan
print_section "Disable services"
disable_systemd_units
print_section "DNS rescue"
rescue_system_dns
print_section "Remove systemd units"
remove_systemd_units
print_section "Remove product files"
remove_runtime_files
print_section "Remove optional user data"
remove_optional_user_data
final_report
