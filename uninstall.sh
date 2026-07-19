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
# shellcheck source=lib/uninstall_safety.sh
. "$ROOT_DIR/lib/uninstall_safety.sh"
# shellcheck source=lib/runtime.sh
. "$ROOT_DIR/lib/runtime.sh"

ASSUME_YES=0
PURGE_CONFIG=0
PURGE_LOGS=0
PURGE_STATE=0
CONFIRM_DELETE=""
FULL_PURGE=0
INTERNAL_BACKUP_ROOT="/var/backups/watchdogvpn"

usage() {
  cat <<'USAGE'
WatchdogVPN uninstaller

Usage:
  ./uninstall.sh [--dry-run] [--yes] [--purge-config] [--purge-logs] [--purge-state] [--confirm-delete DELETE]

Options:
  --dry-run       Show what would be removed without changing the system.
  --yes           Do not ask for confirmation for the basic uninstall.
  --purge-config  Also remove WatchdogVPN config files.
  --purge-logs    Also remove WatchdogVPN logs.
  --purge-state   Also remove WatchdogVPN rotation state.
  --confirm-delete DELETE
                  Required literal confirmation before purging WatchdogVPN data.
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
    --purge-config)
      PURGE_CONFIG=1
      ;;
    --purge-logs)
      PURGE_LOGS=1
      ;;
    --purge-state)
      PURGE_STATE=1
      ;;
    --confirm-delete)
      shift
      [[ $# -gt 0 ]] || fail "--confirm-delete requires DELETE"
      CONFIRM_DELETE="$1"
      ;;
    --skip-dns-rescue)
      fail "--skip-dns-rescue is unsafe and no longer supported"
      exit 64
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
  printf '/run/watchdogvpn/ and an empty WatchdogVPN-created /run/amneziawg/\n'
  printf 'orphaned pre-Phase-2.6 (AdGuard-era) systemd units and scripts, if present\n'

  print_section "Preserved unless explicitly purged"
  printf '/etc/vpn-domain-bypass.conf\n'
  printf '/etc/watchdogvpn/\n'
  printf '/var/log/myvpn/\n'
  printf '/var/lib/watchdogvpn/\n'
  printf '~/.config/watchdogvpn/ legacy migration source (removed only alongside a full purge; root copy included)\n'
  printf '/etc/adguardvpn.env (legacy, if present)\n'
  printf '/var/lib/vpn-rotate/ (legacy, if present)\n'
  printf '~/.conky/WatchdogVPN/ (legacy, if present)\n'
  printf 'watchdogvpn system account and group (removed only alongside a full --purge-config --purge-logs --purge-state --confirm-delete DELETE)\n'
  printf '%s (internal recovery backups; removed only alongside that same full purge)\n' "$INTERNAL_BACKUP_ROOT"
}

configure_full_purge_contract() {
  if ((PURGE_CONFIG == 1 && PURGE_LOGS == 1 && PURGE_STATE == 1)); then
    FULL_PURGE=1
    # A confirmed full purge must not silently recreate unencrypted copies of
    # config, profiles, keys, state or logs while deleting them. The Python
    # CLI already exports the user's explicit pre-delete backup outside
    # product-owned paths. install/update and non-full uninstalls retain the
    # existing recovery-backup behavior.
    REMOVE_ROOT_PATH_BACKUPS=0
  fi
}

remove_runtime_files() {
  remove_root_path /usr/local/bin/no_vpn
  remove_root_path /usr/local/bin/vpn_dns_rescue
  remove_root_path /usr/local/bin/vpn_domain_bypass_rescue
  remove_root_path /usr/local/bin/watchdog_panic
  remove_root_path /usr/local/bin/vpn_backend
  remove_root_path /usr/local/bin/vpn_manual_state
  remove_root_path /usr/local/bin/vpn_notify
  remove_root_path /usr/local/bin/vpn_truth_check
  remove_root_path /usr/local/bin/vpnctl
  remove_root_path /usr/local/bin/watchdog
  remove_root_path /usr/local/bin/watchdogvpn
  remove_root_path /usr/local/bin/watchdogvpn-daemon

  remove_root_path /usr/local/sbin/vpn_domain_bypass_apply.sh

  remove_root_path "$PYTHON_PACKAGE_DIR"

  remove_user_path "$HOME/.local/bin/VPN"
  remove_user_path "$HOME/.local/bin/watchdogvpn"
  remove_user_path "$HOME/.local/share/watchdogvpn"
  remove_user_path "$HOME/.local/share/applications/watchdogvpn.desktop"
  remove_user_path "$HOME/.local/share/applications/vpn-control-center.desktop"
  # install.sh/update.sh are documented to run via sudo, which resets HOME to
  # /root for that invocation (lib/runtime.sh's install_user_file/
  # install_user_dir calls then write under /root/.local). uninstall.sh is
  # not required to run via sudo itself - when it doesn't, $HOME above is the
  # invoking user's, so root's own copies are otherwise never reached. Safe
  # to also target them unconditionally: remove_root_path is a no-op
  # ([KEEP] absent) when uninstall.sh itself ran as root and already removed
  # them via $HOME above.
  remove_root_path /root/.local/bin/VPN
  remove_root_path /root/.local/share/watchdogvpn
  desktop_dir="$(xdg-user-dir DESKTOP 2>/dev/null || true)"
  [[ -n "$desktop_dir" ]] || desktop_dir="$HOME/Desktop"
  remove_user_path "$desktop_dir/watchdogvpn.desktop"

  remove_root_path /etc/logrotate.d/myvpn
  remove_root_path /etc/polkit-1/rules.d/49-watchdogvpn-resolved.rules
}

remove_product_runtime_directories() {
  # RuntimeDirectory normally disappears when systemd stops the service. An
  # interrupted installation can roll the unit back before systemd gets that
  # cleanup opportunity, leaving root-owned runtime paths with an orphaned
  # numeric UID/GID. These paths are ephemeral and must never be backed up.
  remove_root_path_no_backup /run/watchdogvpn

  # /run/amneziawg is the conventional UAPI location and may be shared by an
  # independently managed AmneziaWG process. Remove the directory only when
  # it is a real, empty directory; preserve any non-empty or symlinked path.
  if [[ -L /run/amneziawg ]]; then
    warn "preserving symlinked shared AmneziaWG runtime path: /run/amneziawg"
    return 0
  fi
  if [[ ! -d /run/amneziawg ]]; then
    printf '[KEEP] absent: /run/amneziawg\n'
    return 0
  fi
  if [[ "${INSTALL_DRY_RUN:-0}" == "1" ]]; then
    printf '[DRY-RUN] remove empty shared runtime directory /run/amneziawg\n'
    return 0
  fi
  if sudo rmdir -- /run/amneziawg 2>/dev/null; then
    printf '[REMOVE] empty shared runtime directory: /run/amneziawg\n'
  else
    warn "preserving non-empty shared AmneziaWG runtime path: /run/amneziawg"
  fi
}

remove_legacy_user_config_on_full_purge() {
  local sudo_user="${SUDO_USER:-}" sudo_user_home=""

  # Shared-state migration intentionally preserves its per-user source so an
  # install/update is recoverable. A confirmed delete-all-data purge is the
  # one operation that must remove that second copy too. Limit deletion to the
  # current home, root's known historical sudo-created copy, and (when the
  # whole script was invoked through sudo) the invoking user's NSS home.
  remove_user_path "$HOME/.config/watchdogvpn"
  if [[ "$HOME/.config/watchdogvpn" != "/root/.config/watchdogvpn" ]]; then
    remove_root_path /root/.config/watchdogvpn
  fi

  if [[ -n "$sudo_user" && "$sudo_user" != "root" ]]; then
    sudo_user_home="$(getent passwd "$sudo_user" 2>/dev/null | awk -F: 'NR == 1 {print $6}' || true)"
    if [[ "$sudo_user_home" == /* && "$sudo_user_home" != "/" ]]; then
      if [[ "$sudo_user_home/.config/watchdogvpn" != "$HOME/.config/watchdogvpn" ]]; then
        remove_root_path "$sudo_user_home/.config/watchdogvpn"
      fi
    else
      warn "cannot resolve a safe home for legacy full-purge cleanup: $sudo_user"
    fi
  fi
}

remove_optional_user_data() {
  if ((PURGE_CONFIG == 1)); then
    remove_root_path /etc/vpn-domain-bypass.conf
    remove_root_path "$WATCHDOGVPN_ETC_CONFIG_DIR"
    remove_root_path /etc/adguardvpn.env
    remove_user_path "$HOME/.conky/WatchdogVPN"
  else
    printf '[KEEP] config: /etc/vpn-domain-bypass.conf\n'
    printf '[KEEP] config: %s\n' "$WATCHDOGVPN_ETC_CONFIG_DIR"
    printf '[KEEP] legacy config: /etc/adguardvpn.env\n'
    printf '[KEEP] legacy conky: %s\n' "$HOME/.conky/WatchdogVPN"
  fi

  if ((FULL_PURGE == 1)); then
    remove_legacy_user_config_on_full_purge
  else
    printf '[KEEP] legacy user config: %s\n' "$HOME/.config/watchdogvpn"
    printf '[KEEP] legacy root config: /root/.config/watchdogvpn\n'
  fi

  if ((PURGE_LOGS == 1)); then
    remove_root_path /var/log/myvpn
  else
    printf '[KEEP] logs: /var/log/myvpn\n'
  fi

  if ((PURGE_STATE == 1)); then
    remove_root_path /var/lib/watchdogvpn
    remove_root_path /var/lib/vpn-rotate
  else
    printf '[KEEP] state: /var/lib/watchdogvpn\n'
    printf '[KEEP] legacy state: /var/lib/vpn-rotate\n'
  fi

  # The service account is scoped to config/logs/state, not to any single
  # one of them - only remove it once all three are gone, matching the
  # dpkg --purge convention instead of tying it to one arbitrary flag.
  if ((FULL_PURGE == 1)); then
    remove_watchdogvpn_system_account
  else
    printf '[KEEP] system account: watchdogvpn (removed only alongside a full purge)\n'
  fi
}

remove_internal_recovery_backups() {
  if ((FULL_PURGE == 1)); then
    # Never derive this destructive target from BACKUP_ROOT: callers may set a
    # custom, user-owned recovery location. Only the fixed product-owned root
    # is part of the full-purge contract.
    remove_root_path_no_backup "$INTERNAL_BACKUP_ROOT"
  else
    printf '[KEEP] internal recovery backups: %s\n' "$INTERNAL_BACKUP_ROOT"
  fi
}

require_delete_confirmation() {
  local answer
  if ((PURGE_CONFIG == 0 && PURGE_LOGS == 0 && PURGE_STATE == 0)); then
    return 0
  fi
  if [[ "${INSTALL_DRY_RUN:-0}" == "1" ]]; then
    return 0
  fi
  if [[ "$CONFIRM_DELETE" == "DELETE" ]]; then
    return 0
  fi
  if [[ -t 0 ]]; then
    printf '\nPurging WatchdogVPN data is destructive.\n'
    read -r -p "Type DELETE to purge selected WatchdogVPN data: " answer
    [[ "$answer" == "DELETE" ]] && return 0
  fi
  fail "data purge requires --confirm-delete DELETE"
}

rescue_domain_bypass_routing() {
  # Stopping/disabling vpn-domain-bypass.timer does not undo ip rule entries
  # it already applied - only actually running the rescue script removes
  # them. Without this, a machine that uninstalls WatchdogVPN while another
  # VPN/proxy client is active could be left with the exact routing conflict
  # documented in docs/security.md's "Domain bypass network safety".
  if [[ -x "$ROOT_DIR/bin/vpn_domain_bypass_rescue" ]]; then
    if [[ "${INSTALL_DRY_RUN:-0}" == "1" ]]; then
      INSTALL_DRY_RUN=1 "$ROOT_DIR/bin/vpn_domain_bypass_rescue" auto --strict
    else
      "$ROOT_DIR/bin/vpn_domain_bypass_rescue" auto --strict
    fi
    return 0
  fi

  if [[ -x /usr/local/bin/vpn_domain_bypass_rescue ]]; then
    if [[ "${INSTALL_DRY_RUN:-0}" == "1" ]]; then
      INSTALL_DRY_RUN=1 /usr/local/bin/vpn_domain_bypass_rescue auto --strict
    else
      /usr/local/bin/vpn_domain_bypass_rescue auto --strict
    fi
    return 0
  fi

  printf 'ERROR: domain-bypass rescue tool is not available\n' >&2
  return 1
}

rescue_system_dns() {
  if [[ -x "$ROOT_DIR/bin/vpn_dns_rescue" ]]; then
    if [[ "${INSTALL_DRY_RUN:-0}" == "1" ]]; then
      INSTALL_DRY_RUN=1 "$ROOT_DIR/bin/vpn_dns_rescue" auto --no-reconnect --strict
    else
      "$ROOT_DIR/bin/vpn_dns_rescue" auto --no-reconnect --strict
    fi
    return 0
  fi

  if [[ -x /usr/local/bin/vpn_dns_rescue ]]; then
    if [[ "${INSTALL_DRY_RUN:-0}" == "1" ]]; then
      INSTALL_DRY_RUN=1 /usr/local/bin/vpn_dns_rescue auto --no-reconnect --strict
    else
      /usr/local/bin/vpn_dns_rescue auto --no-reconnect --strict
    fi
    return 0
  fi

  printf 'ERROR: DNS rescue tool is not available\n' >&2
  return 1
}

final_report() {
  print_title "WatchdogVPN uninstall completed"
  print_field "Config purged" "$(yes_no_word "$PURGE_CONFIG")"
  print_field "Logs purged" "$(yes_no_word "$PURGE_LOGS")"
  print_field "Rotation state purged" "$(yes_no_word "$PURGE_STATE")"

  print_section "Recovery"
  printf 'To reinstall, run: ./install.sh\n'
  printf 'If DNS looks wrong, run: vpn_dns_rescue auto --no-reconnect --strict\n'
  printf 'If another VPN client cannot set routes, run: vpn_domain_bypass_rescue auto --strict\n'
}

print_uninstall_plan() {
  print_title "WatchdogVPN uninstall plan"
  print_field "Product files" "remove"
  print_field "Systemd units" "disable and remove"
  print_field "DNS rescue" "required and verified"
  print_field "Purge config" "$(yes_no_word "$PURGE_CONFIG")"
  print_field "Purge logs" "$(yes_no_word "$PURGE_LOGS")"
  print_field "Purge state" "$(yes_no_word "$PURGE_STATE")"
  print_field "Dry run" "$(yes_no_word "${INSTALL_DRY_RUN:-0}")"
  if ((FULL_PURGE == 1)); then
    print_field "Internal backups" "remove $INTERNAL_BACKUP_ROOT; do not create new copies"
  else
    print_field "Backups" "$BACKUP_ROOT"
  fi
}

print_title "$PROJECT_NAME Uninstall"
print_contract

if [[ "${INSTALL_DRY_RUN:-0}" == "1" ]]; then
  warn "dry-run mode: no system changes will be made"
fi
require_installer_privileges

if ((ASSUME_YES == 0)); then
  printf '\nThis removes WatchdogVPN product files from this system.\n'
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

require_delete_confirmation
configure_full_purge_contract

print_uninstall_plan
print_section "Stop and verify daemon inactivity"
if ! stop_watchdogvpn_for_uninstall; then
  uninstall_abort_with_recovery "watchdogvpn daemon inactivity"
  exit 1
fi
print_section "Remove and verify kill switch firewall rules"
if ! remove_kill_switch_rules_strict; then
  uninstall_abort_with_recovery "kill-switch firewall cleanup"
  exit 1
fi
print_section "Domain-bypass routing rescue"
if ! rescue_domain_bypass_routing; then
  uninstall_abort_with_recovery "domain-bypass route cleanup"
  exit 1
fi
print_section "DNS rescue"
if ! rescue_system_dns; then
  uninstall_abort_with_recovery "DNS cleanup"
  exit 1
fi
print_section "Disable remaining product services"
disable_systemd_units
print_section "Remove systemd units"
remove_systemd_units
print_section "Remove ephemeral runtime directories"
remove_product_runtime_directories
print_section "Remove legacy AdGuard-era units"
remove_legacy_systemd_units
print_section "Remove product files"
remove_runtime_files
print_section "Remove legacy AdGuard-era files"
remove_legacy_runtime_files
print_section "Remove optional user data"
remove_optional_user_data
print_section "Remove internal recovery backups"
remove_internal_recovery_backups
final_report
