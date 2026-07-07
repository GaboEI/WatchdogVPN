#!/usr/bin/env bash
set -euo pipefail

# Read-only install/update state classifier for Phase 18.5. It deliberately
# reports paths before any mutation so mixed installs fail closed instead of
# being discovered halfway through replacement.

PREFLIGHT_STATE_CLASS="unknown"
PREFLIGHT_BLOCKED=0
PREFLIGHT_BLOCK_REASONS=()

preflight_path() {
  local path="$1" root="${WATCHDOGVPN_PREFLIGHT_ROOT:-}"
  if [[ -n "$root" && "$path" == /* ]]; then
    printf '%s%s\n' "${root%/}" "$path"
  else
    printf '%s\n' "$path"
  fi
}

preflight_display_path() {
  local path="$1" root="${WATCHDOGVPN_PREFLIGHT_ROOT:-}"
  if [[ -n "$root" && "$path" == "$root"/* ]]; then
    printf '%s\n' "${path#"$root"}"
  else
    printf '%s\n' "$path"
  fi
}

preflight_home_path() {
  local suffix="$1"
  printf '%s/%s\n' "${HOME%/}" "$suffix"
}

preflight_exists() {
  local path="$1"
  [[ -e "$path" || -L "$path" ]]
}

preflight_has_children() {
  local path="$1"
  [[ -d "$path" ]] || return 1
  [[ -n "$(find "$path" -mindepth 1 ! -name .migrated -print -quit 2>/dev/null || true)" ]]
}

preflight_add_block() {
  PREFLIGHT_BLOCKED=1
  PREFLIGHT_BLOCK_REASONS+=("$1")
}

preflight_current_core_paths() {
  preflight_path /usr/local/bin/watchdog
  preflight_path /usr/local/bin/watchdogvpn
  preflight_path /usr/local/bin/watchdogvpn-daemon
  preflight_path /usr/local/lib/watchdogvpn
  preflight_path /etc/systemd/system/watchdogvpn.service
}

preflight_current_runtime_files() {
  preflight_path /usr/local/bin/no_vpn
  preflight_path /usr/local/bin/vpn_dns_rescue
  preflight_path /usr/local/bin/vpn_domain_bypass_rescue
  preflight_path /usr/local/bin/watchdog_panic
  preflight_path /usr/local/bin/vpn_backend
  preflight_path /usr/local/bin/vpn_manual_state
  preflight_path /usr/local/bin/vpn_notify
  preflight_path /usr/local/bin/vpn_truth_check
  preflight_path /usr/local/bin/vpnctl
  preflight_path /usr/local/bin/watchdog
  preflight_path /usr/local/bin/watchdogvpn
  preflight_path /usr/local/bin/watchdogvpn-daemon
  preflight_path /usr/local/sbin/vpn_domain_bypass_apply.sh
  preflight_path /usr/local/lib/watchdogvpn
  preflight_path /etc/logrotate.d/myvpn
  preflight_home_path .local/bin/VPN
  preflight_home_path .local/share/watchdogvpn/watchdogvpn
}

preflight_current_systemd_units() {
  local unit
  for unit in "${SYSTEMD_UNITS[@]}"; do
    preflight_path "/etc/systemd/system/$unit"
  done
}

preflight_legacy_product_paths() {
  local unit
  for unit in "${SYSTEMD_LEGACY_UNITS[@]}"; do
    preflight_path "/etc/systemd/system/$unit"
  done
  preflight_path /usr/local/bin/vpn_auth_check
  preflight_path /usr/local/sbin/vpn_rotate.sh
  preflight_path /usr/local/sbin/vpn_set
  preflight_path /usr/local/sbin/vpn_watchdog.sh
  preflight_path /etc/NetworkManager/dispatcher.d/99-vpn-rotate
  preflight_home_path .local/bin/watchdogvpn
}

preflight_preserved_state_paths() {
  preflight_path "${WATCHDOGVPN_DOMAIN_BYPASS_CONF:-/etc/vpn-domain-bypass.conf}"
  preflight_path "${WATCHDOGVPN_ETC_CONFIG_DIR:-/etc/watchdogvpn}"
  preflight_path "${WATCHDOGVPN_SHARED_STATE_DIR:-/var/lib/watchdogvpn}"
  preflight_path /var/log/myvpn
}

preflight_legacy_user_state_paths() {
  preflight_path /etc/adguardvpn.env
  preflight_path /var/lib/vpn-rotate
  preflight_home_path .conky/WatchdogVPN
  preflight_path "${WATCHDOGVPN_LEGACY_CONFIG_DIR:-$HOME/.config/watchdogvpn}"
}

preflight_count_existing() {
  local count=0 path
  while IFS= read -r path; do
    [[ -n "$path" ]] || continue
    preflight_exists "$path" && count=$((count + 1))
  done
  printf '%s\n' "$count"
}

preflight_print_path_plan() {
  local title="$1" action="$2" path any=0
  print_section "$title"
  while IFS= read -r path; do
    [[ -n "$path" ]] || continue
    any=1
    if preflight_exists "$path"; then
      printf '[%s] %s\n' "$action" "$(preflight_display_path "$path")"
    else
      printf '[ABSENT] %s\n' "$(preflight_display_path "$path")"
    fi
  done
  ((any == 1)) || printf '(none)\n'
}

preflight_detect_unsupported_paths() {
  local path
  for path in \
    "$(preflight_path /usr/local/bin/watchdog)" \
    "$(preflight_path /usr/local/bin/watchdogvpn)" \
    "$(preflight_path /usr/local/bin/watchdogvpn-daemon)" \
    "$(preflight_path /usr/local/bin/vpnctl)" \
    "$(preflight_path /usr/local/sbin/vpn_domain_bypass_apply.sh)" \
    "$(preflight_home_path .local/bin/VPN)"
  do
    if [[ -d "$path" ]]; then
      preflight_add_block "expected file path is a directory: $(preflight_display_path "$path")"
    fi
  done

  for path in \
    "$(preflight_path /usr/local/lib/watchdogvpn)" \
    "$(preflight_path "${WATCHDOGVPN_ETC_CONFIG_DIR:-/etc/watchdogvpn}")" \
    "$(preflight_path "${WATCHDOGVPN_SHARED_STATE_DIR:-/var/lib/watchdogvpn}")" \
    "$(preflight_path /var/log/myvpn)"
  do
    if [[ -e "$path" && ! -d "$path" ]]; then
      preflight_add_block "expected directory path is not a directory: $(preflight_display_path "$path")"
    fi
  done
}

preflight_detect_unsupported_backend_config() {
  local config_file active mode
  config_file="$(preflight_path "${WATCHDOGVPN_CONFIG_FILE:-/etc/watchdogvpn/config.toml}")"
  [[ -r "$config_file" ]] || return 0
  if ! declare -F config_value >/dev/null 2>&1; then
    return 0
  fi

  active="$(config_value backend.active "$config_file" 2>/dev/null || true)"
  mode="$(config_value backend.mode "$config_file" 2>/dev/null || true)"
  if [[ -n "$active" && "$active" != "custom-vps" ]]; then
    preflight_add_block "unsupported configured backend in $(preflight_display_path "$config_file"): backend.active=$active"
  fi
  if [[ -n "$mode" && "$mode" != "custom-vps" ]]; then
    preflight_add_block "unsupported configured backend mode in $(preflight_display_path "$config_file"): backend.mode=$mode"
  fi
}

preflight_classify_machine_state() {
  local core_count core_total legacy_count legacy_state_count current_state_dir legacy_config_dir marker
  PREFLIGHT_BLOCKED=0
  PREFLIGHT_BLOCK_REASONS=()
  preflight_detect_unsupported_paths
  preflight_detect_unsupported_backend_config

  core_count="$(preflight_count_existing < <(preflight_current_core_paths))"
  core_total="$(preflight_current_core_paths | wc -l | awk '{print $1}')"
  legacy_count="$(preflight_count_existing < <(preflight_legacy_product_paths))"
  legacy_state_count="$(preflight_count_existing < <(preflight_legacy_user_state_paths))"
  current_state_dir="$(preflight_path "${WATCHDOGVPN_SHARED_STATE_DIR:-/var/lib/watchdogvpn}")"
  legacy_config_dir="$(preflight_path "${WATCHDOGVPN_LEGACY_CONFIG_DIR:-$HOME/.config/watchdogvpn}")"
  marker="$current_state_dir/.migrated"

  if ((PREFLIGHT_BLOCKED == 1)); then
    PREFLIGHT_STATE_CLASS="unsupported"
    return 0
  fi

  if ((core_count > 0 && core_count < core_total)); then
    PREFLIGHT_STATE_CLASS="mixed-inconsistent"
    preflight_add_block "partial current install detected ($core_count/$core_total core paths present)"
    return 0
  fi

  if ((legacy_count > 0)); then
    PREFLIGHT_STATE_CLASS="legacy migration"
    return 0
  fi

  if [[ -d "$legacy_config_dir" ]] && preflight_has_children "$legacy_config_dir" && [[ ! -e "$marker" ]]; then
    PREFLIGHT_STATE_CLASS="legacy migration"
    return 0
  fi

  if ((core_count == core_total)); then
    PREFLIGHT_STATE_CLASS="clean update"
    return 0
  fi

  if ((legacy_state_count > 0)); then
    PREFLIGHT_STATE_CLASS="legacy migration"
    return 0
  fi

  PREFLIGHT_STATE_CLASS="fresh install"
}

preflight_print_block_reasons() {
  local reason
  ((${#PREFLIGHT_BLOCK_REASONS[@]} > 0)) || return 0
  print_section "Blocking reasons"
  for reason in "${PREFLIGHT_BLOCK_REASONS[@]}"; do
    printf '[BLOCK] %s\n' "$reason"
  done
}

preflight_print_repair_contract() {
  print_section "Repair contract"
  case "$PREFLIGHT_STATE_CLASS" in
    "legacy migration")
      printf 'Known WatchdogVPN-owned legacy units and wrappers are safe to remove because they are no longer shipped.\n'
      printf 'Legacy user data is preserved by default; shared-state migration copies with no overwrite and keeps the source.\n'
      ;;
    "mixed-inconsistent")
      printf 'Refusing by default. A partial current install can hide version skew or unknown ownership.\n'
      printf 'Repair requires an explicit documented path before replacing or deleting anything.\n'
      ;;
    unsupported)
      printf 'Refusing by default. One or more product paths or installed config values are unsupported.\n'
      printf 'Repair requires correcting the reported path/config state before install/update continues.\n'
      ;;
    *)
      printf 'No repair action required for this classification.\n'
      ;;
  esac
}

run_mixed_install_preflight() {
  local mode="${1:-install}"
  print_title "WatchdogVPN mixed-install preflight"
  print_field "Mode" "$mode"

  preflight_classify_machine_state
  print_field "Machine state" "$PREFLIGHT_STATE_CLASS"

  preflight_print_path_plan "Runtime files/wrappers to replace or install" "REPLACE" < <(preflight_current_runtime_files)
  preflight_print_path_plan "Systemd units to replace or install" "REPLACE" < <(preflight_current_systemd_units)
  preflight_print_path_plan "State/config/log paths to preserve" "PRESERVE" < <(preflight_preserved_state_paths)
  preflight_print_path_plan "Legacy product artifacts to remove or report" "REMOVE" < <(preflight_legacy_product_paths)
  preflight_print_path_plan "Legacy user data to preserve unless explicitly purged" "PRESERVE" < <(preflight_legacy_user_state_paths)
  preflight_print_repair_contract
  preflight_print_block_reasons

  if [[ "$PREFLIGHT_STATE_CLASS" == "mixed-inconsistent" || "$PREFLIGHT_STATE_CLASS" == "unsupported" ]]; then
    fail "mixed-install preflight blocked"
    return 1
  fi

  ok "mixed-install preflight passed"
}
