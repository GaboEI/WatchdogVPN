#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

assert_contains() {
  local file="$1" pattern="$2" message="$3"
  if ! grep -Fq "$pattern" "$file"; then
    printf 'FAIL: %s\n' "$message" >&2
    printf 'missing pattern in %s: %s\n' "$file" "$pattern" >&2
    exit 1
  fi
}

assert_order() {
  local file="$1" first="$2" second="$3" message="$4" first_line second_line
  first_line="$(grep -nF "$first" "$file" | head -n1 | cut -d: -f1 || true)"
  second_line="$(grep -nF "$second" "$file" | head -n1 | cut -d: -f1 || true)"
  if [[ -z "$first_line" || -z "$second_line" || "$first_line" -ge "$second_line" ]]; then
    printf 'FAIL: %s\n' "$message" >&2
    exit 1
  fi
}

assert_runtime_order() {
  local file="$1" first="$2" second="$3" message="$4" first_line second_line
  first_line="$(awk -v pat="$first" 'seen && $0 == pat {print NR; exit} /^disable_systemd_units$/ {seen=1}' "$file")"
  second_line="$(awk -v pat="$second" 'seen && $0 == pat {print NR; exit} /^disable_systemd_units$/ {seen=1}' "$file")"
  if [[ -z "$first_line" || -z "$second_line" || "$first_line" -ge "$second_line" ]]; then
    printf 'FAIL: %s\n' "$message" >&2
    exit 1
  fi
}

assert_install_order() {
  local file="$1" first="$2" second="$3" message="$4" first_line second_line
  first_line="$(awk -v pat="$first" 'seen && $0 == pat {print NR; exit} /^enable_systemd_units$/ {seen=1}' "$file")"
  second_line="$(awk -v pat="$second" 'seen && $0 == pat {print NR; exit} /^enable_systemd_units$/ {seen=1}' "$file")"
  if [[ -z "$first_line" || -z "$second_line" || "$first_line" -ge "$second_line" ]]; then
    printf 'FAIL: %s\n' "$message" >&2
    exit 1
  fi
}

assert_contains "$ROOT_DIR/lib/runtime.sh" 'install_root_file "$ROOT_DIR/sbin/vpn_set" /usr/local/sbin/vpn_set 0700' "vpn_set must be installed root-only executable"
assert_contains "$ROOT_DIR/lib/runtime.sh" 'install_root_file "$ROOT_DIR/sbin/vpn_rotate.sh" /usr/local/sbin/vpn_rotate.sh 0700' "vpn_rotate.sh must be installed root-only executable"
assert_contains "$ROOT_DIR/lib/runtime.sh" 'install_root_file "$ROOT_DIR/sbin/vpn_watchdog.sh" /usr/local/sbin/vpn_watchdog.sh 0700' "vpn_watchdog.sh must be installed root-only executable"
assert_contains "$ROOT_DIR/lib/runtime.sh" 'install_root_file "$ROOT_DIR/sbin/vpn_domain_bypass_apply.sh" /usr/local/sbin/vpn_domain_bypass_apply.sh 0700' "domain bypass helper must be installed root-only executable"
assert_contains "$ROOT_DIR/lib/runtime.sh" 'install_config_defaults' "runtime install must create persistent config defaults"
assert_contains "$ROOT_DIR/lib/runtime.sh" 'migrate_watchdogvpn_shared_state' "runtime install must migrate shared WatchdogVPN state"
if grep -Fq 'create_root_dir /var/lib/watchdogvpn 0755' "$ROOT_DIR/lib/runtime.sh"; then
  printf 'FAIL: runtime install must not pre-create /var/lib/watchdogvpn as root-owned state\n' >&2
  exit 1
fi
assert_contains "$ROOT_DIR/lib/runtime.sh" 'install_root_file "$ROOT_DIR/bin/vpn_backend" /usr/local/bin/vpn_backend 0755' "backend helper must be installed as user command"
assert_contains "$ROOT_DIR/lib/runtime.sh" 'install_root_file "$ROOT_DIR/bin/vpn_manual_state" /usr/local/bin/vpn_manual_state 0755' "manual-off state helper must be installed as user command"
assert_contains "$ROOT_DIR/lib/runtime.sh" 'install_root_file "$ROOT_DIR/bin/watchdog" /usr/local/bin/watchdog 0755' "v2 watchdog CLI wrapper must be installed as user command"
assert_contains "$ROOT_DIR/lib/runtime.sh" 'install_root_file "$ROOT_DIR/bin/watchdogvpn" /usr/local/bin/watchdogvpn 0755' "watchdogvpn CLI must be installed as user command"
assert_contains "$ROOT_DIR/lib/runtime.sh" 'install_root_file "$ROOT_DIR/bin/watchdogvpn-daemon" /usr/local/bin/watchdogvpn-daemon 0755' "daemon wrapper must be installed as user command"
assert_contains "$ROOT_DIR/lib/runtime.sh" 'create_system_user_no_home watchdogvpn' "runtime install must create watchdogvpn as a system user without a home directory"
assert_contains "$ROOT_DIR/lib/runtime.sh" 'prepare_watchdogvpn_state_directory "$target_dir"' "migration must prepare default daemon state through systemd when needed"
assert_contains "$ROOT_DIR/lib/runtime.sh" 'StateDirectory=watchdogvpn' "state directory preparation must use systemd StateDirectory"
if grep -Fq 'install -d -m 0755 -o "$source_uid" -g "$source_gid" "$target_dir"' "$ROOT_DIR/lib/runtime.sh"; then
  printf 'FAIL: migration must not create /var/lib/watchdogvpn with install -d\n' >&2
  exit 1
fi
assert_contains "$ROOT_DIR/lib/runtime.sh" 'install_user_file "$ROOT_DIR/tui/VPN" "$HOME/.local/bin/VPN" 0755' "TUI launcher must be user executable"
assert_contains "$ROOT_DIR/lib/runtime.sh" 'remove_user_path "$HOME/.local/bin/watchdogvpn"' "legacy TUI package path must be removed so watchdogvpn CLI is not shadowed"
assert_contains "$ROOT_DIR/lib/runtime.sh" 'install_user_dir "$ROOT_DIR/tui/watchdogvpn" "$HOME/.local/share/watchdogvpn/watchdogvpn"' "TUI package must be installed outside PATH"
assert_contains "$ROOT_DIR/uninstall.sh" 'remove_user_path "$HOME/.local/share/watchdogvpn"' "uninstall must remove installed TUI support package"
assert_contains "$ROOT_DIR/uninstall.sh" 'remove_root_path /usr/local/bin/vpn_backend' "uninstall must remove backend helper"
assert_contains "$ROOT_DIR/uninstall.sh" 'remove_root_path /usr/local/bin/watchdogvpn-daemon' "uninstall must remove daemon wrapper"
assert_contains "$ROOT_DIR/lib/desktop.sh" 'desktop folder not detected; application-menu launcher was installed only' "desktop launcher should skip missing desktop folder cleanly"
assert_contains "$ROOT_DIR/lib/desktop.sh" '"$desktop_dir" == "$HOME"' "desktop launcher should reject HOME as Desktop directory"
assert_contains "$ROOT_DIR/install.sh" "settle_vpn_after_install" "installer must run VPN settle check before final validation"
assert_install_order "$ROOT_DIR/install.sh" "settle_vpn_after_install" "post_install_validation" "installer must settle VPN before final validation"
assert_contains "$ROOT_DIR/install.sh" "restarting adguardvpn.service once before final validation" "installer must attempt one recovery restart for degraded VPN state"
assert_contains "$ROOT_DIR/install.sh" "If the dashboard stays degraded, reboot once" "installer must provide degraded-state recovery guidance"

assert_runtime_order "$ROOT_DIR/uninstall.sh" "rescue_system_dns" "remove_runtime_files" "uninstall must run DNS rescue before removing runtime files"
assert_contains "$ROOT_DIR/uninstall.sh" "This script never removes the official AdGuard VPN CLI or account/license state." "uninstall must declare preserved vendor CLI state"
assert_contains "$ROOT_DIR/uninstall.sh" 'printf '\''/etc/watchdogvpn/\n'\''' "uninstall preservation contract must mention WatchdogVPN config directory"
assert_contains "$ROOT_DIR/uninstall.sh" 'remove_root_path "$WATCHDOGVPN_CONFIG_DIR"' "purge-config must remove WatchdogVPN config directory"
assert_contains "$ROOT_DIR/uninstall.sh" 'printf '\''[KEEP] config: %s\n'\'' "$WATCHDOGVPN_CONFIG_DIR"' "uninstall must preserve WatchdogVPN config by default"
assert_contains "$ROOT_DIR/uninstall.sh" 'remove_root_path /var/lib/watchdogvpn' "purge-state must remove WatchdogVPN runtime state"
assert_contains "$ROOT_DIR/uninstall.sh" 'printf '\''[KEEP] state: /var/lib/watchdogvpn\n'\''' "uninstall must preserve WatchdogVPN runtime state by default"

assert_contains "$ROOT_DIR/lib/adguard_vpn_cli.sh" "does not currently pin that vendor script by checksum" "AdGuard VPN CLI external installer risk must be explicit"
assert_contains "$ROOT_DIR/lib/packages.sh" 'printf '\''%s\n'\'' bash python3 curl tar ip systemctl sudo logrotate awk sed openvpn' "OpenVPN normal compatibility requires installer dependency detection"
assert_contains "$ROOT_DIR/distros/ubuntu.sh" "openvpn" "Ubuntu package set must include OpenVPN"
assert_contains "$ROOT_DIR/distros/debian.sh" "openvpn" "Debian package set must include OpenVPN"
assert_contains "$ROOT_DIR/distros/arch.sh" "openvpn" "Arch package set must include OpenVPN"

echo "install security contract checks passed"
