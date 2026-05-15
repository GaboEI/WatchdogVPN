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
assert_contains "$ROOT_DIR/lib/runtime.sh" 'install_root_file "$ROOT_DIR/bin/watchdogvpn" /usr/local/bin/watchdogvpn 0755' "watchdogvpn CLI must be installed as user command"
assert_contains "$ROOT_DIR/lib/runtime.sh" 'install_user_file "$ROOT_DIR/tui/VPN" "$HOME/.local/bin/VPN" 0755' "TUI launcher must be user executable"
assert_contains "$ROOT_DIR/lib/runtime.sh" 'install_user_dir "$ROOT_DIR/tui/watchdogvpn" "$HOME/.local/bin/watchdogvpn"' "TUI package must be installed with launcher"
assert_contains "$ROOT_DIR/lib/desktop.sh" 'desktop folder not detected; application-menu launcher was installed only' "desktop launcher should skip missing desktop folder cleanly"
assert_contains "$ROOT_DIR/lib/desktop.sh" '"$desktop_dir" == "$HOME"' "desktop launcher should reject HOME as Desktop directory"
assert_contains "$ROOT_DIR/install.sh" "settle_vpn_after_install" "installer must run VPN settle check before final validation"
assert_install_order "$ROOT_DIR/install.sh" "settle_vpn_after_install" "post_install_validation" "installer must settle VPN before final validation"
assert_contains "$ROOT_DIR/install.sh" "restarting adguardvpn.service once before final validation" "installer must attempt one recovery restart for degraded VPN state"
assert_contains "$ROOT_DIR/install.sh" "If the dashboard stays degraded, reboot once" "installer must provide degraded-state recovery guidance"

assert_runtime_order "$ROOT_DIR/uninstall.sh" "rescue_system_dns" "remove_runtime_files" "uninstall must run DNS rescue before removing runtime files"
assert_contains "$ROOT_DIR/uninstall.sh" "This script never removes the official AdGuard VPN CLI or account/license state." "uninstall must declare preserved vendor CLI state"

assert_contains "$ROOT_DIR/lib/adguard_vpn_cli.sh" "does not currently pin that vendor script by checksum" "AdGuard VPN CLI external installer risk must be explicit"
assert_contains "$ROOT_DIR/lib/adguard_home.sh" "does not currently pin that vendor script by checksum" "AdGuard Home external installer risk must be explicit"

echo "install security contract checks passed"
