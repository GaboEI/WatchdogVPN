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

assert_contains "$ROOT_DIR/lib/runtime.sh" 'install_root_file "$ROOT_DIR/sbin/vpn_domain_bypass_apply.sh" /usr/local/sbin/vpn_domain_bypass_apply.sh 0700' "domain bypass helper must be installed root-only executable"
assert_contains "$ROOT_DIR/lib/runtime.sh" 'install_config_defaults' "runtime install must create persistent config defaults"
assert_contains "$ROOT_DIR/lib/runtime.sh" 'migrate_watchdogvpn_shared_state' "runtime install must migrate shared WatchdogVPN state"
assert_contains "$ROOT_DIR/lib/runtime.sh" 'install_python_package_tree' "runtime install must install Python packages for daemon and v2 CLI wrappers"
assert_contains "$ROOT_DIR/lib/runtime.sh" 'PYTHON_PACKAGE_DIR="${PYTHON_PACKAGE_DIR:-/usr/local/lib/watchdogvpn}"' "Python runtime package directory must be outside the user home"
assert_contains "$ROOT_DIR/lib/runtime.sh" '  node_groups' "runtime install must include node_groups package required by daemon imports"
if grep -Fq 'create_root_dir /var/lib/watchdogvpn 0755' "$ROOT_DIR/lib/runtime.sh"; then
  printf 'FAIL: runtime install must not pre-create /var/lib/watchdogvpn as root-owned state\n' >&2
  exit 1
fi
assert_contains "$ROOT_DIR/lib/runtime.sh" 'install_root_file "$ROOT_DIR/bin/vpn_backend" /usr/local/bin/vpn_backend 0755' "backend helper must be installed as user command"
assert_contains "$ROOT_DIR/lib/runtime.sh" 'install_root_file "$ROOT_DIR/bin/vpn_manual_state" /usr/local/bin/vpn_manual_state 0755' "manual-off state helper must be installed as user command"
assert_contains "$ROOT_DIR/lib/runtime.sh" 'install_python_module_wrapper /usr/local/bin/watchdog cli.main' "v2 watchdog CLI wrapper must be installed with checkout PYTHONPATH"
assert_contains "$ROOT_DIR/lib/runtime.sh" 'install_root_file "$ROOT_DIR/bin/watchdogvpn" /usr/local/bin/watchdogvpn 0755' "watchdogvpn CLI must be installed as user command"
assert_contains "$ROOT_DIR/lib/runtime.sh" 'install_python_module_wrapper /usr/local/bin/watchdogvpn-daemon daemon.main' "daemon wrapper must be installed with checkout PYTHONPATH"
assert_contains "$ROOT_DIR/lib/runtime.sh" 'create_system_user_no_home watchdogvpn' "runtime install must create watchdogvpn as a system user without a home directory"
assert_contains "$ROOT_DIR/lib/runtime.sh" 'add_installing_user_to_watchdogvpn_group' "runtime install must grant the desktop CLI user access to shared daemon state"
assert_contains "$ROOT_DIR/lib/runtime.sh" 'usermod -a -G watchdogvpn "$target_user"' "runtime install must add the invoking user to watchdogvpn group"
assert_contains "$ROOT_DIR/lib/runtime.sh" 'prepare_watchdogvpn_state_directory "$target_dir"' "migration must prepare default daemon state through systemd when needed"
assert_contains "$ROOT_DIR/lib/runtime.sh" 'StateDirectory=watchdogvpn' "state directory preparation must use systemd StateDirectory"
assert_contains "$ROOT_DIR/lib/runtime.sh" 'StateDirectoryMode=2770' "state directory preparation must be group-writable and setgid"
assert_contains "$ROOT_DIR/lib/runtime.sh" 'repair_watchdogvpn_shared_state_permissions' "runtime install must normalize shared state permissions after migration"
assert_contains "$ROOT_DIR/lib/runtime.sh" 'find "$target_dir" -type d -exec chmod 2770 {} +' "shared state directories must retain watchdogvpn group inheritance"
assert_contains "$ROOT_DIR/lib/runtime.sh" 'find "$target_dir" -type f -exec chmod 0660 {} +' "shared state files must be readable and writable by the watchdogvpn group"
assert_contains "$ROOT_DIR/lib/runtime.sh" 'smoke_test_watchdogvpn_daemon()' "runtime install must define a daemon smoke test"
assert_contains "$ROOT_DIR/lib/runtime.sh" 'systemctl is-active --quiet watchdogvpn.service' "daemon smoke test must verify the service is active"
assert_contains "$ROOT_DIR/lib/runtime.sh" 'sudo test -S "$socket_path"' "daemon smoke test must verify the IPC socket exists"
assert_contains "$ROOT_DIR/lib/runtime.sh" '/usr/local/bin/watchdog status --json' "daemon smoke test must use a read-only daemon status command"
assert_contains "$ROOT_DIR/lib/runtime.sh" 'Open a new login session after the watchdogvpn group change' "daemon smoke test must distinguish session group refresh from daemon failure"
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
assert_contains "$ROOT_DIR/install.sh" "smoke_test_watchdogvpn_daemon" "installer must run daemon smoke validation"
assert_contains "$ROOT_DIR/update.sh" "smoke_test_watchdogvpn_daemon" "updater must run daemon smoke validation"
assert_order "$ROOT_DIR/install.sh" "enable_systemd_units" "smoke_test_watchdogvpn_daemon" "installer must smoke test after enabling services"
assert_order "$ROOT_DIR/update.sh" "enable_systemd_units" "smoke_test_watchdogvpn_daemon" "updater must smoke test after enabling services"
assert_install_order "$ROOT_DIR/install.sh" "settle_vpn_after_install" "post_install_validation" "installer must settle VPN before final validation"
assert_contains "$ROOT_DIR/install.sh" "If the dashboard stays degraded, reboot once" "installer must provide degraded-state recovery guidance"

assert_runtime_order "$ROOT_DIR/uninstall.sh" "rescue_system_dns" "remove_runtime_files" "uninstall must run DNS rescue before removing runtime files"
assert_contains "$ROOT_DIR/uninstall.sh" 'printf '\''/etc/watchdogvpn/\n'\''' "uninstall preservation contract must mention WatchdogVPN config directory"
assert_contains "$ROOT_DIR/uninstall.sh" 'remove_root_path "$WATCHDOGVPN_CONFIG_DIR"' "purge-config must remove WatchdogVPN config directory"
assert_contains "$ROOT_DIR/uninstall.sh" 'printf '\''[KEEP] config: %s\n'\'' "$WATCHDOGVPN_CONFIG_DIR"' "uninstall must preserve WatchdogVPN config by default"
assert_contains "$ROOT_DIR/uninstall.sh" 'remove_root_path /var/lib/watchdogvpn' "purge-state must remove WatchdogVPN runtime state"
assert_contains "$ROOT_DIR/uninstall.sh" 'printf '\''[KEEP] state: /var/lib/watchdogvpn\n'\''' "uninstall must preserve WatchdogVPN runtime state by default"

assert_contains "$ROOT_DIR/lib/packages.sh" 'printf '\''%s\n'\'' bash python3 curl tar ip systemctl sudo logrotate awk sed openvpn' "OpenVPN normal compatibility requires installer dependency detection"
assert_contains "$ROOT_DIR/distros/ubuntu.sh" "openvpn" "Ubuntu package set must include OpenVPN"
assert_contains "$ROOT_DIR/distros/debian.sh" "openvpn" "Debian package set must include OpenVPN"
assert_contains "$ROOT_DIR/distros/arch.sh" "openvpn" "Arch package set must include OpenVPN"

echo "install security contract checks passed"
