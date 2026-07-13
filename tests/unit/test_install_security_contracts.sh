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

assert_not_contains() {
  local file="$1" pattern="$2" message="$3"
  if grep -Fq "$pattern" "$file"; then
    printf 'FAIL: %s\n' "$message" >&2
    printf 'unexpected pattern in %s: %s\n' "$file" "$pattern" >&2
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
assert_contains "$ROOT_DIR/lib/runtime.sh" 'PYTHON_RUNTIME_SUPPORT_FILES=(' "runtime install must define support files for cwd-independent doctor/uninstall"
assert_contains "$ROOT_DIR/lib/runtime.sh" 'doctor.sh' "runtime support tree must include doctor.sh"
assert_contains "$ROOT_DIR/lib/runtime.sh" 'uninstall.sh' "runtime support tree must include uninstall.sh"
assert_contains "$ROOT_DIR/lib/runtime.sh" 'PYTHON_RUNTIME_SUPPORT_DIRS=(' "runtime install must define support directories for cwd-independent doctor/uninstall"
assert_contains "$ROOT_DIR/lib/runtime.sh" '  lib' "runtime support tree must include shell libraries"
assert_contains "$ROOT_DIR/lib/runtime.sh" '  bin' "runtime support tree must include helper binaries for doctor/uninstall"
assert_contains "$ROOT_DIR/lib/runtime.sh" '  systemd' "runtime support tree must include systemd unit definitions for doctor"
assert_contains "$ROOT_DIR/lib/runtime.sh" '  examples' "runtime support tree must include config examples for sourced libs"
assert_contains "$ROOT_DIR/lib/runtime.sh" 'sudo chmod 0755 "$dest/$item"' "runtime support scripts must stay executable after permission normalization"
assert_contains "$ROOT_DIR/lib/runtime.sh" 'sudo find "$dest/bin" "$dest/sbin" -type f -exec chmod 0755 {} +' "installed helper scripts must stay executable after permission normalization"
assert_contains "$ROOT_DIR/lib/runtime.sh" '  node_groups' "runtime install must include node_groups package required by daemon imports"
assert_contains "$ROOT_DIR/lib/runtime.sh" '  route_chains' "runtime install must include route_chains package required by backup/config imports"
if grep -Fq 'create_root_dir /var/lib/watchdogvpn 0755' "$ROOT_DIR/lib/runtime.sh"; then
  printf 'FAIL: runtime install must not pre-create /var/lib/watchdogvpn as root-owned state\n' >&2
  exit 1
fi
assert_contains "$ROOT_DIR/lib/runtime.sh" 'install_root_file "$ROOT_DIR/bin/vpn_backend" /usr/local/bin/vpn_backend 0755' "backend helper must be installed as user command"
assert_contains "$ROOT_DIR/lib/runtime.sh" 'install_root_file "$ROOT_DIR/bin/vpn_manual_state" /usr/local/bin/vpn_manual_state 0755' "manual-off state helper must be installed as user command"
assert_contains "$ROOT_DIR/lib/runtime.sh" 'install_python_module_wrapper /usr/local/bin/watchdog cli.main' "v2 watchdog CLI wrapper must be installed with checkout PYTHONPATH"
assert_contains "$ROOT_DIR/lib/runtime.sh" 'install_root_file "$ROOT_DIR/bin/watchdogvpn" /usr/local/bin/watchdogvpn 0755' "watchdogvpn CLI must be installed as user command"
assert_contains "$ROOT_DIR/bin/watchdogvpn" 'watchdogvpn is deprecated; use watchdog' "watchdogvpn must identify itself as a deprecated compatibility alias"
assert_contains "$ROOT_DIR/bin/watchdogvpn" 'exec "$canonical_cli" maintenance "$@"' "legacy-only commands must route through the canonical maintenance namespace"
assert_contains "$ROOT_DIR/bin/watchdogvpn" 'WATCHDOGVPN_MAINTENANCE_INTERNAL' "maintenance backend execution must use an explicit internal boundary"
assert_contains "$ROOT_DIR/cli/main.py" '"maintenance"' "canonical CLI parser must expose the maintenance namespace"
assert_contains "$ROOT_DIR/tui/watchdogvpn/constants.py" 'WATCHDOG_CLI = "/usr/local/bin/watchdog"' "TUI must build product commands with the canonical CLI"
assert_not_contains "$ROOT_DIR/tui/watchdogvpn/actions.py" '/usr/local/bin/watchdogvpn' "TUI actions must not invoke the deprecated alias"
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
assert_contains "$ROOT_DIR/install.sh" "settle_vpn_after_install" "installer must run VPN settle check before final validation"
assert_contains "$ROOT_DIR/install.sh" "smoke_test_watchdogvpn_daemon" "installer must run daemon smoke validation"
assert_contains "$ROOT_DIR/update.sh" "smoke_test_watchdogvpn_daemon" "updater must run daemon smoke validation"
assert_contains "$ROOT_DIR/update.sh" "capture_watchdogvpn_service_state" "updater must capture the live daemon generation before replacing runtime files"
assert_contains "$ROOT_DIR/update.sh" "restart_watchdogvpn_service_after_runtime_update" "updater must restart an active daemon after replacing imported Python modules"
assert_contains "$ROOT_DIR/lib/systemd.sh" 'systemctl restart watchdogvpn.service' "runtime update restart must be an explicit systemd lifecycle action"
assert_contains "$ROOT_DIR/lib/systemd.sh" 'WATCHDOGVPN_DAEMON_PID_BEFORE_UPDATE' "runtime update must verify that the daemon enters a new process generation"
assert_contains "$ROOT_DIR/lib/common.sh" 'print_installer_failure_recovery()' "shared installer failure recovery guidance must exist"
assert_contains "$ROOT_DIR/lib/common.sh" '/etc/watchdogvpn/' "failure recovery guidance must state config preservation"
assert_contains "$ROOT_DIR/lib/common.sh" '/var/lib/watchdogvpn/' "failure recovery guidance must state state preservation"
assert_contains "$ROOT_DIR/lib/common.sh" '${BACKUP_ROOT:-/var/backups/watchdogvpn}' "failure recovery guidance must point at installer backups"
assert_contains "$ROOT_DIR/install.sh" 'trap '\''install_failure_trap "install.sh"'\'' ERR' "installer must print recovery guidance on unexpected failure"
assert_contains "$ROOT_DIR/update.sh" 'trap '\''install_failure_trap "update.sh"'\'' ERR' "updater must print recovery guidance on unexpected failure"
assert_order "$ROOT_DIR/install.sh" "enable_systemd_units" "smoke_test_watchdogvpn_daemon" "installer must smoke test after enabling services"
assert_order "$ROOT_DIR/update.sh" "enable_systemd_units" "smoke_test_watchdogvpn_daemon" "updater must smoke test after enabling services"
assert_order "$ROOT_DIR/update.sh" "capture_watchdogvpn_service_state" "install_runtime_files" "updater must snapshot the old daemon before replacing its imported modules"
assert_order "$ROOT_DIR/update.sh" "restart_watchdogvpn_service_after_runtime_update" "smoke_test_watchdogvpn_daemon" "updater must restart the daemon before accepting the IPC smoke test"
assert_install_order "$ROOT_DIR/install.sh" "settle_vpn_after_install" "post_install_validation" "installer must settle VPN before final validation"
assert_contains "$ROOT_DIR/install.sh" "If the dashboard stays degraded, reboot once" "installer must provide degraded-state recovery guidance"

assert_runtime_order "$ROOT_DIR/uninstall.sh" "rescue_system_dns" "remove_runtime_files" "uninstall must run DNS rescue before removing runtime files"
assert_contains "$ROOT_DIR/uninstall.sh" 'printf '\''/etc/watchdogvpn/\n'\''' "uninstall preservation contract must mention WatchdogVPN config directory"
assert_contains "$ROOT_DIR/uninstall.sh" 'remove_root_path "$WATCHDOGVPN_ETC_CONFIG_DIR"' "purge-config must remove WatchdogVPN config directory"
assert_contains "$ROOT_DIR/uninstall.sh" 'printf '\''[KEEP] config: %s\n'\'' "$WATCHDOGVPN_ETC_CONFIG_DIR"' "uninstall must preserve WatchdogVPN config by default"
assert_not_contains "$ROOT_DIR/lib/config.sh" 'WATCHDOGVPN_CONFIG_DIR:-' "shell config lib must not reuse the Python-side WATCHDOGVPN_CONFIG_DIR env var name (collision risk found in Task 18.4 audit)"
assert_contains "$ROOT_DIR/uninstall.sh" 'remove_root_path /var/lib/watchdogvpn' "purge-state must remove WatchdogVPN runtime state"
assert_contains "$ROOT_DIR/uninstall.sh" 'printf '\''[KEEP] state: /var/lib/watchdogvpn\n'\''' "uninstall must preserve WatchdogVPN runtime state by default"
assert_contains "$ROOT_DIR/uninstall.sh" 'require_delete_confirmation' "uninstall data purge must require DELETE confirmation"
assert_contains "$ROOT_DIR/uninstall.sh" 'fail "data purge requires --confirm-delete DELETE"' "uninstall data purge must fail without DELETE confirmation"

# INV-18.1-001 regression coverage: a prior fix (remove_legacy_adguard_units,
# commit c19394f) was silently deleted without replacement in commit 59f4260.
# These assertions must keep failing loudly if legacy cleanup disappears again.
assert_contains "$ROOT_DIR/lib/systemd.sh" 'SYSTEMD_LEGACY_UNITS=(' "systemd lib must track historical WatchdogVPN unit names separately from the current shipped set"
assert_contains "$ROOT_DIR/lib/systemd.sh" 'adguardvpn.service' "legacy unit list must target the removed AdGuard-era service"
assert_contains "$ROOT_DIR/lib/systemd.sh" 'vpn-watchdog.service' "legacy unit list must target the removed watchdog service"
assert_contains "$ROOT_DIR/lib/systemd.sh" 'vpn-rotate.service' "legacy unit list must target the removed rotate service"
assert_contains "$ROOT_DIR/lib/systemd.sh" 'remove_legacy_systemd_units()' "systemd lib must define a legacy unit cleanup function"
assert_contains "$ROOT_DIR/uninstall.sh" 'remove_legacy_systemd_units' "uninstall must clean up orphaned AdGuard-era systemd units from pre-Phase-2.6 installs"
assert_contains "$ROOT_DIR/uninstall.sh" 'remove_legacy_runtime_files' "uninstall must call the legacy binary/script cleanup function"
assert_contains "$ROOT_DIR/lib/runtime.sh" 'remove_legacy_runtime_files()' "runtime lib must define the legacy binary/script cleanup function (shared by install/update/uninstall)"
assert_contains "$ROOT_DIR/lib/runtime.sh" 'remove_root_path /usr/local/bin/vpn_auth_check' "cleanup must target the orphaned AdGuard-era auth check binary"
assert_contains "$ROOT_DIR/lib/runtime.sh" 'remove_root_path /usr/local/sbin/vpn_rotate.sh' "cleanup must target the orphaned AdGuard-era rotate script"
assert_contains "$ROOT_DIR/lib/runtime.sh" 'remove_root_path /usr/local/sbin/vpn_watchdog.sh' "cleanup must target the orphaned AdGuard-era watchdog script"
assert_contains "$ROOT_DIR/lib/runtime.sh" 'remove_root_path /etc/NetworkManager/dispatcher.d/99-vpn-rotate' "cleanup must target the orphaned AdGuard-era NetworkManager dispatcher"
assert_contains "$ROOT_DIR/uninstall.sh" 'remove_root_path /etc/adguardvpn.env' "purge-config must also remove legacy AdGuard env config"
assert_contains "$ROOT_DIR/uninstall.sh" 'remove_root_path /var/lib/vpn-rotate' "purge-state must also remove legacy rotate state"
assert_runtime_order "$ROOT_DIR/uninstall.sh" "remove_systemd_units" "remove_legacy_systemd_units" "uninstall must remove legacy systemd units alongside current ones"

# Legacy cleanup must also run on every install/update, not only a full
# uninstall, so a machine that never gets uninstalled is not contaminated
# forever (feedback from the maintainer after the initial INV-18.1-001 fix
# only covered uninstall.sh).
assert_contains "$ROOT_DIR/lib/runtime.sh" $'  remove_legacy_systemd_units\n  remove_legacy_runtime_files' "install_runtime_files must call legacy systemd cleanup then legacy file cleanup on every install/update"

assert_contains "$ROOT_DIR/lib/packages.sh" 'printf '\''%s\n'\'' bash python3 curl tar ip systemctl sudo logrotate awk sed openvpn' "OpenVPN normal compatibility requires installer dependency detection"
assert_contains "$ROOT_DIR/distros/ubuntu.sh" "openvpn" "Ubuntu package set must include OpenVPN"
assert_contains "$ROOT_DIR/distros/debian.sh" "openvpn" "Debian package set must include OpenVPN"
assert_contains "$ROOT_DIR/distros/arch.sh" "openvpn" "Arch package set must include OpenVPN"

# The desktop launcher feature was removed entirely (maintainer feedback:
# "nadie la uso realmente"). Guard against it silently coming back.
if [[ -e "$ROOT_DIR/lib/desktop.sh" ]]; then
  printf 'FAIL: lib/desktop.sh must not exist; the desktop launcher feature was removed\n' >&2
  exit 1
fi
if [[ -e "$ROOT_DIR/desktop" ]]; then
  printf 'FAIL: desktop/ must not exist; the desktop launcher feature was removed\n' >&2
  exit 1
fi
for script in install.sh update.sh doctor.sh; do
  if grep -Fqi 'desktop' "$ROOT_DIR/$script"; then
    printf 'FAIL: %s must not reference the removed desktop launcher feature\n' "$script" >&2
    exit 1
  fi
done
assert_contains "$ROOT_DIR/uninstall.sh" 'watchdogvpn.desktop' "uninstall must still clean up a desktop launcher file left by a pre-removal install"

echo "install security contract checks passed"
