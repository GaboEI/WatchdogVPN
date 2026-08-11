#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
CERTIFICATION_VAGRANTFILE="$ROOT_DIR/tests/vm/distro-certification/Vagrantfile"

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

assert_contains "$ROOT_DIR/lib/runtime.sh" 'install_root_file "$runtime_root/sbin/vpn_domain_bypass_apply.sh" /usr/local/sbin/vpn_domain_bypass_apply.sh 0700' "domain bypass helper must be installed root-only executable"
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
assert_contains "$ROOT_DIR/lib/runtime.sh" '  distros' "runtime support tree must include distro adapters required by installed doctor"
assert_contains "$ROOT_DIR/lib/runtime.sh" '  tui' "runtime support tree must include repository-runtime files checked by installed doctor"
assert_contains "$ROOT_DIR/lib/runtime.sh" 'PYTHON_RUNTIME_SUPPORT_EXECUTABLES=(' "runtime install must declare executable support paths separately from copied content"
assert_contains "$ROOT_DIR/lib/runtime.sh" '  tui/VPN' "installed doctor runtime must preserve the executable TUI launcher"
assert_contains "$ROOT_DIR/lib/runtime.sh" 'sudo chmod 0755 "$dest/$item"' "runtime support scripts must stay executable after permission normalization"
assert_contains "$ROOT_DIR/lib/runtime.sh" 'sudo find "$dest/bin" "$dest/sbin" -type f -exec chmod 0755 {} +' "installed helper scripts must stay executable after permission normalization"
assert_contains "$ROOT_DIR/lib/runtime.sh" '  node_groups' "runtime install must include node_groups package required by daemon imports"
assert_contains "$ROOT_DIR/lib/runtime.sh" '  route_chains' "runtime install must include route_chains package required by backup/config imports"
if grep -Fq 'create_root_dir /var/lib/watchdogvpn 0755' "$ROOT_DIR/lib/runtime.sh"; then
  printf 'FAIL: runtime install must not pre-create /var/lib/watchdogvpn as root-owned state\n' >&2
  exit 1
fi
assert_contains "$ROOT_DIR/lib/runtime.sh" 'install_root_file "$runtime_root/bin/vpn_backend" /usr/local/bin/vpn_backend 0755' "backend helper must be installed as user command"
assert_contains "$ROOT_DIR/lib/runtime.sh" 'install_root_file "$runtime_root/bin/vpn_manual_state" /usr/local/bin/vpn_manual_state 0755' "manual-off state helper must be installed as user command"
assert_contains "$ROOT_DIR/lib/runtime.sh" 'install_python_module_wrapper /usr/local/bin/watchdog cli.main' "v2 watchdog CLI wrapper must be installed with checkout PYTHONPATH"
assert_contains "$ROOT_DIR/lib/runtime.sh" 'install_root_file "$runtime_root/bin/watchdogvpn" /usr/local/bin/watchdogvpn 0755' "watchdogvpn CLI must be installed as user command"
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
assert_contains "$ROOT_DIR/lib/runtime.sh" 'prepare_watchdogvpn_private_state' "runtime install must provision service-only private state after shared-state repair"
assert_contains "$ROOT_DIR/lib/runtime.sh" 'find "$target_dir" -path "$private_dir" -prune -o -type d -exec chmod 2770 {} +' "shared state directories must retain watchdogvpn group inheritance without widening private state"
assert_contains "$ROOT_DIR/lib/runtime.sh" 'find "$target_dir" -path "$private_dir" -prune -o -type f -exec chmod 0660 {} +' "shared state files must remain group-writable without widening private state"
assert_contains "$ROOT_DIR/lib/runtime.sh" 'install -d -m 0700 -o watchdogvpn -g watchdogvpn "$private_dir"' "private state must be service-only"
assert_contains "$ROOT_DIR/lib/runtime.sh" 'sudo chmod 0700 "$private_dir"' "private state must enforce service-only rwx permissions"
assert_contains "$ROOT_DIR/lib/runtime.sh" 'sudo chmod g-s "$private_dir"' "private state must explicitly clear the setgid bit inherited from shared state"
assert_contains "$ROOT_DIR/lib/runtime.sh" 'sudo chmod 0600 "$cache_path"' "FakeIP cache must remain private"
assert_contains "$ROOT_DIR/lib/runtime.sh" 'etc/polkit-1/rules.d/49-watchdogvpn-resolved.rules' "runtime install must deploy the DNS runtime policy"
assert_contains "$ROOT_DIR/etc/polkit-1/rules.d/49-watchdogvpn-resolved.rules" 'action.id === "org.freedesktop.resolve1.flush-caches"' "polkit policy must authorize resolver cache flushing"
assert_not_contains "$ROOT_DIR/etc/polkit-1/rules.d/49-watchdogvpn-resolved.rules" 'org.freedesktop.NetworkManager.settings.modify.system' "polkit policy must not grant global NetworkManager settings modification"
assert_contains "$ROOT_DIR/etc/polkit-1/rules.d/49-watchdogvpn-resolved.rules" 'action.id === "org.freedesktop.systemd1.manage-units"' "polkit policy must authorize only the dedicated DNS restore unit"
assert_contains "$ROOT_DIR/etc/polkit-1/rules.d/49-watchdogvpn-resolved.rules" 'action.lookup("unit") === "watchdogvpn-nm-dns-restore.service"' "polkit policy must bind unit authorization to the DNS restore helper"
assert_contains "$ROOT_DIR/etc/polkit-1/rules.d/49-watchdogvpn-resolved.rules" 'action.lookup("unit") === "watchdogvpn-nm-tun-cleanup.service"' "polkit policy must bind TUN cleanup authorization to the fixed NetworkManager helper"
assert_contains "$ROOT_DIR/etc/polkit-1/rules.d/49-watchdogvpn-resolved.rules" 'action.lookup("verb") === "start"' "polkit policy must not permit stop, restart, or other unit operations"
assert_contains "$ROOT_DIR/lib/runtime.sh" 'prepare_networkmanager_dns_restore_state' "runtime install must create root-only NetworkManager DNS restore state"
assert_contains "$ROOT_DIR/lib/runtime.sh" 'install -d -m 0700 -o root -g root "$state_dir"' "NetworkManager DNS restore state must be root-only"
assert_contains "$ROOT_DIR/lib/runtime.sh" 'chmod g-s "$state_dir"' "NetworkManager DNS restore state must explicitly remove inherited setgid"
assert_contains "$ROOT_DIR/lib/runtime.sh" 'chmod 0700 "$state_dir"' "NetworkManager DNS restore state must clear inherited setgid bits"
assert_contains "$ROOT_DIR/lib/runtime.sh" 'install_python_module_wrapper /usr/local/bin/watchdogvpn-nm-dns-restore dns.networkmanager_restore' "runtime install must deploy the root DNS-only restore helper"
assert_contains "$ROOT_DIR/lib/runtime.sh" 'install_python_module_wrapper /usr/local/bin/watchdogvpn-nm-tun-cleanup drivers.networkmanager_tun_cleanup' "runtime install must deploy the fixed NetworkManager TUN cleanup helper"
assert_contains "$ROOT_DIR/systemd/watchdogvpn-nm-dns-restore.service" 'User=root' "DNS restore unit must execute as root"
assert_contains "$ROOT_DIR/systemd/watchdogvpn-nm-dns-restore.service" 'ReadWritePaths=/var/lib/watchdogvpn/nm-dns-restore' "DNS restore unit must only write its root snapshot directory"
assert_contains "$ROOT_DIR/systemd/watchdogvpn-nm-tun-cleanup.service" 'ExecStart=/usr/local/bin/watchdogvpn-nm-tun-cleanup' "TUN cleanup unit must execute only the fixed no-argument helper"
assert_contains "$ROOT_DIR/etc/polkit-1/rules.d/49-watchdogvpn-resolved.rules" 'subject.user === "watchdogvpn"' "polkit policy must scope authorization to the service account"
assert_contains "$ROOT_DIR/uninstall.sh" '/etc/polkit-1/rules.d/49-watchdogvpn-resolved.rules' "uninstall must remove the resolver cache-flush policy"
assert_contains "$ROOT_DIR/install.sh" 'validate_polkit_runtime_dependency' "installer must validate the resolver authorization runtime"
assert_contains "$ROOT_DIR/update.sh" 'validate_polkit_runtime_dependency' "updater must validate the resolver authorization runtime before replacement"
assert_contains "$ROOT_DIR/distros/arch.sh" 'DISTRO_POLKIT_PACKAGE="polkit"' "Arch-family installs must name the polkit runtime package"
assert_contains "$ROOT_DIR/distros/debian.sh" 'DISTRO_POLKIT_PACKAGE="polkitd"' "Debian-family installs must name the polkit daemon package"
assert_contains "$ROOT_DIR/lib/runtime.sh" 'smoke_test_watchdogvpn_daemon()' "runtime install must define a daemon smoke test"
assert_contains "$ROOT_DIR/lib/runtime.sh" 'systemctl is-active --quiet watchdogvpn.service' "daemon smoke test must verify the service is active"
assert_contains "$ROOT_DIR/lib/runtime.sh" 'sudo test -S "$socket_path"' "daemon smoke test must verify the IPC socket exists"
assert_contains "$ROOT_DIR/lib/runtime.sh" 'watchdog_status_with_refreshed_groups "$socket_path"' "daemon smoke test must refresh the invoking user's group vector"
assert_contains "$ROOT_DIR/lib/runtime.sh" 'sudo setpriv \' "daemon smoke test must use the required privilege transition tool"
assert_contains "$ROOT_DIR/lib/runtime.sh" '      --init-groups \' "daemon smoke test must reload supplementary groups from NSS"
assert_contains "$ROOT_DIR/lib/runtime.sh" 'env HOME="$target_home" USER="$target_user" LOGNAME="$target_user"' "daemon smoke test must not inherit root's identity environment after sudo"
assert_contains "$ROOT_DIR/lib/runtime.sh" '/usr/local/bin/watchdog status --json' "daemon smoke test must use a read-only daemon status command"
assert_not_contains "$ROOT_DIR/lib/runtime.sh" 'daemon is active, but this login session cannot access the IPC socket yet' "daemon smoke test must not accept an unverified IPC connection"
if grep -Fq 'install -d -m 0755 -o "$source_uid" -g "$source_gid" "$target_dir"' "$ROOT_DIR/lib/runtime.sh"; then
  printf 'FAIL: migration must not create /var/lib/watchdogvpn with install -d\n' >&2
  exit 1
fi
assert_contains "$ROOT_DIR/lib/runtime.sh" 'install_user_file "$runtime_root/tui/VPN" "$HOME/.local/bin/VPN" 0755' "TUI launcher must be user executable"
assert_contains "$ROOT_DIR/lib/runtime.sh" 'remove_user_path "$HOME/.local/bin/watchdogvpn"' "legacy TUI package path must be removed so watchdogvpn CLI is not shadowed"
assert_contains "$ROOT_DIR/lib/runtime.sh" 'install_user_dir "$runtime_root/tui/watchdogvpn" "$HOME/.local/share/watchdogvpn/watchdogvpn"' "TUI package must be installed outside PATH"
assert_contains "$ROOT_DIR/lib/runtime.sh" 'install_user_dir "$runtime_root/terminal_safety" "$HOME/.local/share/watchdogvpn/terminal_safety"' "TUI must install the shared terminal-safety package outside PATH"
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
assert_contains "$ROOT_DIR/install.sh" 'trap '\''runtime_transaction_failure_trap "install.sh"'\'' ERR' "installer must roll back and print recovery guidance on unexpected failure"
assert_contains "$ROOT_DIR/update.sh" 'trap '\''runtime_transaction_failure_trap "update.sh"'\'' ERR' "updater must roll back and print recovery guidance on unexpected failure"
assert_order "$ROOT_DIR/install.sh" "enable_systemd_units" "smoke_test_watchdogvpn_daemon" "installer must smoke test after enabling services"
assert_order "$ROOT_DIR/update.sh" "enable_systemd_units" "smoke_test_watchdogvpn_daemon" "updater must smoke test after enabling services"
assert_order "$ROOT_DIR/update.sh" "capture_watchdogvpn_service_state" "install_runtime_files" "updater must snapshot the old daemon before replacing its imported modules"
assert_order "$ROOT_DIR/update.sh" "restart_watchdogvpn_service_after_runtime_update" "smoke_test_watchdogvpn_daemon" "updater must restart the daemon before accepting the IPC smoke test"
assert_install_order "$ROOT_DIR/install.sh" "settle_vpn_after_install" "post_install_validation" "installer must settle VPN before final validation"
assert_contains "$ROOT_DIR/install.sh" "If the dashboard stays degraded, reboot once" "installer must provide degraded-state recovery guidance"

dns_rescue_line="$(grep -nF 'if ! rescue_system_dns; then' "$ROOT_DIR/uninstall.sh" | head -n1 | cut -d: -f1)"
remove_product_line="$(grep -nF 'print_section "Remove product files"' "$ROOT_DIR/uninstall.sh" | head -n1 | cut -d: -f1)"
if [[ -z "$dns_rescue_line" || -z "$remove_product_line" || "$dns_rescue_line" -ge "$remove_product_line" ]]; then
  printf 'FAIL: uninstall must run DNS rescue before removing runtime files\n' >&2
  exit 1
fi
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

assert_contains "$ROOT_DIR/lib/packages.sh" 'openvpn setpriv' "OpenVPN hardening requires installer dependency detection"
assert_contains "$ROOT_DIR/lib/packages.sh" 'nft iptables ip6tables ping pgrep' "security/runtime dependency inventory must include firewall, AWG trigger, and process recovery commands"
assert_contains "$ROOT_DIR/distros/ubuntu.sh" "openvpn" "Ubuntu package set must include OpenVPN"
assert_contains "$ROOT_DIR/distros/debian.sh" "openvpn" "Debian package set must include OpenVPN"
assert_contains "$ROOT_DIR/distros/arch.sh" "openvpn" "Arch package set must include OpenVPN"
assert_contains "$CERTIFICATION_VAGRANTFILE" 'Vagrant.has_plugin?("vagrant-vbguest")' "certification lab must account for an installed vagrant-vbguest plugin"
assert_contains "$CERTIFICATION_VAGRANTFILE" 'config.vbguest.auto_update = false' "certification lab must prevent Guest Additions package mutation before dependency provenance is captured"
assert_not_contains "$CERTIFICATION_VAGRANTFILE" 'config.vbguest.auto_update = true' "certification lab must never pre-provision Guest Additions build dependencies"
assert_contains "$CERTIFICATION_VAGRANTFILE" 'abort "WDVPN_VM_BRIDGE is required; certification VMs are bridge-only and must never use NAT" if bridge.empty?' "certification lab must fail closed when no host bridge is selected"
assert_contains "$CERTIFICATION_VAGRANTFILE" 'abort "VAGRANT_EXPERIMENTAL=none_communicator is required for bridge-only direct SSH"' "certification lab must fail clearly unless Vagrant loads its no-communicator plugin"
assert_contains "$CERTIFICATION_VAGRANTFILE" 'config.vm.communicator = "none"' "certification lab must not retain Vagrant's NAT-dependent SSH communicator"
assert_contains "$CERTIFICATION_VAGRANTFILE" 'id: "ssh"' "certification lab must override Vagrant's reserved SSH forwarded-port id"
assert_contains "$CERTIFICATION_VAGRANTFILE" 'disabled: true' "certification lab must disable Vagrant's implicit SSH NAT redirect"
assert_contains "$CERTIFICATION_VAGRANTFILE" 'vb.customize ["modifyvm", :id, "--nic1", "bridged"]' "certification lab must replace VirtualBox's implicit NAT adapter with a bridge"
assert_contains "$CERTIFICATION_VAGRANTFILE" 'vb.customize ["modifyvm", :id, "--bridgeadapter1", bridge]' "certification lab must attach its primary adapter to the selected bridge"
assert_contains "$CERTIFICATION_VAGRANTFILE" 'vb.customize ["modifyvm", :id, "--nic2", "none"]' "certification lab must disable secondary network adapters"
assert_not_contains "$CERTIFICATION_VAGRANTFILE" 'config.vm.network "public_network"' "certification lab must not let Vagrant add a second adapter behind the primary guest interface"
assert_contains "$CERTIFICATION_VAGRANTFILE" 'config.vm.synced_folder ".", "/vagrant", disabled: true' "bridge-only certification must disable Vagrant's implicit project share"
assert_contains "$CERTIFICATION_VAGRANTFILE" 'config.vm.synced_folder "../../..", "/home/vagrant/WatchdogVPN", disabled: true' "bridge-only certification must disable the historical NAT-era source share"
assert_contains "$ROOT_DIR/tests/vm/distro-certification/inventory.json" '"network": "bridge-only-no-nat"' "certification inventory must declare the permanent no-NAT topology"

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
