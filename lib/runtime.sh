#!/usr/bin/env bash
set -euo pipefail

PYTHON_PACKAGE_DIR="${PYTHON_PACKAGE_DIR:-/usr/local/lib/watchdogvpn}"
PYTHON_RUNTIME_PACKAGES=(
  app_policy
  cli
  config
  core
  daemon
  diagnostics
  dns
  drivers
  metrics
  models
  network_context
  node_groups
  parsers
  providers
  route_chains
  rotation
  rules
  terminal_safety
)
PYTHON_RUNTIME_SUPPORT_FILES=(
  doctor.sh
  uninstall.sh
)
PYTHON_RUNTIME_SUPPORT_DIRS=(
  lib
  bin
  sbin
  systemd
  etc
  examples
  distros
  tui
)
PYTHON_RUNTIME_SUPPORT_EXECUTABLES=(
  doctor.sh
  uninstall.sh
  tui/VPN
)

SYSCTL_DEFAULTS_PATH="${WATCHDOGVPN_SYSCTL_DEFAULTS_PATH:-/etc/sysctl.d/99-watchdogvpn.conf}"
SYSCTL_BASELINE_DIR="${WATCHDOGVPN_SYSCTL_BASELINE_DIR:-/var/backups/watchdogvpn/install-baseline/sysctl}"
SYSCTL_BASELINE_MANIFEST="$SYSCTL_BASELINE_DIR/manifest"
SYSCTL_BASELINE_FILE="$SYSCTL_BASELINE_DIR/defaults.before"
SRC_VALID_MARK_ALL_PATH="${WATCHDOGVPN_SRC_VALID_MARK_ALL_PATH:-/proc/sys/net/ipv4/conf/all/src_valid_mark}"
SRC_VALID_MARK_DEFAULT_PATH="${WATCHDOGVPN_SRC_VALID_MARK_DEFAULT_PATH:-/proc/sys/net/ipv4/conf/default/src_valid_mark}"
RP_FILTER_ALL_PATH="${WATCHDOGVPN_RP_FILTER_ALL_PATH:-/proc/sys/net/ipv4/conf/all/rp_filter}"
RP_FILTER_DEFAULT_PATH="${WATCHDOGVPN_RP_FILTER_DEFAULT_PATH:-/proc/sys/net/ipv4/conf/default/rp_filter}"
RP_FILTER_CONF_DIR="${WATCHDOGVPN_RP_FILTER_CONF_DIR:-/proc/sys/net/ipv4/conf}"
SYSCTL_INSTALLED_MARKER_PATH="${WATCHDOGVPN_VERSION_MARKER:-/usr/local/lib/watchdogvpn/installed-version}"

# Historical WatchdogVPN-owned files removed from the shipped set before this
# release (AdGuard-era rotation/watchdog automation, Task 2.6). Kept separate
# from remove_runtime_files()/install_runtime_files() purely so both install
# and update can clean up a machine that installed before their removal, not
# only a full uninstall. See INV-18.1-001 in
# docs/phase-18-task-18-1-legacy-contamination-inventory.md.
remove_legacy_runtime_files() {
  remove_root_path /usr/local/bin/vpn_auth_check
  remove_root_path /usr/local/sbin/vpn_rotate.sh
  remove_root_path /usr/local/sbin/vpn_set
  remove_root_path /usr/local/sbin/vpn_watchdog.sh
  remove_root_path /etc/NetworkManager/dispatcher.d/99-vpn-rotate
}

install_runtime_files() {
  local runtime_root="${WATCHDOGVPN_RUNTIME_CANDIDATE_ROOT:-$ROOT_DIR}"
  if declare -F runtime_transaction_is_active >/dev/null && runtime_transaction_is_active; then
    runtime_transaction_prepare_candidate "$ROOT_DIR"
    runtime_root="$WATCHDOGVPN_RUNTIME_CANDIDATE_ROOT"
  fi
  create_system_user_no_home watchdogvpn
  add_installing_user_to_watchdogvpn_group
  create_root_dir /var/log/myvpn 0755

  create_config_if_missing "$runtime_root/examples/vpn-domain-bypass.conf.example" /etc/vpn-domain-bypass.conf 0644
  install_config_defaults
  install_sysctl_defaults
  migrate_watchdogvpn_shared_state
  repair_watchdogvpn_shared_state_permissions
  prepare_watchdogvpn_private_state
  install_python_package_tree

  # Clean up pre-Phase-2.6 (AdGuard-era) contamination on every install and
  # update, not only on a full uninstall - a machine that never gets
  # uninstalled should not carry orphaned legacy units/scripts forever.
  remove_legacy_systemd_units
  remove_legacy_runtime_files

  install_root_file "$runtime_root/bin/no_vpn" /usr/local/bin/no_vpn 0755
  install_root_file "$runtime_root/bin/vpn_dns_rescue" /usr/local/bin/vpn_dns_rescue 0755
  install_root_file "$runtime_root/bin/vpn_domain_bypass_rescue" /usr/local/bin/vpn_domain_bypass_rescue 0755
  install_root_file "$runtime_root/bin/watchdog_panic" /usr/local/bin/watchdog_panic 0755
  install_root_file "$runtime_root/bin/vpn_rp_filter_boot" /usr/local/bin/vpn_rp_filter_boot 0755
  install_root_file "$runtime_root/bin/vpn_backend" /usr/local/bin/vpn_backend 0755
  install_root_file "$runtime_root/bin/vpn_manual_state" /usr/local/bin/vpn_manual_state 0755
  install_root_file "$runtime_root/bin/vpn_notify" /usr/local/bin/vpn_notify 0755
  install_root_file "$runtime_root/bin/vpn_truth_check" /usr/local/bin/vpn_truth_check 0755
  install_root_file "$runtime_root/bin/vpnctl" /usr/local/bin/vpnctl 0755
  install_python_module_wrapper /usr/local/bin/watchdog cli.main
  install_root_file "$runtime_root/bin/watchdogvpn" /usr/local/bin/watchdogvpn 0755
  install_python_module_wrapper /usr/local/bin/watchdogvpn-daemon daemon.main

  install_root_file "$runtime_root/sbin/vpn_domain_bypass_apply.sh" /usr/local/sbin/vpn_domain_bypass_apply.sh 0700

  install_user_file "$runtime_root/tui/VPN" "$HOME/.local/bin/VPN" 0755
  remove_user_path "$HOME/.local/bin/watchdogvpn"
  install_user_dir "$runtime_root/tui/watchdogvpn" "$HOME/.local/share/watchdogvpn/watchdogvpn"
  install_user_dir "$runtime_root/terminal_safety" "$HOME/.local/share/watchdogvpn/terminal_safety"
  install_root_file "$runtime_root/etc/logrotate.d/myvpn" /etc/logrotate.d/myvpn 0644
  install_root_file \
    "$runtime_root/etc/polkit-1/rules.d/49-watchdogvpn-resolved.rules" \
    /etc/polkit-1/rules.d/49-watchdogvpn-resolved.rules \
    0644
  install_sudoers_secure_path
  install_systemd_units
}

# sudo's own secure_path excludes /usr/local/bin (and /usr/local/sbin) on
# several distros, breaking bare-name "sudo <command>" for every WatchdogVPN
# privileged entry point (watchdog_panic, vpn_domain_bypass_rescue, etc.) -
# confirmed on Rocky Linux 9 (Task 23.6.5b): /etc/sudoers there ships
# "Defaults secure_path = /sbin:/bin:/usr/sbin:/usr/bin". bin/watchdog_panic's
# own internal PATH prepend only helps once sudo has already found and
# started the script; it cannot fix sudo's own lookup of the script itself,
# so a real user typing the documented `sudo watchdog_panic sleep` still hit
# "sudo: watchdog_panic: command not found" even after that earlier fix.
#
# A malformed sudoers.d file can break sudo system-wide, so this validates
# the fragment with `visudo -cf` both before and after installing it, and
# removes the installed copy immediately if it somehow fails the post-install
# check, rather than ever leaving a broken sudoers.d file in place.
install_sudoers_secure_path() {
  local runtime_root="${WATCHDOGVPN_RUNTIME_CANDIDATE_ROOT:-$ROOT_DIR}"
  local src="$runtime_root/etc/sudoers.d/99-watchdogvpn-secure-path"
  local dest="${WATCHDOGVPN_SUDOERS_SECURE_PATH:-/etc/sudoers.d/99-watchdogvpn-secure-path}"
  if [[ "${INSTALL_DRY_RUN:-0}" == "1" ]]; then
    printf '[DRY-RUN] validate and install %s\n' "$dest"
    return 0
  fi
  if ! command -v visudo >/dev/null 2>&1; then
    printf 'WARNING: visudo not found; skipping sudoers secure_path fix (sudo <cmd> may need a full path for privileged WatchdogVPN scripts)\n' >&2
    return 0
  fi
  if ! visudo -cf "$src"; then
    printf 'ERROR: sudoers secure_path fragment failed validation; not installing\n' >&2
    return 1
  fi
  install_root_file "$src" "$dest" 0440
  if ! sudo visudo -cf "$dest"; then
    printf 'ERROR: installed sudoers secure_path fragment failed validation; removing it\n' >&2
    run_step sudo rm -f -- "$dest"
    return 1
  fi
}

# Detects the interface currently carrying the default IPv4 route - the same
# interface whose reverse-path check drivers/amneziawg_driver.py's
# _ensure_rp_filter() later verifies at connect time, using the same
# detection logic and the same virtual-interface exclusion list
# (drivers/singbox_driver.py:VIRTUAL_INTERFACE_PREFIXES) so both sides agree
# on "the" interface. Does not need root: reading the routing table is an
# ordinary operation, unlike writing to /proc/sys.
_detect_default_interface() {
  local ip_tool line part prev="" iface=""
  ip_tool="$(command -v ip)" || return 0
  line="$("$ip_tool" route show default 2>/dev/null | head -n1)"
  [[ -n "$line" ]] || return 0
  for part in $line; do
    if [[ "$prev" == "dev" ]]; then
      iface="$part"
      break
    fi
    prev="$part"
  done
  [[ -n "$iface" ]] || return 0
  case "$iface" in
    lo* | tun* | tap* | wg* | wd* | ppp* | tailscale* | zt* | docker* | br-* | veth* | virbr* | podman*)
      return 0
      ;;
  esac
  printf '%s\n' "$iface"
}

_interface_rp_filter_path() {
  printf '%s/%s/rp_filter\n' "$RP_FILTER_CONF_DIR" "$1"
}

_manifest_default_interface() {
  run_privileged_readonly awk -F= '$1 == "default_interface" {print $2}' "$1"
}

# Records the current default-route interface's *original* rp_filter value in
# the sysctl baseline manifest, but only the first time WatchdogVPN observes
# that particular interface: capturing again after _ensure_default_interface_rp_filter
# has already forced it to 2 would corrupt the baseline with WatchdogVPN's
# own value instead of what was really there before install. If the default
# interface changes on a later update run, the newly-seen interface's current
# value becomes its own fresh baseline - the previous interface's forced
# value is no longer tracked, the same class of limitation already accepted
# for conf.default not reaching interfaces that pre-date it.
_ensure_default_interface_baseline_recorded() {
  local cur_iface recorded_iface cur_value manifest_tmp
  cur_iface="$(_detect_default_interface)"
  [[ -n "$cur_iface" ]] || return 0
  cur_value="$(_read_rp_filter "$(_interface_rp_filter_path "$cur_iface")")" || return 0
  if [[ "${INSTALL_DRY_RUN:-0}" == "1" ]]; then
    printf '[DRY-RUN] record default-interface sysctl baseline: interface=%s rp_filter=%s\n' "$cur_iface" "$cur_value"
    return 0
  fi
  root_path_is_file "$SYSCTL_BASELINE_MANIFEST" || return 0
  recorded_iface="$(_manifest_default_interface "$SYSCTL_BASELINE_MANIFEST")" || return 1
  [[ "$cur_iface" != "$recorded_iface" ]] || return 0
  manifest_tmp="$(mktemp)"
  run_privileged_readonly awk -F= '$1 != "default_interface" && $1 != "default_interface_rp_filter"' \
    "$SYSCTL_BASELINE_MANIFEST" >"$manifest_tmp"
  {
    printf 'default_interface=%s\n' "$cur_iface"
    printf 'default_interface_rp_filter=%s\n' "$cur_value"
  } >>"$manifest_tmp"
  run_step sudo install -m 0600 -o root -g root "$manifest_tmp" "$SYSCTL_BASELINE_MANIFEST"
  rm -f -- "$manifest_tmp"
  printf '[INFO] recorded default-interface sysctl baseline: interface=%s rp_filter=%s\n' "$cur_iface" "$cur_value"
}

# conf.default only templates *newly created* interfaces (see the sysctl.d
# file's own comment) - a physical NIC that already exists at boot is
# typically created by the kernel driver before systemd-sysctl.service ever
# runs, so it never inherits this file's conf.default.rp_filter at all.
# Confirmed live on Rocky Linux 9 (Task 23.6.5b): systemd-sysctl.service
# finished four seconds before NetworkManager even saw the interface, yet a
# full reboot afterward still left it strict. Nudging the currently-detected
# default interface directly, on every install/update run, is what actually
# makes this self-healing for the overwhelmingly common case where the
# default interface does not change between install/update and connect time.
# drivers/amneziawg_driver.py's _ensure_rp_filter() remains the connect-time
# safety net for the remaining case: the default interface changed since the
# last install/update ran.
_ensure_default_interface_rp_filter() {
  local iface
  iface="$(_detect_default_interface)"
  [[ -n "$iface" ]] || return 0
  if [[ "${INSTALL_DRY_RUN:-0}" == "1" ]]; then
    printf '[DRY-RUN] set net.ipv4.conf.%s.rp_filter=2\n' "$iface"
    return 0
  fi
  _write_rp_filter "$(_interface_rp_filter_path "$iface")" "2"
}

# net.ipv4.conf.all.src_valid_mark must be 1 for AmneziaWG/WireGuard-style
# fwmark default-route policy routing to pass return traffic. The daemon
# runs under ProtectKernelTunables=true and cannot set this itself at
# connect time (see drivers/amneziawg_driver.py), so it is applied once
# here, at install/update time, as root, outside the daemon's sandbox.
install_sysctl_defaults() {
  local runtime_root="${WATCHDOGVPN_RUNTIME_CANDIDATE_ROOT:-$ROOT_DIR}"
  capture_sysctl_defaults_baseline
  _ensure_default_interface_baseline_recorded
  install_root_file "$runtime_root/etc/sysctl.d/99-watchdogvpn.conf" "$SYSCTL_DEFAULTS_PATH" 0644
  if [[ "${INSTALL_DRY_RUN:-0}" == "1" ]]; then
    printf '[DRY-RUN] sudo sysctl -p %s\n' "$SYSCTL_DEFAULTS_PATH"
    _ensure_default_interface_rp_filter
    return 0
  fi
  run_step sudo sysctl -q -p "$SYSCTL_DEFAULTS_PATH"
  _ensure_default_interface_rp_filter
}

_read_src_valid_mark() {
  local path="$1" value
  value="$(run_privileged_readonly cat "$path")" || return 1
  [[ "$value" =~ ^[01]$ ]] || return 1
  printf '%s\n' "$value"
}

# rp_filter is a 3-state tunable (0 off / 1 strict / 2 loose), unlike
# src_valid_mark's boolean.
_read_rp_filter() {
  local path="$1" value
  value="$(run_privileged_readonly cat "$path")" || return 1
  [[ "$value" =~ ^[012]$ ]] || return 1
  printf '%s\n' "$value"
}

_validated_sysctl_baseline() {
  local manifest="$1" version origin file_present all_value default_value
  local rp_all_value rp_default_value iface_name iface_rp_value
  version="$(run_privileged_readonly awk -F= '$1 == "version" {print $2}' "$manifest")" || return 1
  origin="$(run_privileged_readonly awk -F= '$1 == "origin" {print $2}' "$manifest")" || return 1
  file_present="$(run_privileged_readonly awk -F= '$1 == "file_present" {print $2}' "$manifest")" || return 1
  all_value="$(run_privileged_readonly awk -F= '$1 == "all_src_valid_mark" {print $2}' "$manifest")" || return 1
  default_value="$(run_privileged_readonly awk -F= '$1 == "default_src_valid_mark" {print $2}' "$manifest")" || return 1
  rp_all_value="$(run_privileged_readonly awk -F= '$1 == "all_rp_filter" {print $2}' "$manifest")" || return 1
  rp_default_value="$(run_privileged_readonly awk -F= '$1 == "default_rp_filter" {print $2}' "$manifest")" || return 1
  # default_interface/default_interface_rp_filter are optional: they were
  # added after some manifests already existed, and a machine with no
  # detectable default route at capture time never gets them at all. Their
  # absence is not a validation failure, just "no interface baseline yet".
  iface_name="$(run_privileged_readonly awk -F= '$1 == "default_interface" {print $2}' "$manifest")" || return 1
  iface_rp_value="$(run_privileged_readonly awk -F= '$1 == "default_interface_rp_filter" {print $2}' "$manifest")" || return 1
  [[ "$version" == "2" ]] || return 1
  [[ "$origin" == "fresh" || "$origin" == "legacy-inferred" || "$origin" == "migrated-v1" ]] || return 1
  [[ "$file_present" =~ ^[01]$ && "$all_value" =~ ^[01]$ && "$default_value" =~ ^[01]$ ]] || return 1
  [[ "$rp_all_value" =~ ^[012]$ && "$rp_default_value" =~ ^[012]$ ]] || return 1
  [[ -z "$iface_rp_value" || "$iface_rp_value" =~ ^[012]$ ]] || return 1
  [[ "$origin" != "legacy-inferred" || "$file_present $all_value $default_value" == "0 0 0" ]] || return 1
  [[ "$file_present" == "0" ]] || root_path_is_file "$SYSCTL_BASELINE_FILE" || return 1
  printf '%s %s %s %s %s %s %s\n' "$file_present" "$all_value" "$default_value" "$rp_all_value" "$rp_default_value" \
    "${iface_name:--}" "${iface_rp_value:--}"
}

# A v1 manifest (from before rp_filter was tracked) has file_present/
# all_src_valid_mark/default_src_valid_mark but no rp_filter fields at all -
# distinct from a v2 manifest simply failing validation for some other
# reason. Only this specific, narrow shape should be treated as "needs
# migration"; anything else stays a hard validation failure.
_sysctl_baseline_is_migratable_v1() {
  local manifest="$1" version file_present all_value default_value has_rp_all has_rp_default
  version="$(run_privileged_readonly awk -F= '$1 == "version" {print $2}' "$manifest")" || return 1
  file_present="$(run_privileged_readonly awk -F= '$1 == "file_present" {print $2}' "$manifest")" || return 1
  all_value="$(run_privileged_readonly awk -F= '$1 == "all_src_valid_mark" {print $2}' "$manifest")" || return 1
  default_value="$(run_privileged_readonly awk -F= '$1 == "default_src_valid_mark" {print $2}' "$manifest")" || return 1
  has_rp_all="$(run_privileged_readonly awk -F= '$1 == "all_rp_filter" {print $2}' "$manifest")" || return 1
  has_rp_default="$(run_privileged_readonly awk -F= '$1 == "default_rp_filter" {print $2}' "$manifest")" || return 1
  [[ "$version" == "1" ]] || return 1
  [[ "$file_present" =~ ^[01]$ && "$all_value" =~ ^[01]$ && "$default_value" =~ ^[01]$ ]] || return 1
  [[ -z "$has_rp_all" && -z "$has_rp_default" ]] || return 1
  return 0
}

capture_sysctl_defaults_baseline() {
  local all_value default_value rp_all_value rp_default_value file_present=0 manifest_tmp origin="fresh"
  if root_path_is_file "$SYSCTL_BASELINE_MANIFEST"; then
    if _validated_sysctl_baseline "$SYSCTL_BASELINE_MANIFEST" >/dev/null; then
      printf '[KEEP] existing sysctl baseline: %s\n' "$SYSCTL_BASELINE_MANIFEST"
      return 0
    fi
    if _sysctl_baseline_is_migratable_v1 "$SYSCTL_BASELINE_MANIFEST"; then
      # rp_filter was never touched by any release that only ever wrote a v1
      # manifest, so the live value right now (before this run applies the
      # product's own etc/sysctl.d/99-watchdogvpn.conf) is still the true,
      # untouched baseline for it - the same reasoning as a fresh capture,
      # just scoped to the fields v1 never recorded.
      file_present="$(run_privileged_readonly awk -F= '$1 == "file_present" {print $2}' "$SYSCTL_BASELINE_MANIFEST")" || return 1
      all_value="$(run_privileged_readonly awk -F= '$1 == "all_src_valid_mark" {print $2}' "$SYSCTL_BASELINE_MANIFEST")" || return 1
      default_value="$(run_privileged_readonly awk -F= '$1 == "default_src_valid_mark" {print $2}' "$SYSCTL_BASELINE_MANIFEST")" || return 1
      rp_all_value="$(_read_rp_filter "$RP_FILTER_ALL_PATH")" || {
        printf 'ERROR: cannot read a valid all.rp_filter baseline\n' >&2
        return 1
      }
      rp_default_value="$(_read_rp_filter "$RP_FILTER_DEFAULT_PATH")" || {
        printf 'ERROR: cannot read a valid default.rp_filter baseline\n' >&2
        return 1
      }
      origin="migrated-v1"
      printf '[MIGRATE] add rp_filter to the existing sysctl baseline (v1 -> v2)\n'
      if [[ "${INSTALL_DRY_RUN:-0}" == "1" ]]; then
        printf '[DRY-RUN] capture sysctl baseline: origin=%s file_present=%s all=%s default=%s rp_all=%s rp_default=%s\n' \
          "$origin" "$file_present" "$all_value" "$default_value" "$rp_all_value" "$rp_default_value"
        return 0
      fi
      manifest_tmp="$(mktemp)"
      {
        printf 'version=2\n'
        printf 'origin=%s\n' "$origin"
        printf 'file_present=%s\n' "$file_present"
        printf 'all_src_valid_mark=%s\n' "$all_value"
        printf 'default_src_valid_mark=%s\n' "$default_value"
        printf 'all_rp_filter=%s\n' "$rp_all_value"
        printf 'default_rp_filter=%s\n' "$rp_default_value"
      } >"$manifest_tmp"
      run_step sudo install -m 0600 -o root -g root "$manifest_tmp" "$SYSCTL_BASELINE_MANIFEST"
      rm -f -- "$manifest_tmp"
      return 0
    fi
    printf 'ERROR: invalid WatchdogVPN sysctl baseline: %s\n' "$SYSCTL_BASELINE_MANIFEST" >&2
    return 1
  fi

  if root_path_is_file "$SYSCTL_INSTALLED_MARKER_PATH"; then
    # Releases predating this baseline journal installed the product-specific
    # file and forced src_valid_mark to 1 without recording what they
    # replaced. The kernel default is 0 for both src_valid_mark booleans, and
    # this same release is also the first to touch rp_filter at all, so its
    # live value right now is still the untouched pre-WatchdogVPN baseline.
    # Recognize that one-time migration by the already-installed product
    # marker; otherwise an update would misclassify WatchdogVPN's own
    # residue as user configuration.
    origin="legacy-inferred"
    all_value=0
    default_value=0
    rp_all_value="$(_read_rp_filter "$RP_FILTER_ALL_PATH")" || {
      printf 'ERROR: cannot read a valid all.rp_filter baseline\n' >&2
      return 1
    }
    rp_default_value="$(_read_rp_filter "$RP_FILTER_DEFAULT_PATH")" || {
      printf 'ERROR: cannot read a valid default.rp_filter baseline\n' >&2
      return 1
    }
    printf '[MIGRATE] infer pre-journal sysctl baseline from installed WatchdogVPN generation\n'
  else
    all_value="$(_read_src_valid_mark "$SRC_VALID_MARK_ALL_PATH")" || {
      printf 'ERROR: cannot read a valid all.src_valid_mark baseline\n' >&2
      return 1
    }
    default_value="$(_read_src_valid_mark "$SRC_VALID_MARK_DEFAULT_PATH")" || {
      printf 'ERROR: cannot read a valid default.src_valid_mark baseline\n' >&2
      return 1
    }
    rp_all_value="$(_read_rp_filter "$RP_FILTER_ALL_PATH")" || {
      printf 'ERROR: cannot read a valid all.rp_filter baseline\n' >&2
      return 1
    }
    rp_default_value="$(_read_rp_filter "$RP_FILTER_DEFAULT_PATH")" || {
      printf 'ERROR: cannot read a valid default.rp_filter baseline\n' >&2
      return 1
    }
    root_path_is_file "$SYSCTL_DEFAULTS_PATH" && file_present=1
  fi
  if [[ "${INSTALL_DRY_RUN:-0}" == "1" ]]; then
    printf '[DRY-RUN] capture sysctl baseline: origin=%s file_present=%s all=%s default=%s rp_all=%s rp_default=%s\n' \
      "$origin" "$file_present" "$all_value" "$default_value" "$rp_all_value" "$rp_default_value"
    return 0
  fi

  run_step sudo install -d -m 0700 -o root -g root "$SYSCTL_BASELINE_DIR"
  if [[ "$file_present" == "1" ]]; then
    run_step sudo cp -a -- "$SYSCTL_DEFAULTS_PATH" "$SYSCTL_BASELINE_FILE"
  else
    run_step sudo rm -f -- "$SYSCTL_BASELINE_FILE"
  fi
  manifest_tmp="$(mktemp)"
  {
    printf 'version=2\n'
    printf 'origin=%s\n' "$origin"
    printf 'file_present=%s\n' "$file_present"
    printf 'all_src_valid_mark=%s\n' "$all_value"
    printf 'default_src_valid_mark=%s\n' "$default_value"
    printf 'all_rp_filter=%s\n' "$rp_all_value"
    printf 'default_rp_filter=%s\n' "$rp_default_value"
  } >"$manifest_tmp"
  run_step sudo install -m 0600 -o root -g root "$manifest_tmp" "$SYSCTL_BASELINE_MANIFEST"
  rm -f -- "$manifest_tmp"
}

_write_src_valid_mark() {
  local path="$1" value="$2"
  printf '%s\n' "$value" | sudo tee "$path" >/dev/null
}

_write_rp_filter() {
  local path="$1" value="$2"
  printf '%s\n' "$value" | sudo tee "$path" >/dev/null
}

restore_sysctl_defaults_baseline() {
  local values file_present all_value default_value rp_all_value rp_default_value observed
  local iface_name iface_rp_value
  if ! root_path_is_file "$SYSCTL_BASELINE_MANIFEST"; then
    if root_path_is_file "$SYSCTL_INSTALLED_MARKER_PATH"; then
      if [[ "${INSTALL_DRY_RUN:-0}" == "1" ]]; then
        printf '[DRY-RUN] migrate the pre-journal installed sysctl baseline before restoration\n'
        return 0
      fi
      capture_sysctl_defaults_baseline || return 1
    fi
  fi
  if root_path_is_file "$SYSCTL_BASELINE_MANIFEST" && _sysctl_baseline_is_migratable_v1 "$SYSCTL_BASELINE_MANIFEST"; then
    if [[ "${INSTALL_DRY_RUN:-0}" == "1" ]]; then
      printf '[DRY-RUN] migrate the v1 sysctl baseline to add rp_filter before restoration\n'
      return 0
    fi
    capture_sysctl_defaults_baseline || return 1
  fi
  if ! root_path_is_file "$SYSCTL_BASELINE_MANIFEST"; then
    if ! root_path_exists "$SYSCTL_DEFAULTS_PATH"; then
      printf '[KEEP] sysctl defaults and baseline are both absent\n'
      return 0
    fi
    if [[ "${INSTALL_DRY_RUN:-0}" == "1" ]]; then
      printf '[DRY-RUN] sysctl baseline is missing; a real uninstall would refuse before mutation\n'
      return 0
    fi
    printf 'ERROR: WatchdogVPN sysctl baseline is missing; refusing an inexact uninstall\n' >&2
    return 1
  fi
  values="$(_validated_sysctl_baseline "$SYSCTL_BASELINE_MANIFEST")" || {
    printf 'ERROR: WatchdogVPN sysctl baseline is invalid\n' >&2
    return 1
  }
  read -r file_present all_value default_value rp_all_value rp_default_value iface_name iface_rp_value <<<"$values"
  [[ "$iface_name" != "-" ]] || iface_name=""
  [[ "$iface_rp_value" != "-" ]] || iface_rp_value=""
  if [[ "${INSTALL_DRY_RUN:-0}" == "1" ]]; then
    printf '[DRY-RUN] restore sysctl baseline: file_present=%s all=%s default=%s rp_all=%s rp_default=%s interface=%s interface_rp=%s\n' \
      "$file_present" "$all_value" "$default_value" "$rp_all_value" "$rp_default_value" \
      "${iface_name:-none}" "${iface_rp_value:-n/a}"
    return 0
  fi

  if [[ "$file_present" == "1" ]]; then
    run_step sudo cp -a -- "$SYSCTL_BASELINE_FILE" "$SYSCTL_DEFAULTS_PATH"
  else
    run_step sudo rm -f -- "$SYSCTL_DEFAULTS_PATH"
  fi
  _write_src_valid_mark "$SRC_VALID_MARK_ALL_PATH" "$all_value"
  _write_src_valid_mark "$SRC_VALID_MARK_DEFAULT_PATH" "$default_value"
  _write_rp_filter "$RP_FILTER_ALL_PATH" "$rp_all_value"
  _write_rp_filter "$RP_FILTER_DEFAULT_PATH" "$rp_default_value"
  observed="$(_read_src_valid_mark "$SRC_VALID_MARK_ALL_PATH")" || return 1
  [[ "$observed" == "$all_value" ]] || return 1
  observed="$(_read_src_valid_mark "$SRC_VALID_MARK_DEFAULT_PATH")" || return 1
  [[ "$observed" == "$default_value" ]] || return 1
  observed="$(_read_rp_filter "$RP_FILTER_ALL_PATH")" || return 1
  [[ "$observed" == "$rp_all_value" ]] || return 1
  observed="$(_read_rp_filter "$RP_FILTER_DEFAULT_PATH")" || return 1
  [[ "$observed" == "$rp_default_value" ]] || return 1
  if [[ -n "$iface_name" ]]; then
    if ip link show "$iface_name" >/dev/null 2>&1; then
      _write_rp_filter "$(_interface_rp_filter_path "$iface_name")" "$iface_rp_value"
      observed="$(_read_rp_filter "$(_interface_rp_filter_path "$iface_name")")" || return 1
      [[ "$observed" == "$iface_rp_value" ]] || return 1
    else
      printf '[SKIP] default-interface sysctl baseline interface no longer exists: %s\n' "$iface_name"
    fi
  fi
  if [[ "$file_present" == "1" ]]; then
    root_path_is_file "$SYSCTL_DEFAULTS_PATH" || return 1
    run_privileged_readonly cmp -s "$SYSCTL_BASELINE_FILE" "$SYSCTL_DEFAULTS_PATH" || return 1
  else
    ! root_path_exists "$SYSCTL_DEFAULTS_PATH" || return 1
  fi
}

install_python_module_wrapper() {
  local dest="$1" module="$2" tmp quoted_root py quoted_py
  py="$(watchdogvpn_python)" || {
    fail "no Python >=3.${WATCHDOGVPN_MIN_PYTHON_MINOR} interpreter available for the runtime launcher"
    return 1
  }
  tmp="$(mktemp)"
  printf -v quoted_root '%q' "$PYTHON_PACKAGE_DIR"
  printf -v quoted_py '%q' "$py"
  {
    printf '#!/usr/bin/env bash\n'
    printf 'set -euo pipefail\n\n'
    printf 'ROOT_DIR=%s\n' "$quoted_root"
    printf 'export PYTHONPATH="$ROOT_DIR${PYTHONPATH:+:$PYTHONPATH}"\n'
    printf 'exec %s -m %s "$@"\n' "$quoted_py" "$module"
  } >"$tmp"
  install_root_file "$tmp" "$dest" 0755
  rm -f "$tmp"
}

install_python_package_tree() {
  local dest="${1:-$PYTHON_PACKAGE_DIR}" package item stage source_root="${WATCHDOGVPN_RUNTIME_CANDIDATE_ROOT:-$ROOT_DIR}"
  if [[ "${INSTALL_DRY_RUN:-0}" == "1" ]]; then
    printf '[DRY-RUN] install Python runtime packages to %s\n' "$dest"
    return 0
  fi
  if declare -F runtime_transaction_is_active >/dev/null && runtime_transaction_is_active; then
    runtime_transaction_checkpoint disk
    stage="$(sudo mktemp -d "$(dirname "$dest")/.${dest##*/}.candidate.XXXXXX")" || return 1
    runtime_transaction_register_cleanup_path "$stage"
    for package in "${PYTHON_RUNTIME_PACKAGES[@]}"; do
      runtime_transaction_checkpoint copy
      run_step sudo cp -a "$source_root/$package" "$stage/"
    done
    for item in "${PYTHON_RUNTIME_SUPPORT_FILES[@]}"; do
      runtime_transaction_checkpoint copy
      run_step sudo cp -a "$source_root/$item" "$stage/"
    done
    for item in "${PYTHON_RUNTIME_SUPPORT_DIRS[@]}"; do
      runtime_transaction_checkpoint copy
      run_step sudo cp -a "$source_root/$item" "$stage/"
    done
    runtime_transaction_checkpoint permission
    run_step sudo chown -R root:root "$stage"
    run_step sudo find "$stage" -type d -exec chmod 0755 {} +
    run_step sudo find "$stage" -type f -exec chmod 0644 {} +
    for item in "${PYTHON_RUNTIME_SUPPORT_EXECUTABLES[@]}"; do
      run_step sudo chmod 0755 "$stage/$item"
    done
    run_step sudo find "$stage/bin" "$stage/sbin" -type f -exec chmod 0755 {} +
    _validate_staged_python_runtime "$stage"
    runtime_transaction_replace_directory_from_stage "$stage" "$dest"
    return 0
  fi
  backup_path "$dest"
  run_step sudo rm -rf -- "$dest"
  run_step sudo install -d -m 0755 -o root -g root "$dest"
  for package in "${PYTHON_RUNTIME_PACKAGES[@]}"; do
    run_step sudo cp -a "$source_root/$package" "$dest/"
  done
  for item in "${PYTHON_RUNTIME_SUPPORT_FILES[@]}"; do
    run_step sudo cp -a "$source_root/$item" "$dest/"
  done
  for item in "${PYTHON_RUNTIME_SUPPORT_DIRS[@]}"; do
    run_step sudo cp -a "$source_root/$item" "$dest/"
  done
  run_step sudo chown -R root:root "$dest"
  run_step sudo find "$dest" -type d -exec chmod 0755 {} +
  run_step sudo find "$dest" -type f -exec chmod 0644 {} +
  for item in "${PYTHON_RUNTIME_SUPPORT_EXECUTABLES[@]}"; do
    run_step sudo chmod 0755 "$dest/$item"
  done
  run_step sudo find "$dest/bin" "$dest/sbin" -type f -exec chmod 0755 {} +
}

_validate_staged_python_runtime() {
  local stage="$1" package item
  for package in "${PYTHON_RUNTIME_PACKAGES[@]}"; do
    [[ -d "$stage/$package" ]] || {
      printf 'ERROR: staged Python runtime is missing package: %s\n' "$package" >&2
      return 1
    }
  done
  for item in "${PYTHON_RUNTIME_SUPPORT_FILES[@]}" "${PYTHON_RUNTIME_SUPPORT_DIRS[@]}"; do
    [[ -e "$stage/$item" ]] || {
      printf 'ERROR: staged Python runtime is missing support path: %s\n' "$item" >&2
      return 1
    }
  done
  "$(watchdogvpn_python)" -m compileall -q "$stage"
}

migrate_watchdogvpn_shared_state() {
  local source_dir="${WATCHDOGVPN_LEGACY_CONFIG_DIR:-$HOME/.config/watchdogvpn}"
  local target_dir="${WATCHDOGVPN_SHARED_STATE_DIR:-/var/lib/watchdogvpn}"
  local marker="$target_dir/.migrated"
  local journal="$target_dir/.migration-in-progress"
  local stage_dir marker_tmp journal_tmp entry_name
  local has_legacy_data=0

  # NOTE: the marker means "the shared state directory is ready for the CLI
  # and daemon to use," not literally "a copy happened." A fresh install with
  # no legacy $HOME/.config/watchdogvpn data must still get the marker once
  # the target directory exists, otherwise config/paths.py::resolve_config_dir()
  # keeps routing the CLI to $HOME/.config/watchdogvpn forever (the daemon
  # always uses the shared dir), so the CLI and daemon silently never share
  # state on any install that never had legacy per-user config. Found during
  # the Phase 18 Task 18.4 shared-state permissions audit.
  if root_path_exists "$marker"; then
    # A crash after marker publication but before journal cleanup is already a
    # completed migration: marker publication only follows target validation.
    if root_path_exists "$journal"; then
      run_step sudo rm -f -- "$journal"
    fi
    printf '[KEEP] WatchdogVPN shared state already migrated: %s\n' "$target_dir"
    return 0
  fi
  if root_path_exists "$journal" \
    && { ! root_path_is_file "$journal" || ! run_privileged_readonly grep -Fxq 'watchdogvpn-state-migration-v1' "$journal"; }; then
    printf 'ERROR: WatchdogVPN migration recovery journal is invalid: %s\n' "$journal" >&2
    return 1
  fi
  if root_path_exists "$target_dir" && ! root_path_is_directory "$target_dir"; then
    printf 'ERROR: WatchdogVPN shared state target is not a directory: %s\n' "$target_dir" >&2
    return 1
  fi
  if [[ -d "$source_dir" ]] \
    && [[ -n "$(find "$source_dir" -mindepth 1 ! -name .migrated -print -quit)" ]]; then
    has_legacy_data=1
  fi
  if ! root_path_is_directory "$target_dir"; then
    prepare_watchdogvpn_state_directory "$target_dir"
  fi
  if ! root_path_is_directory "$target_dir"; then
    printf '[SKIP] WatchdogVPN shared state target is not available yet: %s\n' "$target_dir"
    return 0
  fi
  if root_path_exists "$marker"; then
    printf '[KEEP] WatchdogVPN shared state already migrated: %s\n' "$target_dir"
    return 0
  fi
  if [[ "${INSTALL_DRY_RUN:-0}" == "1" ]]; then
    if ((has_legacy_data == 1)); then
      printf '[DRY-RUN] migrate WatchdogVPN state %s -> %s\n' "$source_dir" "$target_dir"
    else
      printf '[DRY-RUN] mark WatchdogVPN shared state ready (no legacy user state to migrate): %s\n' "$target_dir"
    fi
    return 0
  fi

  if ((has_legacy_data == 0)); then
    printf '[SKIP] no legacy WatchdogVPN user state to migrate; marking shared state ready: %s\n' "$target_dir"
    _publish_watchdogvpn_migration_marker "$marker" || return 1
    repair_watchdogvpn_shared_state_permissions "$target_dir"
    return 0
  fi

  stage_dir="$(sudo mktemp -d "$target_dir/.migration-stage.XXXXXX")" || {
    printf 'ERROR: unable to create WatchdogVPN migration staging directory in %s\n' "$target_dir" >&2
    return 1
  }
  if ! _stage_watchdogvpn_legacy_state "$source_dir" "$stage_dir"; then
    run_step sudo rm -rf -- "$stage_dir"
    return 1
  fi
  if ! _validate_watchdogvpn_migration_tree "$source_dir" "$stage_dir" stage-validate; then
    printf 'ERROR: staged WatchdogVPN legacy state failed content validation\n' >&2
    run_step sudo rm -rf -- "$stage_dir"
    return 1
  fi

  if [[ ! -e "$journal" ]] && ! _watchdogvpn_migration_target_is_publishable "$stage_dir" "$target_dir"; then
    printf 'ERROR: WatchdogVPN shared state has unmarked conflicting entries; refusing to certify migration\n' >&2
    run_step sudo rm -rf -- "$stage_dir"
    return 1
  fi
  if [[ ! -e "$journal" ]]; then
    journal_tmp="$(sudo mktemp "$target_dir/.migration-journal.XXXXXX")" || {
      run_step sudo rm -rf -- "$stage_dir"
      return 1
    }
    if ! printf 'watchdogvpn-state-migration-v1\n' | sudo tee "$journal_tmp" >/dev/null \
      || ! _watchdogvpn_migration_checkpoint journal-publish \
      || ! run_step sudo mv -f -- "$journal_tmp" "$journal"; then
      printf 'ERROR: unable to publish WatchdogVPN migration recovery journal\n' >&2
      run_step sudo rm -f -- "$journal_tmp"
      run_step sudo rm -rf -- "$stage_dir"
      return 1
    fi
  fi

  while IFS= read -r -d '' entry_name; do
    if ! _watchdogvpn_migration_checkpoint "publish:$entry_name"; then
      printf 'ERROR: WatchdogVPN migration interrupted before publishing %s\n' "$entry_name" >&2
      run_step sudo rm -rf -- "$stage_dir"
      return 1
    fi
    # Each staged top-level entry is published with one same-filesystem rename.
    # A recovery rerun leaves an already-published identical entry untouched;
    # any divergent entry is rejected rather than deleted and falsely repaired.
    if [[ -e "$target_dir/$entry_name" || -L "$target_dir/$entry_name" ]]; then
      if ! run_step sudo diff -r --no-dereference -- \
        "$stage_dir/$entry_name" "$target_dir/$entry_name" >/dev/null; then
        printf 'ERROR: journaled WatchdogVPN migration entry diverged: %s\n' "$entry_name" >&2
        run_step sudo rm -rf -- "$stage_dir"
        return 1
      fi
      continue
    fi
    if ! run_step sudo mv -- "$stage_dir/$entry_name" "$target_dir/$entry_name"; then
      printf 'ERROR: unable to atomically publish WatchdogVPN state entry: %s\n' "$entry_name" >&2
      run_step sudo rm -rf -- "$stage_dir"
      return 1
    fi
  done < <(_watchdogvpn_migration_entries "$stage_dir")
  run_step sudo rm -rf -- "$stage_dir"

  if ! _watchdogvpn_migration_checkpoint target-validate \
    || ! _validate_watchdogvpn_migration_tree "$source_dir" "$target_dir" target-content-validate; then
    printf 'ERROR: published WatchdogVPN legacy state failed content validation; recovery journal retained\n' >&2
    return 1
  fi
  if ! _watchdogvpn_migration_checkpoint marker-publish \
    || ! _publish_watchdogvpn_migration_marker "$marker"; then
    printf 'ERROR: WatchdogVPN shared state is complete but not certified; recovery journal retained\n' >&2
    return 1
  fi
  run_step sudo rm -f -- "$journal"
  printf '[MIGRATE] WatchdogVPN shared state: %s -> %s\n' "$source_dir" "$target_dir"
  repair_watchdogvpn_shared_state_permissions "$target_dir"
}


_watchdogvpn_migration_entries() {
  local directory="$1"
  # sudo is required here: this is also called against the staging directory,
  # which is created with `sudo mktemp -d` and is therefore root-owned and
  # unreadable to the invoking user. A plain `find` silently returns zero
  # entries instead of failing, which made both the publishability check and
  # the publish loop above no-op instead of erroring - the publish loop then
  # left the target directory empty, and target-content-validate correctly
  # caught the resulting divergence, but only after silently discarding the
  # staged legacy state.
  run_privileged_readonly find "$directory" -mindepth 1 -maxdepth 1 \
    ! -name .migrated \
    ! -name .migration-in-progress \
    -printf '%f\0' | sort -z
}


_stage_watchdogvpn_legacy_state() {
  local source_dir="$1" stage_dir="$2" entry_name
  while IFS= read -r -d '' entry_name; do
    if ! _watchdogvpn_migration_checkpoint "stage-copy:$entry_name" \
      || ! run_step sudo cp -a -- "$source_dir/$entry_name" "$stage_dir/$entry_name"; then
      printf 'ERROR: unable to stage WatchdogVPN legacy state entry: %s\n' "$entry_name" >&2
      return 1
    fi
  done < <(_watchdogvpn_migration_entries "$source_dir")
}


_validate_watchdogvpn_migration_tree() {
  local source_dir="$1" candidate_dir="$2" checkpoint="$3" entry_name
  if ! _watchdogvpn_migration_checkpoint "$checkpoint"; then
    return 1
  fi
  while IFS= read -r -d '' entry_name; do
    if ! run_step sudo diff -r --no-dereference -- \
      "$source_dir/$entry_name" "$candidate_dir/$entry_name" >/dev/null; then
      return 1
    fi
  done < <(_watchdogvpn_migration_entries "$source_dir")
}


_watchdogvpn_migration_target_is_publishable() {
  local stage_dir="$1" target_dir="$2" entry_name
  while IFS= read -r -d '' entry_name; do
    if [[ -e "$target_dir/$entry_name" || -L "$target_dir/$entry_name" ]]; then
      return 1
    fi
  done < <(_watchdogvpn_migration_entries "$stage_dir")
  return 0
}


_publish_watchdogvpn_migration_marker() {
  local marker="$1" marker_tmp
  marker_tmp="$(sudo mktemp "${marker}.tmp.XXXXXX")" || return 1
  if ! printf 'watchdogvpn-shared-state-ready-v2\n' | sudo tee "$marker_tmp" >/dev/null \
    || ! run_step sudo mv -f -- "$marker_tmp" "$marker"; then
    run_step sudo rm -f -- "$marker_tmp"
    return 1
  fi
}


_watchdogvpn_migration_checkpoint() {
  # Test seam: unit coverage replaces this function to inject interruptions at
  # every staging, validation, publication, and marker boundary.
  return 0
}

prepare_watchdogvpn_state_directory() {
  local target_dir="$1"
  if [[ "$target_dir" != "/var/lib/watchdogvpn" ]]; then
    printf '[SKIP] non-default WatchdogVPN shared state target is not managed by systemd: %s\n' "$target_dir"
    return 0
  fi
  if [[ "${INSTALL_DRY_RUN:-0}" == "1" ]]; then
    printf '[DRY-RUN] ask systemd to create StateDirectory=watchdogvpn\n'
    return 0
  fi
  if ! have_cmd systemd-run; then
    printf 'ERROR: systemd-run is required to prepare StateDirectory=watchdogvpn\n' >&2
    return 1
  fi
  run_step sudo systemd-run \
    --wait \
    --collect \
    --quiet \
    --unit=watchdogvpn-state-directory \
    --property=User=watchdogvpn \
    --property=Group=watchdogvpn \
    --property=StateDirectory=watchdogvpn \
    --property=StateDirectoryMode=2770 \
    /bin/true
}

add_installing_user_to_watchdogvpn_group() {
  local target_user="${SUDO_USER:-${USER:-}}"
  if [[ -z "$target_user" || "$target_user" == "root" ]]; then
    printf '[SKIP] no non-root installing user to add to watchdogvpn group\n'
    return 0
  fi
  if id -nG "$target_user" 2>/dev/null | tr ' ' '\n' | grep -Fxq watchdogvpn; then
    printf '[KEEP] user already in watchdogvpn group: %s\n' "$target_user"
    return 0
  fi
  run_step sudo usermod -a -G watchdogvpn "$target_user"
  warn "added $target_user to watchdogvpn group; open a new login session before using the v2 CLI"
}

remove_watchdogvpn_system_account() {
  # Only called by uninstall.sh when config, logs and state were all purged
  # with explicit --confirm-delete DELETE: a full purge previously left the
  # service account and the installing user's group membership behind
  # forever, with neither state documented in the uninstall contract. A
  # plain (non-purge) uninstall must keep preserving this account, matching
  # every other preserved-unless-purged path.
  if getent passwd watchdogvpn >/dev/null 2>&1; then
    run_step sudo userdel watchdogvpn
  else
    printf '[KEEP] absent: watchdogvpn system user\n'
  fi
  if getent group watchdogvpn >/dev/null 2>&1; then
    run_step sudo groupdel watchdogvpn
  else
    printf '[KEEP] absent: watchdogvpn system group\n'
  fi
}

repair_watchdogvpn_shared_state_permissions() {
  local target_dir="${1:-${WATCHDOGVPN_SHARED_STATE_DIR:-/var/lib/watchdogvpn}}"
  local private_dir="$target_dir/private"
  if [[ "$target_dir" != "/var/lib/watchdogvpn" ]]; then
    printf '[SKIP] non-default WatchdogVPN shared state permissions are caller-managed: %s\n' "$target_dir"
    return 0
  fi
  if [[ ! -d "$target_dir" ]]; then
    printf '[SKIP] WatchdogVPN shared state directory not present: %s\n' "$target_dir"
    return 0
  fi
  run_step sudo chown -R watchdogvpn:watchdogvpn "$target_dir"
  # The normal state is intentionally shared with the desktop user's
  # watchdogvpn group. DNS/FakeIP mappings are browsing metadata, however,
  # and belong in the service-only subtree rather than being widened by this
  # generic shared-state repair.
  run_step sudo find "$target_dir" -path "$private_dir" -prune -o -type d -exec chmod 2770 {} +
  run_step sudo find "$target_dir" -path "$private_dir" -prune -o -type f -exec chmod 0660 {} +
}

prepare_watchdogvpn_private_state() {
  local target_dir="${WATCHDOGVPN_SHARED_STATE_DIR:-/var/lib/watchdogvpn}"
  local private_dir="$target_dir/private"
  local cache_path="$private_dir/singbox-fakeip-cache.db"
  local legacy_cache="$target_dir/singbox-fakeip-cache.db"
  local legacy_owner

  if [[ "$target_dir" != "/var/lib/watchdogvpn" ]]; then
    printf '[SKIP] non-default WatchdogVPN private state is caller-managed: %s\n' "$target_dir"
    return 0
  fi
  if [[ "${INSTALL_DRY_RUN:-0}" == "1" ]]; then
    printf '[DRY-RUN] prepare private WatchdogVPN DNS state: %s\n' "$private_dir"
    return 0
  fi

  run_step sudo install -d -m 0700 -o watchdogvpn -g watchdogvpn "$private_dir"
  # The shared parent is setgid (2770), so mkdir/install can inherit its
  # setgid bit even when passed -m 0700. GNU chmod also preserves setgid on a
  # directory for a plain numeric 0700 mode, so clear the inherited bit with
  # an explicit symbolic operation: this subtree is intentionally
  # service-only, not group-shared state.
  run_step sudo chmod 0700 "$private_dir"
  run_step sudo chmod g-s "$private_dir"
  # The first FakeIP implementation stored this file at the shared-state
  # root. Preserve it only when it is a regular file owned by the dedicated
  # service account; a group-writable legacy path is never trusted as an
  # input to the service-only directory.
  if [[ ! -e "$cache_path" && -f "$legacy_cache" && ! -L "$legacy_cache" ]]; then
    legacy_owner="$(sudo stat -c '%U:%G' "$legacy_cache" 2>/dev/null || true)"
    if [[ "$legacy_owner" == "watchdogvpn:watchdogvpn" ]]; then
      run_step sudo mv -- "$legacy_cache" "$cache_path"
    else
      warn "ignored untrusted legacy FakeIP cache: $legacy_cache"
    fi
  fi
  if [[ -f "$cache_path" && ! -L "$cache_path" ]]; then
    run_step sudo chown watchdogvpn:watchdogvpn "$cache_path"
    run_step sudo chmod 0600 "$cache_path"
  fi
}

watchdog_status_with_refreshed_groups() {
  local socket_path="$1"
  local target_user="${SUDO_USER:-${USER:-}}"
  local target_uid target_gid target_home

  # usermod updates /etc/group, but it cannot change the supplementary groups
  # of the already-running installer process.  Run the read-only IPC probe as
  # the invoking user with a group vector freshly loaded from NSS so a clean
  # first install tests the real post-login access contract.
  if [[ -n "$target_user" && "$target_user" != "root" ]] \
    && getent passwd "$target_user" >/dev/null 2>&1; then
    target_uid="$(id -u "$target_user")"
    target_gid="$(id -g "$target_user")"
    target_home="$(getent passwd "$target_user" | awk -F: 'NR == 1 {print $6}')"
    if [[ "$target_home" != /* ]]; then
      printf 'ERROR: cannot resolve an absolute home directory for IPC smoke user: %s\n' \
        "$target_user" >&2
      return 1
    fi
    sudo setpriv \
      --reuid "$target_uid" \
      --regid "$target_gid" \
      --init-groups \
      -- env HOME="$target_home" USER="$target_user" LOGNAME="$target_user" \
      WATCHDOGVPN_SOCKET_PATH="$socket_path" \
      /usr/local/bin/watchdog status --json
    return
  fi

  WATCHDOGVPN_SOCKET_PATH="$socket_path" /usr/local/bin/watchdog status --json
}

smoke_test_watchdogvpn_daemon() {
  local socket_path="${WATCHDOGVPN_SOCKET_PATH:-/run/watchdogvpn/control.sock}"
  local status_output status_rc

  if [[ "${INSTALL_DRY_RUN:-0}" == "1" ]]; then
    printf '[DRY-RUN] smoke test watchdogvpn.service and daemon IPC status\n'
    return 0
  fi

  if declare -F runtime_transaction_is_active >/dev/null && runtime_transaction_is_active; then
    runtime_transaction_checkpoint smoke
  fi

  if [[ "${ENABLE_VPN_AUTOMATION:-1}" != "1" ]]; then
    printf '[SKIP] daemon smoke test; VPN automation is disabled for this install\n'
    return 0
  fi

  if [[ -e "${WATCHDOGVPN_HIBERNATE_MARKER:-/etc/watchdogvpn/.hibernating}" ]]; then
    printf '[SKIP] daemon smoke test; WatchdogVPN is asleep (run: watchdog_panic wake)\n'
    return 0
  fi

  if ! systemctl is-active --quiet watchdogvpn.service; then
    fail "watchdogvpn.service is not active after install/update"
    printf 'Check: sudo journalctl -u watchdogvpn --no-pager -n 80\n'
    return 1
  fi

  if ! sudo test -S "$socket_path"; then
    fail "daemon IPC socket was not created: $socket_path"
    printf 'Check: sudo systemctl status watchdogvpn --no-pager\n'
    return 1
  fi

  set +e
  status_output="$(watchdog_status_with_refreshed_groups "$socket_path" 2>&1)"
  status_rc=$?
  set -e
  if ((status_rc == 0)); then
    ok "daemon IPC status smoke test passed"
    return 0
  fi

  fail "daemon IPC status smoke test failed"
  printf '%s\n' "$status_output"
  return 1
}

ensure_user_local_bin_path() {
  local path_line='export PATH="$HOME/.local/bin:$PATH"'
  local marker="# WatchdogVPN: user local commands"
  local shell_rc=""

  case "${SHELL:-}" in
    */zsh) shell_rc="$HOME/.zshrc" ;;
    */bash) shell_rc="$HOME/.bashrc" ;;
  esac

  case ":$PATH:" in
    *":$HOME/.local/bin:"*)
      ok "PATH includes ~/.local/bin"
      return 0
      ;;
  esac

  if [[ -z "$shell_rc" ]]; then
    warn "~/.local/bin is not in PATH; run: export PATH=\"\$HOME/.local/bin:\$PATH\""
    return 0
  fi

  if [[ "${INSTALL_DRY_RUN:-0}" == "1" ]]; then
    printf '[DRY-RUN] append ~/.local/bin PATH setup to %s\n' "$shell_rc"
    return 0
  fi

  touch "$shell_rc"
  if grep -Fq "$path_line" "$shell_rc"; then
    ok "PATH setup already present in $shell_rc"
    return 0
  fi

  {
    printf '\n%s\n' "$marker"
    printf '%s\n' "$path_line"
  } >> "$shell_rc"
  PATH_UPDATED=1
  warn "added ~/.local/bin to PATH in $shell_rc; open a new terminal or run: source $shell_rc"
}
