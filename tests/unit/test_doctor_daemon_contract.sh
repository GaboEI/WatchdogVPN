#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
DOCTOR="$ROOT_DIR/doctor.sh"

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

assert_contains "$DOCTOR" 'section "WatchdogVPN Daemon"' "doctor must include daemon diagnostics section"
assert_contains "$DOCTOR" 'section "PATH Entrypoints"' "doctor must include PATH entrypoint diagnostics"
assert_contains "$DOCTOR" 'section "Current Product Systemd Units"' "doctor must report current product systemd units"
assert_contains "$DOCTOR" 'section "Legacy Product Artifacts"' "doctor must report real legacy product artifacts"
assert_contains "$DOCTOR" 'getent passwd watchdogvpn' "doctor must check the dedicated watchdogvpn service user"
assert_contains "$DOCTOR" 'daemon_unit="${WATCHDOGVPN_DAEMON_UNIT:-watchdogvpn.service}"' "doctor must check watchdogvpn.service by default"
assert_contains "$DOCTOR" 'daemon_socket="${WATCHDOGVPN_SOCKET_PATH:-/run/watchdogvpn/control.sock}"' "doctor must check the default daemon IPC socket"
assert_contains "$DOCTOR" 'socket_reachable "$daemon_socket"' "doctor must test IPC socket reachability"
assert_contains "$DOCTOR" 'check_path_entrypoint watchdog /usr/local/bin/watchdog' "doctor must verify watchdog PATH resolution"
assert_contains "$DOCTOR" 'check_path_entrypoint watchdogvpn /usr/local/bin/watchdogvpn' "doctor must verify watchdogvpn PATH resolution"
assert_contains "$DOCTOR" 'check_path_entrypoint watchdogvpn-daemon /usr/local/bin/watchdogvpn-daemon' "doctor must verify daemon wrapper PATH resolution"
assert_contains "$DOCTOR" 'check_path_entrypoint vpnctl /usr/local/bin/vpnctl' "doctor must verify vpnctl PATH resolution"
assert_contains "$DOCTOR" 'PATH conflict for $name: first hit is $first' "doctor must report PATH precedence conflicts"
assert_contains "$DOCTOR" 'recovery: remove or rename the earlier wrapper, or adjust PATH precedence' "doctor must provide PATH conflict recovery hints"
assert_contains "$DOCTOR" 'installed_product_paths=(' "doctor must keep an explicit installed product file list"
assert_contains "$DOCTOR" '/usr/local/bin/no_vpn' "doctor must check the no_vpn installed helper"
assert_contains "$DOCTOR" '. "$ROOT_DIR/lib/doctor_paths.sh"' "doctor must use permission-aware installed-path classification"
assert_contains "$DOCTOR" 'installed product file not verifiable without privilege: $path' "doctor must distinguish a protected installed path from an absent path"
assert_contains "$DOCTOR" 'verification: sudo test -e -- $path' "doctor must provide a non-destructive privileged verification command"
assert_contains "$DOCTOR" 'installed product file missing: $path' "doctor must warn when an existing install is incomplete"
assert_contains "$DOCTOR" 'recovery: run ./install.sh or ./update.sh to refresh the installed runtime' "doctor must provide incomplete-install recovery hints"
assert_contains "$DOCTOR" 'cap_net_bind_service' "doctor must check privileged-port bind capability"
assert_contains "$DOCTOR" 'cap_eff_has_bind_service "$daemon_pid"' "doctor must check active daemon effective capabilities"
assert_contains "$DOCTOR" 'cap_dac_read_search' "doctor must check process-attribution read capability"
assert_contains "$DOCTOR" 'cap_eff_has_process_attribution_caps "$daemon_pid"' "doctor must check active daemon process-attribution capabilities"
assert_contains "$DOCTOR" 'section "Time and NTP"' "doctor must include time/NTP diagnostics section"
assert_contains "$DOCTOR" 'python3 -m diagnostics.time_check' "doctor must run the non-mutating time diagnostic"
assert_contains "$DOCTOR" 'python3 -m diagnostics.capture_mode_check' "doctor must run the side-effect-free capture-mode diagnostic"
assert_contains "$ROOT_DIR/diagnostics/capture_mode_check.py" 'manager.load_readonly()' "doctor capture diagnostics must not create persistent lock files"
assert_contains "$DOCTOR" 'mark_warn "system time/NTP risk: ${time_message:-unknown}"' "doctor must warn on time/NTP risk"
assert_contains "$DOCTOR" 'wrong system time can break TLS and VPN/proxy protocol handshakes' "doctor must explain protocol-connectivity risk"
assert_contains "$DOCTOR" 'mark_ok "daemon port 53 capability configured"' "doctor must report port 53 capability success"
assert_contains "$DOCTOR" 'mark_warn "daemon missing CAP_NET_BIND_SERVICE in systemd capability sets"' "doctor must warn on missing daemon port 53 capability"
assert_contains "$DOCTOR" 'mark_warn "daemon missing CAP_SYS_PTRACE/CAP_DAC_READ_SEARCH for process attribution"' "doctor must warn on missing process-attribution capabilities"
assert_contains "$DOCTOR" 'mark_warn "daemon socket permission denied: $daemon_socket"' "doctor must report socket permission problems"
assert_contains "$DOCTOR" 'recovery: run ./install.sh or ./update.sh to create the service user' "doctor must give service-user recovery hints"
assert_contains "$DOCTOR" 'recovery: enable/start $daemon_unit, or run ./update.sh to refresh the service' "doctor must give daemon-state recovery hints"
assert_contains "$DOCTOR" 'recovery: run ./update.sh to reinstall the current systemd unit' "doctor must give capability recovery hints"
assert_contains "$DOCTOR" 'recovery: start $daemon_unit or run watchdog_panic wake if WatchdogVPN was put asleep' "doctor must give socket-missing recovery hints"
assert_contains "$DOCTOR" 'for unit in "${SYSTEMD_UNITS[@]}"' "doctor must use the shared current systemd unit list"
assert_contains "$DOCTOR" 'for unit in "${SYSTEMD_LEGACY_UNITS[@]}"' "doctor must use the shared legacy systemd unit list"
assert_contains "$DOCTOR" 'legacy systemd unit present: $unit' "doctor must warn on legacy systemd units"
assert_contains "$DOCTOR" 'legacy product artifact present: $path' "doctor must warn on legacy runtime files"
assert_contains "$DOCTOR" 'recovery: run ./update.sh to back up and remove known-dead legacy units' "doctor must give legacy unit recovery hints"
assert_contains "$DOCTOR" 'recovery: run ./update.sh to back up and remove known-dead legacy product files' "doctor must give legacy file recovery hints"
assert_contains "$DOCTOR" 'check_repo_file "systemd/watchdogvpn.service"' "doctor must verify repo daemon unit presence"
assert_contains "$DOCTOR" 'check_repo_file "bin/watchdogvpn-daemon" exec' "doctor must verify repo daemon wrapper presence"
assert_contains "$DOCTOR" '/usr/local/bin/watchdogvpn-daemon' "doctor must detect installed daemon wrapper"
assert_contains "$DOCTOR" '/usr/local/lib/watchdogvpn' "doctor must detect installed Python runtime package tree"
assert_not_contains "$DOCTOR" 'section "Legacy Systemd Units"' "doctor must not label current product timers as legacy units"
assert_not_contains "$DOCTOR" 'systemctl start watchdogvpn' "doctor must not start the daemon"
assert_not_contains "$DOCTOR" 'sudo systemctl' "doctor must remain read-only and non-privileged"
assert_not_contains "$DOCTOR" 'timedatectl set-' "doctor must not change time or NTP settings"
assert_not_contains "$DOCTOR" 'date -s' "doctor must not set the system clock"

# shellcheck source=../../lib/doctor_paths.sh
. "$ROOT_DIR/lib/doctor_paths.sh"

doctor_path_exists_impl="$(declare -f _doctor_path_exists)"
doctor_path_parent_searchable_impl="$(declare -f _doctor_path_parent_searchable)"

assert_path_state() {
  local expected="$1" actual
  actual="$(doctor_path_presence_state /irrelevant-for-mocked-probe)"
  if [[ "$actual" != "$expected" ]]; then
    printf 'FAIL: expected doctor path state %s, got %s\n' "$expected" "$actual" >&2
    exit 1
  fi
}

_doctor_path_exists() { return 0; }
_doctor_path_parent_searchable() { return 0; }
assert_path_state present

_doctor_path_exists() { return 1; }
_doctor_path_parent_searchable() { return 0; }
assert_path_state absent

_doctor_path_exists() { return 1; }
_doctor_path_parent_searchable() { return 1; }
assert_path_state protected

# Exercise the field failure mode against the real filesystem when the test is
# not running as root. Root can traverse a mode-000 directory by capability,
# so the deterministic probes above remain the portable regression contract.
if ((EUID != 0)); then
  doctor_tmp="$(mktemp -d)"
  trap 'chmod 0700 "$doctor_tmp/protected" 2>/dev/null || true; rm -rf -- "$doctor_tmp"' EXIT
  mkdir "$doctor_tmp/protected"
  touch "$doctor_tmp/protected/installed-rule"
  chmod 000 "$doctor_tmp/protected"

  unset -f _doctor_path_exists _doctor_path_parent_searchable
  eval "$doctor_path_exists_impl"
  eval "$doctor_path_parent_searchable_impl"
  if [[ "$(doctor_path_presence_state "$doctor_tmp/protected/installed-rule")" != "protected" ]]; then
    printf 'FAIL: an existing path behind a non-searchable parent was not classified as protected\n' >&2
    exit 1
  fi

  chmod 0700 "$doctor_tmp/protected"
  rm -rf -- "$doctor_tmp"
  trap - EXIT
fi

echo "doctor daemon contract checks passed"
