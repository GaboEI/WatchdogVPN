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
assert_contains "$DOCTOR" 'getent passwd watchdogvpn' "doctor must check the dedicated watchdogvpn service user"
assert_contains "$DOCTOR" 'daemon_unit="${WATCHDOGVPN_DAEMON_UNIT:-watchdogvpn.service}"' "doctor must check watchdogvpn.service by default"
assert_contains "$DOCTOR" 'daemon_socket="${WATCHDOGVPN_SOCKET_PATH:-/run/watchdogvpn/control.sock}"' "doctor must check the default daemon IPC socket"
assert_contains "$DOCTOR" 'socket_reachable "$daemon_socket"' "doctor must test IPC socket reachability"
assert_contains "$DOCTOR" 'cap_net_bind_service' "doctor must check privileged-port bind capability"
assert_contains "$DOCTOR" 'cap_eff_has_bind_service "$daemon_pid"' "doctor must check active daemon effective capabilities"
assert_contains "$DOCTOR" 'cap_dac_read_search' "doctor must check process-attribution read capability"
assert_contains "$DOCTOR" 'cap_eff_has_process_attribution_caps "$daemon_pid"' "doctor must check active daemon process-attribution capabilities"
assert_contains "$DOCTOR" 'section "Time and NTP"' "doctor must include time/NTP diagnostics section"
assert_contains "$DOCTOR" 'python3 -m diagnostics.time_check' "doctor must run the non-mutating time diagnostic"
assert_contains "$DOCTOR" 'mark_warn "system time/NTP risk: ${time_message:-unknown}"' "doctor must warn on time/NTP risk"
assert_contains "$DOCTOR" 'wrong system time can break TLS and VPN/proxy protocol handshakes' "doctor must explain protocol-connectivity risk"
assert_contains "$DOCTOR" 'mark_ok "daemon port 53 capability configured"' "doctor must report port 53 capability success"
assert_contains "$DOCTOR" 'mark_warn "daemon missing CAP_NET_BIND_SERVICE in systemd capability sets"' "doctor must warn on missing daemon port 53 capability"
assert_contains "$DOCTOR" 'mark_warn "daemon missing CAP_SYS_PTRACE/CAP_DAC_READ_SEARCH for process attribution"' "doctor must warn on missing process-attribution capabilities"
assert_contains "$DOCTOR" 'mark_warn "daemon socket permission denied: $daemon_socket"' "doctor must report socket permission problems"
assert_contains "$DOCTOR" 'check_repo_file "systemd/watchdogvpn.service"' "doctor must verify repo daemon unit presence"
assert_contains "$DOCTOR" 'check_repo_file "bin/watchdogvpn-daemon" exec' "doctor must verify repo daemon wrapper presence"
assert_contains "$DOCTOR" '/usr/local/bin/watchdogvpn-daemon' "doctor must detect installed daemon wrapper"
assert_contains "$DOCTOR" '/usr/local/lib/watchdogvpn' "doctor must detect installed Python runtime package tree"
assert_not_contains "$DOCTOR" 'systemctl start watchdogvpn' "doctor must not start the daemon"
assert_not_contains "$DOCTOR" 'sudo systemctl' "doctor must remain read-only and non-privileged"
assert_not_contains "$DOCTOR" 'timedatectl set-' "doctor must not change time or NTP settings"
assert_not_contains "$DOCTOR" 'date -s' "doctor must not set the system clock"

echo "doctor daemon contract checks passed"
