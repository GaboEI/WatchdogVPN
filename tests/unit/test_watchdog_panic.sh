#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

# Coverage for the WatchdogVPN panic button (bin/watchdog_panic): a
# dedicated "sleep everything until I explicitly wake it" state, distinct
# from `watchdog disconnect` (only tears down the active tunnel) and from
# disabling autostart (only affects the next boot). See docs/security.md
# "WatchdogVPN Panic Button".

# shellcheck source=../../lib/install_files.sh
. "$ROOT_DIR/lib/install_files.sh"
# shellcheck source=../../lib/systemd.sh
. "$ROOT_DIR/lib/systemd.sh"

sudo() { "$@"; }

assert_contains() {
  local file="$1" pattern="$2" message="$3"
  if ! grep -Fq "$pattern" "$file"; then
    printf 'FAIL: %s\n' "$message" >&2
    exit 1
  fi
}

assert_not_contains() {
  local file="$1" pattern="$2" message="$3"
  if grep -Fq "$pattern" "$file"; then
    printf 'FAIL: %s\n' "$message" >&2
    exit 1
  fi
}

# --- static wiring ---

bash -n "$ROOT_DIR/bin/watchdog_panic"

assert_contains "$ROOT_DIR/lib/systemd.sh" 'enable_watchdogvpn_service_unless_hibernating' \
  "enable_systemd_units must call the hibernate-aware daemon enabler"
assert_contains "$ROOT_DIR/lib/systemd.sh" 'for unit in "${SYSTEMD_ENABLE_UNITS[@]}" watchdogvpn.service vpn-domain-bypass.timer' \
  "disable_systemd_units must still disable watchdogvpn.service on uninstall regardless of hibernate state"
assert_contains "$ROOT_DIR/lib/systemd.sh" 'remove_kill_switch_rules' \
  "lib/systemd.sh must define kill switch firewall cleanup"
assert_contains "$ROOT_DIR/uninstall.sh" 'remove_kill_switch_rules' \
  "uninstall must remove kill switch firewall rules before removing files"
assert_contains "$ROOT_DIR/uninstall.sh" 'remove_root_path /usr/local/bin/watchdog_panic' \
  "uninstall must remove the panic button script"
assert_contains "$ROOT_DIR/lib/runtime.sh" 'watchdog_panic' \
  "runtime install must ship watchdog_panic"
assert_contains "$ROOT_DIR/lib/runtime.sh" 'WATCHDOGVPN_HIBERNATE_MARKER' \
  "daemon smoke test must be aware of the hibernate marker"
assert_contains "$ROOT_DIR/bin/watchdog_panic" 'HIBERNATE_MARKER' \
  "panic script must write/read the hibernate marker"
assert_contains "$ROOT_DIR/bin/watchdog_panic" 'KILL_SWITCH_NFT_TABLE' \
  "panic script must clean up kill switch firewall state"

# Regression: the user's own manual incident-recovery script had to pkill
# leftover processes directly (systemctl stop alone wasn't enough to
# convince them everything was actually down). The precise, safe equivalent
# is scoping to the dedicated `watchdogvpn` system user (systemd/watchdogvpn.service
# User=/Group=watchdogvpn; drivers/singbox_driver.py never switches users),
# never a name/command-line match that could hit an unrelated sing-box the
# user runs independently.
assert_contains "$ROOT_DIR/bin/watchdog_panic" 'pkill -u watchdogvpn' \
  "sleep must defensively pkill leftover processes scoped to the watchdogvpn system user"
assert_contains "$ROOT_DIR/bin/watchdog_panic" 'id -u watchdogvpn' \
  "the pkill -u watchdogvpn cleanup must guard on the system user actually existing"

# Regression: found live while manually testing this script - `systemctl
# is-enabled`/`is-active` already print "not-found"/"disabled"/"inactive"
# themselves and exit non-zero even for a real, valid disabled/inactive
# unit, so `|| echo "not-found"` double-prints the state line. The
# established correct pattern in this codebase is `|| true`
# (doctor.sh::systemd_active_state/systemd_enabled_state).
assert_not_contains "$ROOT_DIR/bin/watchdog_panic" '|| echo "not-found"' \
  "must not double-print systemctl state; use '|| true' like doctor.sh does"
assert_not_contains "$ROOT_DIR/bin/vpn_domain_bypass_rescue" '|| echo "not-found"' \
  "must not double-print systemctl state; use '|| true' like doctor.sh does"

# --- behavioral: enable_watchdogvpn_service_unless_hibernating() ---

marker="$TMP_DIR/hibernating"
STUB_ENABLE_CALLED=0
systemctl() {
  case "$1" in
    enable)
      STUB_ENABLE_CALLED=1
      ;;
    *)
      return 0
      ;;
  esac
}
INSTALL_DRY_RUN=0

# Marker present: must not enable/start the daemon.
: > "$marker"
STUB_ENABLE_CALLED=0
WATCHDOGVPN_HIBERNATE_MARKER="$marker" enable_watchdogvpn_service_unless_hibernating >/dev/null
if ((STUB_ENABLE_CALLED == 1)); then
  echo "FAIL: must not enable watchdogvpn.service while the hibernate marker is present" >&2
  exit 1
fi

# Marker absent: must enable/start the daemon normally.
rm -f "$marker"
STUB_ENABLE_CALLED=0
WATCHDOGVPN_HIBERNATE_MARKER="$marker" enable_watchdogvpn_service_unless_hibernating >/dev/null
if ((STUB_ENABLE_CALLED != 1)); then
  echo "FAIL: must enable watchdogvpn.service when not hibernating" >&2
  exit 1
fi

# --- behavioral: remove_kill_switch_rules() tolerates a system with none of
#     nft/iptables/ip6tables available (run in a subshell so overriding the
#     `command` builtin cannot affect anything after this check) ---

(
  command() { return 1; }
  INSTALL_DRY_RUN=0
  remove_kill_switch_rules
) || {
  echo "FAIL: remove_kill_switch_rules must not fail when no firewall backend is available" >&2
  exit 1
}

printf 'watchdog panic checks passed\n'
