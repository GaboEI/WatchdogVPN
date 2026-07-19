#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

VPN_DOMAIN_BYPASS_DISABLED_MARKER="$TMP_DIR/default-domain-bypass-disabled"

# Regression coverage for a real incident (2026-07-07): running ./update.sh
# unconditionally restarted vpn-domain-bypass.timer via
# `systemctl enable --now`, even though it was already active. Because the
# timer has OnActiveSec=30s, that restart reset its schedule and caused it
# to re-apply live ip rule routing state ~30s after a routine update
# finished, colliding with another VPN client (Karing) managing its own
# routes at that moment. See docs/security.md "Domain Bypass Network
# Safety".

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

# --- static: the timer must not be in the unconditional-enable list ---
# (checked against the actual sourced array, not source text - a grep -F
# pattern with embedded newlines matches each line independently (OR
# semantics), not as a literal consecutive sequence, so it cannot reliably
# assert an element's *absence* from a specific array.)

for entry in "${SYSTEMD_ENABLE_UNITS[@]}"; do
  if [[ "$entry" == "vpn-domain-bypass.timer" ]]; then
    echo "FAIL: vpn-domain-bypass.timer must not be unconditionally (re)started by enable_systemd_units" >&2
    exit 1
  fi
done

assert_contains "$ROOT_DIR/lib/systemd.sh" 'enable_vpn_domain_bypass_timer_if_safe' \
  "enable_systemd_units must call the safe domain-bypass enabler"
# (the exact array/unit list in disable_systemd_units's loop is asserted in
# test_watchdog_panic.sh, since watchdog_panic sleep/wake also depend on it)
assert_contains "$ROOT_DIR/lib/systemd.sh" 'vpn-domain-bypass.timer' \
  "disable_systemd_units must still disable vpn-domain-bypass.timer on uninstall"
assert_contains "$ROOT_DIR/uninstall.sh" 'rescue_domain_bypass_routing' \
  "uninstall must run the domain-bypass rescue before removing files"
assert_contains "$ROOT_DIR/lib/runtime.sh" 'vpn_domain_bypass_rescue' \
  "runtime install must ship vpn_domain_bypass_rescue"
assert_contains "$ROOT_DIR/lib/systemd.sh" 'VPN_DOMAIN_BYPASS_DISABLED_MARKER' \
  "domain-bypass enabler must track an explicit manual-disable marker"
assert_contains "$ROOT_DIR/bin/vpn_domain_bypass_rescue" 'DISABLED_MARKER' \
  "rescue script must write the manual-disable marker"

# Regression: the user's own manual incident-recovery script swept the
# entire known ip-rule priority range instead of trusting only the (possibly
# stale/missing, since it lives under /run) state file. The rescue script
# must do the same brute-force sweep as a safety net.
assert_contains "$ROOT_DIR/bin/vpn_domain_bypass_rescue" 'BASE_PRIO' \
  "rescue script must brute-force-sweep the known BASE_PRIO..MAX_RULES range, not just the state file"
assert_contains "$ROOT_DIR/bin/vpn_domain_bypass_rescue" 'Sweeping the full known priority range' \
  "rescue script must brute-force-sweep the known BASE_PRIO..MAX_RULES range, not just the state file"

# Regression: `while run sudo ip rule del ...; do :; done` never terminates
# under INSTALL_DRY_RUN=1, because run()'s dry-run branch always returns 0.
# All repeated-delete call sites must go through delete_ip_rule_repeatedly,
# which explicitly short-circuits to a single printed line in dry-run mode.
assert_not_contains "$ROOT_DIR/bin/vpn_domain_bypass_rescue" 'while run sudo ip' \
  "must not use the 'while run ...; do :; done' idiom - it hangs forever under INSTALL_DRY_RUN=1"
assert_contains "$ROOT_DIR/bin/vpn_domain_bypass_rescue" 'delete_ip_rule_repeatedly' \
  "repeated ip rule deletion must go through delete_ip_rule_repeatedly (dry-run safe)"

# The rescue command runs as the invoking user but the runtime state under
# /run is owned by root. Both reading recorded priorities and clearing the
# file must go through sudo; a bare cat/redirection silently skipped that
# state during a real clean uninstall.
assert_contains "$ROOT_DIR/bin/vpn_domain_bypass_rescue" 'run sudo cat "$STATE_FILE"' \
  "route rescue must read root-owned priority state with sudo"
assert_contains "$ROOT_DIR/bin/vpn_domain_bypass_rescue" 'run sudo truncate -s 0 "$STATE_FILE"' \
  "route rescue must clear root-owned priority state with sudo"

# Regression (empirical): dry-run mode must terminate promptly instead of
# looping forever. This is the actual bug repro from the 2026-07-07 session,
# guarded by `timeout` so a regression here fails the test suite instead of
# hanging it.
if ! timeout 10 env INSTALL_DRY_RUN=1 "$ROOT_DIR/bin/vpn_domain_bypass_rescue" auto >/dev/null 2>&1; then
  echo "FAIL: vpn_domain_bypass_rescue auto must terminate promptly under INSTALL_DRY_RUN=1 (infinite loop regression)" >&2
  exit 1
fi

# Regression (CachyOS field certification, 2026-07-19): strict cleanup
# correctly treats a missing policy-routing table as empty, but the raw
# verification command leaked iproute2's "FIB table does not exist" message
# to stderr. A successful uninstall must not look failed on a clean host.
mock_bin="$TMP_DIR/mock-bin"
mkdir -p "$mock_bin"
printf '%s\n' \
  '#!/usr/bin/env bash' \
  'exit 1' \
  > "$mock_bin/systemctl"
printf '%s\n' \
  '#!/usr/bin/env bash' \
  'if [[ "$*" == "route show table 880" ]]; then' \
  '  echo "Error: ipv4: FIB table does not exist." >&2' \
  '  exit 2' \
  'fi' \
  'exit 0' \
  > "$mock_bin/ip"
chmod 755 "$mock_bin/systemctl" "$mock_bin/ip"
missing_table_stderr="$TMP_DIR/missing-table.stderr"
if ! PATH="$mock_bin:$PATH" INSTALL_DRY_RUN=1 \
  "$ROOT_DIR/bin/vpn_domain_bypass_rescue" auto \
  >"$TMP_DIR/missing-table.stdout" 2>"$missing_table_stderr"; then
  echo "FAIL: a missing policy-routing table must be accepted as already clean" >&2
  exit 1
fi
if [[ -s "$missing_table_stderr" ]]; then
  echo "FAIL: a missing policy-routing table must not leak a false error to stderr" >&2
  cat "$missing_table_stderr" >&2
  exit 1
fi

# --- vpn_domain_bypass_configured(): file content detection ---

empty_conf="$TMP_DIR/empty.conf"
: > "$empty_conf"
if WATCHDOGVPN_DOMAIN_BYPASS_CONF="$empty_conf" vpn_domain_bypass_configured; then
  echo "FAIL: an empty conf must not be considered configured" >&2
  exit 1
fi

comments_conf="$TMP_DIR/comments.conf"
printf '# just a comment\n\n' >"$comments_conf"
if WATCHDOGVPN_DOMAIN_BYPASS_CONF="$comments_conf" vpn_domain_bypass_configured; then
  echo "FAIL: a comments-only conf must not be considered configured" >&2
  exit 1
fi

real_conf="$TMP_DIR/real.conf"
printf '# comment\nexample.com\n' >"$real_conf"
if ! WATCHDOGVPN_DOMAIN_BYPASS_CONF="$real_conf" vpn_domain_bypass_configured; then
  echo "FAIL: a conf with a real domain must be considered configured" >&2
  exit 1
fi

missing_conf="$TMP_DIR/missing.conf"
if WATCHDOGVPN_DOMAIN_BYPASS_CONF="$missing_conf" vpn_domain_bypass_configured; then
  echo "FAIL: a missing conf must not be considered configured" >&2
  exit 1
fi

# --- enable_vpn_domain_bypass_timer_if_safe(): stubbed systemctl behavior ---

STUB_ACTIVE=0
STUB_ENABLE_CALLED=0
systemctl() {
  case "$1" in
    is-active)
      ((STUB_ACTIVE == 1))
      ;;
    enable)
      STUB_ENABLE_CALLED=1
      ;;
    *)
      return 0
      ;;
  esac
}
INSTALL_DRY_RUN=0

# Already active: must NOT call `systemctl enable` (would restart it).
STUB_ACTIVE=1
STUB_ENABLE_CALLED=0
WATCHDOGVPN_DOMAIN_BYPASS_CONF="$real_conf" enable_vpn_domain_bypass_timer_if_safe >/dev/null
if ((STUB_ENABLE_CALLED == 1)); then
  echo "FAIL: must not call systemctl enable when the timer is already active" >&2
  exit 1
fi

# Not active, domains configured: must enable it (first real setup).
STUB_ACTIVE=0
STUB_ENABLE_CALLED=0
WATCHDOGVPN_DOMAIN_BYPASS_CONF="$real_conf" enable_vpn_domain_bypass_timer_if_safe >/dev/null
if ((STUB_ENABLE_CALLED != 1)); then
  echo "FAIL: must call systemctl enable when inactive and domains are configured" >&2
  exit 1
fi

# Not active, no domains configured (fresh install default): must not enable.
STUB_ACTIVE=0
STUB_ENABLE_CALLED=0
WATCHDOGVPN_DOMAIN_BYPASS_CONF="$empty_conf" enable_vpn_domain_bypass_timer_if_safe >/dev/null
if ((STUB_ENABLE_CALLED == 1)); then
  echo "FAIL: must not call systemctl enable when no domains are configured" >&2
  exit 1
fi

# --- manual-disable marker: must be respected, and cleared once the user
#     re-enables the timer themselves ---

marker="$TMP_DIR/domain-bypass-disabled"

# Marker present, not active, domains configured: must NOT re-enable - a
# manual disable after a real routing conflict must survive install/update.
: > "$marker"
STUB_ACTIVE=0
STUB_ENABLE_CALLED=0
VPN_DOMAIN_BYPASS_DISABLED_MARKER="$marker" WATCHDOGVPN_DOMAIN_BYPASS_CONF="$real_conf" \
  enable_vpn_domain_bypass_timer_if_safe >/dev/null
if ((STUB_ENABLE_CALLED == 1)); then
  echo "FAIL: must not re-enable a timer the user manually disabled after a conflict" >&2
  exit 1
fi
if [[ ! -e "$marker" ]]; then
  echo "FAIL: the manual-disable marker must not be removed while the timer stays inactive" >&2
  exit 1
fi

# Marker present, but the user has since manually re-enabled the timer
# themselves (now active): must clear the stale marker instead of leaving it
# around forever.
STUB_ACTIVE=1
STUB_ENABLE_CALLED=0
VPN_DOMAIN_BYPASS_DISABLED_MARKER="$marker" WATCHDOGVPN_DOMAIN_BYPASS_CONF="$real_conf" \
  enable_vpn_domain_bypass_timer_if_safe >/dev/null
if [[ -e "$marker" ]]; then
  echo "FAIL: the manual-disable marker must be cleared once the timer is active again" >&2
  exit 1
fi

printf 'vpn domain bypass safety checks passed\n'
