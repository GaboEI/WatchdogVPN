#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

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
assert_contains "$ROOT_DIR/lib/systemd.sh" 'for unit in "${SYSTEMD_ENABLE_UNITS[@]}" vpn-domain-bypass.timer' \
  "disable_systemd_units must still disable vpn-domain-bypass.timer on uninstall"
assert_contains "$ROOT_DIR/uninstall.sh" 'rescue_domain_bypass_routing' \
  "uninstall must run the domain-bypass rescue before removing files"
assert_contains "$ROOT_DIR/lib/runtime.sh" 'vpn_domain_bypass_rescue' \
  "runtime install must ship vpn_domain_bypass_rescue"
assert_contains "$ROOT_DIR/lib/systemd.sh" 'VPN_DOMAIN_BYPASS_DISABLED_MARKER' \
  "domain-bypass enabler must track an explicit manual-disable marker"
assert_contains "$ROOT_DIR/bin/vpn_domain_bypass_rescue" 'DISABLED_MARKER' \
  "rescue script must write the manual-disable marker"

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
