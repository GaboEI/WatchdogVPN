#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
UNINSTALLER="$ROOT_DIR/uninstall.sh"
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

contains() {
  local haystack="$1" needle="$2" message="$3"
  if ! grep -Fq -- "$needle" <<<"$haystack"; then
    printf 'FAIL: %s\n' "$message" >&2
    exit 1
  fi
}

not_contains() {
  local haystack="$1" needle="$2" message="$3"
  if grep -Fq -- "$needle" <<<"$haystack"; then
    printf 'FAIL: %s\n' "$message" >&2
    exit 1
  fi
}

# Regression: a full purge previously left the watchdogvpn system user/group,
# and the installing user's membership in it, behind forever with neither
# state documented in the uninstall contract. Removal must be tied to the
# full purge combination (dpkg --purge convention), not to any single flag,
# and a plain uninstall must keep preserving the account like everything else
# in "Preserved unless explicitly purged".
grep -Fq 'remove_watchdogvpn_system_account' "$ROOT_DIR/lib/runtime.sh" || {
  printf 'FAIL: lib/runtime.sh must define remove_watchdogvpn_system_account\n' >&2
  exit 1
}
grep -Fq 'if ((PURGE_CONFIG == 1 && PURGE_LOGS == 1 && PURGE_STATE == 1)); then' "$UNINSTALLER" || {
  printf 'FAIL: uninstall.sh must gate system-account removal on all three purge flags\n' >&2
  exit 1
}
grep -Fq 'watchdogvpn system account and group' "$UNINSTALLER" || {
  printf 'FAIL: uninstall.sh contract must document the system-account removal condition\n' >&2
  exit 1
}

etc_dir="$TMP_DIR/etc/watchdogvpn"
mkdir -p "$etc_dir"

no_purge_output="$(WATCHDOGVPN_ETC_CONFIG_DIR="$etc_dir" "$UNINSTALLER" --dry-run --yes 2>&1)"
contains "$no_purge_output" '[KEEP] system account: watchdogvpn' \
  "a plain uninstall must keep the watchdogvpn system account"
not_contains "$no_purge_output" 'sudo userdel watchdogvpn' \
  "a plain uninstall must not attempt to remove the watchdogvpn user"
not_contains "$no_purge_output" 'sudo groupdel watchdogvpn' \
  "a plain uninstall must not attempt to remove the watchdogvpn group"

partial_purge_output="$(WATCHDOGVPN_ETC_CONFIG_DIR="$etc_dir" "$UNINSTALLER" --dry-run --yes --purge-config --confirm-delete DELETE 2>&1)"
contains "$partial_purge_output" '[KEEP] system account: watchdogvpn' \
  "purging only config must not remove the watchdogvpn system account"
not_contains "$partial_purge_output" 'sudo userdel watchdogvpn' \
  "purging only config must not attempt to remove the watchdogvpn user"

full_purge_output="$(WATCHDOGVPN_ETC_CONFIG_DIR="$etc_dir" "$UNINSTALLER" --dry-run --yes --purge-config --purge-logs --purge-state --confirm-delete DELETE 2>&1)"
contains "$full_purge_output" '[DRY-RUN] sudo userdel watchdogvpn' \
  "a full purge must remove the watchdogvpn system user"
contains "$full_purge_output" '[DRY-RUN] sudo groupdel watchdogvpn' \
  "a full purge must remove the watchdogvpn system group"

bash -n "$UNINSTALLER"
bash -n "$ROOT_DIR/lib/runtime.sh"

printf 'uninstall system-account checks passed\n'
