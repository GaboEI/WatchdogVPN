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

# These two combinations never reach getent/userdel/groupdel at all - the gate
# short-circuits before remove_watchdogvpn_system_account is even called - so
# their output is deterministic regardless of whether this machine happens to
# have a real watchdogvpn account (CI runners and freshly-installed dev boxes
# do not; a machine that has run WatchdogVPN's real installer does).
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

# The full-purge combination's actual behavior does depend on whether the
# account exists, so exercise remove_watchdogvpn_system_account() directly
# with getent/userdel/groupdel stubbed - never against this machine's real
# system account state.
(
  # shellcheck source=../../lib/common.sh
  . "$ROOT_DIR/lib/common.sh"
  # shellcheck source=../../lib/install_files.sh
  . "$ROOT_DIR/lib/install_files.sh"
  # shellcheck source=../../lib/runtime.sh
  . "$ROOT_DIR/lib/runtime.sh"

  sudo() { "$@"; }
  userdel_called=0
  groupdel_called=0
  userdel() { userdel_called=1; [[ "$1" == watchdogvpn ]]; }
  groupdel() { groupdel_called=1; [[ "$1" == watchdogvpn ]]; }

  account_present=1
  getent() {
    case "$1" in
      passwd|group) [[ "$2" == watchdogvpn && "$account_present" == 1 ]] ;;
      *) return 1 ;;
    esac
  }

  INSTALL_DRY_RUN=0
  remove_watchdogvpn_system_account >/dev/null
  if [[ "$userdel_called" != 1 ]]; then
    printf 'FAIL: full purge must call userdel when the account exists\n' >&2
    exit 1
  fi
  if [[ "$groupdel_called" != 1 ]]; then
    printf 'FAIL: full purge must call groupdel when the group exists\n' >&2
    exit 1
  fi

  account_present=0
  userdel_called=0
  groupdel_called=0
  # A command-substitution capture ($(...)) forks a subshell, which would
  # make the userdel_called/groupdel_called checks below pass trivially
  # (they'd never see the fork's assignments) - redirect to a file instead
  # so this still runs as a plain command in the current shell.
  absent_output_file="$TMP_DIR/absent-output"
  remove_watchdogvpn_system_account >"$absent_output_file"
  if [[ "$userdel_called" != 0 || "$groupdel_called" != 0 ]]; then
    printf 'FAIL: must not call userdel/groupdel when the account is already absent\n' >&2
    exit 1
  fi
  grep -Fq '[KEEP] absent: watchdogvpn system user' "$absent_output_file" || {
    printf 'FAIL: must report the watchdogvpn user as absent when it does not exist\n' >&2
    exit 1
  }
  grep -Fq '[KEEP] absent: watchdogvpn system group' "$absent_output_file" || {
    printf 'FAIL: must report the watchdogvpn group as absent when it does not exist\n' >&2
    exit 1
  }
)

bash -n "$UNINSTALLER"
bash -n "$ROOT_DIR/lib/runtime.sh"

printf 'uninstall system-account checks passed\n'
