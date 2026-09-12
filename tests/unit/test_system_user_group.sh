#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

# shellcheck source=../../lib/install_files.sh
. "$ROOT_DIR/lib/install_files.sh"

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

CALLED=()
run_step() {
  CALLED+=("$*")
  return 0
}

# Controllable getent: openSUSE Leap 15.6 sets USERGROUPS_ENAB=no, so useradd
# creates the system user but not the homonymous primary group.
getent() {
  case "$1" in
    passwd)
      if [[ "${FAKE_USER_EXISTS:-0}" == "1" ]]; then
        printf 'watchdogvpn:x:474:100::/home/watchdogvpn:/usr/sbin/nologin\n'
        return 0
      fi
      return 2
      ;;
    group)
      if [[ "${FAKE_GROUP_EXISTS:-0}" == "1" ]]; then
        printf 'watchdogvpn:x:474:\n'
        return 0
      fi
      return 2
      ;;
    *)
      return 2
      ;;
  esac
}

assert_called() {
  local needle="$1" label="$2"
  local call
  for call in "${CALLED[@]}"; do
    if [[ "$call" == *"$needle"* ]]; then
      return 0
    fi
  done
  printf 'FAIL %s: expected a run_step call containing %s\n' "$label" "$needle" >&2
  exit 1
}

assert_not_called() {
  local needle="$1" label="$2"
  local call
  for call in "${CALLED[@]}"; do
    if [[ "$call" == *"$needle"* ]]; then
      printf 'FAIL %s: unexpected run_step call containing %s\n' "$label" "$needle" >&2
      exit 1
    fi
  done
}

# 1. Neither user nor group exists: useradd AND groupadd both run.
FAKE_USER_EXISTS=0
FAKE_GROUP_EXISTS=0
CALLED=()
create_system_user_no_home watchdogvpn
assert_called "useradd --system --no-create-home" "user-created"
assert_called "groupadd --system watchdogvpn" "group-created"

# 2. User exists but the homonymous group is missing (openSUSE case): only
#    groupadd runs.
FAKE_USER_EXISTS=1
FAKE_GROUP_EXISTS=0
CALLED=()
create_system_user_no_home watchdogvpn
assert_not_called "useradd --system" "user-kept"
assert_called "groupadd --system watchdogvpn" "group-created-when-user-exists"

# 3. Both exist: nothing runs.
FAKE_USER_EXISTS=1
FAKE_GROUP_EXISTS=1
CALLED=()
create_system_user_no_home watchdogvpn
assert_not_called "useradd --system" "noop-user"
assert_not_called "groupadd --system" "noop-group"

printf 'system user/group checks passed\n'