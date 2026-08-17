#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

# shellcheck source=../../lib/common.sh
. "$ROOT_DIR/lib/common.sh"
# shellcheck source=../../lib/distro.sh
. "$ROOT_DIR/lib/distro.sh"

WATCHDOGVPN_EXPERIMENTAL_OVERRIDE_MARKER="$TMP_DIR/.experimental-distro-override"

assert_eq() {
  local expected="$1" actual="$2" label="$3"
  if [[ "$expected" != "$actual" ]]; then
    printf 'FAIL %s: expected %q, got %q\n' "$label" "$expected" "$actual" >&2
    exit 1
  fi
}

assert_contains() {
  local expected="$1" actual="$2" label="$3"
  if [[ "$actual" != *"$expected"* ]]; then
    printf 'FAIL %s: expected to contain %q, got %q\n' "$label" "$expected" "$actual" >&2
    exit 1
  fi
}

assert_file_contains() {
  local file="$1" expected="$2" label="$3"
  if ! grep -F -- "$expected" "$file" >/dev/null 2>&1; then
    printf 'FAIL %s: expected %s to contain %q\n' "$label" "$file" "$expected" >&2
    exit 1
  fi
}

# No marker yet: no override recorded.
DISTRO_ID="manjaro"
DISTRO_NAME="Manjaro Linux"
if distro_experimental_override_accepted; then
  printf 'FAIL: no marker should mean no accepted override\n' >&2
  exit 1
fi

# Record it, then it must be accepted for the same distro id.
distro_record_experimental_override
[[ -f "$WATCHDOGVPN_EXPERIMENTAL_OVERRIDE_MARKER" ]] \
  || { printf 'FAIL: marker file was not created\n' >&2; exit 1; }

dir_perm="$(stat -c '%a' "$TMP_DIR" 2>/dev/null || echo unknown)"
assert_eq "700" "$dir_perm" "marker directory permissions"

perm="$(stat -c '%a' "$WATCHDOGVPN_EXPERIMENTAL_OVERRIDE_MARKER" 2>/dev/null || echo unknown)"
assert_eq "600" "$perm" "marker permissions"

assert_file_contains "$ROOT_DIR/lib/distro.sh" 'sudo install -d -m 0700 -o root -g root "$marker_dir"' "privileged marker directory creation"
assert_file_contains "$ROOT_DIR/lib/distro.sh" 'sudo install -m 0600 -o root -g root "$tmp_marker" "$WATCHDOGVPN_EXPERIMENTAL_OVERRIDE_MARKER"' "privileged marker file publication"

if ! distro_experimental_override_accepted; then
  printf 'FAIL: recorded override for the same distro must be accepted\n' >&2
  exit 1
fi

# A different, unproven distro must NOT silently inherit the acceptance.
DISTRO_ID="zorin"
DISTRO_NAME="Zorin OS"
if distro_experimental_override_accepted; then
  printf 'FAIL: a stale override for a different distro must not carry over\n' >&2
  exit 1
fi

# Re-detecting the original distro still honors the earlier acceptance.
DISTRO_ID="manjaro"
DISTRO_NAME="Manjaro Linux"
if ! distro_experimental_override_accepted; then
  printf 'FAIL: re-detecting the original distro must still be accepted\n' >&2
  exit 1
fi

# prompt_experimental_distro_override(): accept path.
if ! output="$(printf 'y\n' | prompt_experimental_distro_override 2>&1)"; then
  printf 'FAIL: prompt should return 0 when the user answers y\n' >&2
  printf '%s\n' "$output" >&2
  exit 1
fi
assert_contains "at your own risk" "$output" "prompt accept message"

# prompt_experimental_distro_override(): decline path (default is No).
if output="$(printf '\n' | prompt_experimental_distro_override 2>&1)"; then
  printf 'FAIL: prompt should return 1 on an empty/default answer\n' >&2
  exit 1
fi

# prompt_experimental_distro_override(): explicit decline.
if output="$(printf 'n\n' | prompt_experimental_distro_override 2>&1)"; then
  printf 'FAIL: prompt should return 1 when the user answers n\n' >&2
  exit 1
fi

printf 'experimental distro override checks passed\n'
