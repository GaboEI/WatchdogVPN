#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

fail() {
  printf 'FAIL: %s\n' "$1" >&2
  exit 1
}

run_profiles_present() {
  # shellcheck disable=SC2034
  local env_out
  env_out="$(cd "$ROOT_DIR" && WATCHDOGVPN_AWG_PROFILE_COUNT="$1" bash -c '
    source lib/amneziawg.sh
    if amneziawg_profiles_present; then echo present; else echo absent; fi
  ')"
  printf '%s' "$env_out"
}

# 1. No AWG context (authoritative CLI count 0): no detection, not present.
if [[ "$(run_profiles_present 0)" != "absent" ]]; then
  fail "amneziawg_profiles_present must be absent when WATCHDOGVPN_AWG_PROFILE_COUNT=0"
fi

# 2. With an AWG profile (authoritative count 1): present.
if [[ "$(run_profiles_present 1)" != "present" ]]; then
  fail "amneziawg_profiles_present must be present when WATCHDOGVPN_AWG_PROFILE_COUNT=1"
fi

# 3. Without the env var, a profiles file with an AWG profile must be detected.
tmpdir="$(mktemp -d)"
trap 'rm -rf "$tmpdir"' EXIT
printf '[{"id":"awg-1","protocol":"amneziawg","name":"Server 1"}]\n' > "$tmpdir/profiles.json"
out="$(cd "$ROOT_DIR" && WATCHDOGVPN_PROFILES_FILE="$tmpdir/profiles.json" bash -c '
  source lib/amneziawg.sh
  if amneziawg_profiles_present; then echo present; else echo absent; fi
')"
if [[ "$out" != "present" ]]; then
  fail "amneziawg_profiles_present must detect a profiles file containing an amneziawg profile"
fi

# 4. A profiles file without any AWG profile must not activate detection.
printf '[{"id":"vless-1","protocol":"vless","name":"Server A"}]\n' > "$tmpdir/non_awg.json"
out="$(cd "$ROOT_DIR" && WATCHDOGVPN_PROFILES_FILE="$tmpdir/non_awg.json" bash -c '
  source lib/amneziawg.sh
  if amneziawg_profiles_present; then echo present; else echo absent; fi
')"
if [[ "$out" != "absent" ]]; then
  fail "amneziawg_profiles_present must stay absent when no amneziawg profile exists"
fi

echo "doctor amneziawg context: OK"
