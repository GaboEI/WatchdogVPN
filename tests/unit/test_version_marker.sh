#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

assert_contains() {
  local file="$1" pattern="$2" message="$3"
  if ! grep -Fq "$pattern" "$file"; then
    printf 'FAIL: %s\n' "$message" >&2
    printf 'missing pattern in %s: %s\n' "$file" "$pattern" >&2
    exit 1
  fi
}

# --- static wiring: install.sh/update.sh record it, doctor.sh reads it ---

assert_contains "$ROOT_DIR/lib/version_marker.sh" 'record_installed_version' "version marker lib must define a recorder"
assert_contains "$ROOT_DIR/lib/version_marker.sh" 'installed_version_commit' "version marker lib must define an installed-commit reader"
assert_contains "$ROOT_DIR/lib/version_marker.sh" 'source_checkout_commit' "version marker lib must define a source-checkout-commit reader"
assert_contains "$ROOT_DIR/lib/runtime_transaction.sh" 'runtime_transaction_publish_installed_version' "runtime transaction must defer installed-version publication"
assert_contains "$ROOT_DIR/install.sh" 'runtime_transaction_publish_installed_version' "installer must publish the marker only after runtime validation"
assert_contains "$ROOT_DIR/update.sh" 'runtime_transaction_publish_installed_version' "updater must publish the marker only after runtime validation"
assert_contains "$ROOT_DIR/install.sh" '. "$ROOT_DIR/lib/version_marker.sh"' "installer must source lib/version_marker.sh"
assert_contains "$ROOT_DIR/update.sh" '. "$ROOT_DIR/lib/version_marker.sh"' "updater must source lib/version_marker.sh"
assert_contains "$ROOT_DIR/doctor.sh" '. "$ROOT_DIR/lib/version_marker.sh"' "doctor must source lib/version_marker.sh"
assert_contains "$ROOT_DIR/doctor.sh" 'Installed/Source Version Skew' "doctor must report installed/source version skew"
assert_contains "$ROOT_DIR/doctor.sh" 'installed_version_commit' "doctor must read the installed version marker"
assert_contains "$ROOT_DIR/doctor.sh" 'source_checkout_commit' "doctor must compare against the source checkout commit"

# Regression guard: this defensive parent-dir creation used to hardcode 0755,
# silently clobbering /etc/watchdogvpn back from the 0750 that
# install_config_defaults() (lib/config.sh) sets it to earlier in the same
# install/update run - install -d re-applies the mode on an already-existing
# directory, so this ran later and always won, reproducing the exact
# ConfigurationDirectoryMode=0750 mismatch warning on every single install.
# Found only by watching a real install with inotifywait in a disposable VM;
# a static read of lib/config.sh alone could not have caught it.
assert_contains "$ROOT_DIR/lib/version_marker.sh" 'install -d -m 0750' "version marker's parent-dir creation must not reintroduce the /etc/watchdogvpn mode drift"

# --- behavioral: record/read/compare actually works, isolated from the real
#     system (no sudo, a throwaway marker path) ---

tmp_marker="$(mktemp -u)"
trap 'rm -f "$tmp_marker"' EXIT

dry_run_output="$(cd "$ROOT_DIR" && bash -c '
set -euo pipefail
ROOT_DIR="'"$ROOT_DIR"'"
source lib/common.sh
WATCHDOGVPN_VERSION_MARKER="'"$tmp_marker"'"
source lib/version_marker.sh
INSTALL_DRY_RUN=1 record_installed_version
' 2>&1)"
grep -Fq "[DRY-RUN] record installed version marker" <<<"$dry_run_output" || {
  printf 'FAIL: record_installed_version must skip writing under --dry-run\n' >&2
  exit 1
}
[[ ! -e "$tmp_marker" ]] || {
  printf 'FAIL: record_installed_version must not create a marker file under --dry-run\n' >&2
  exit 1
}

real_commit="$(git -C "$ROOT_DIR" rev-parse HEAD)"
printf 'commit=%s\ninstalled_at=2026-07-07T00:00:00Z\n' "$real_commit" >"$tmp_marker"

read_output="$(cd "$ROOT_DIR" && bash -c '
set -euo pipefail
ROOT_DIR="'"$ROOT_DIR"'"
source lib/common.sh
WATCHDOGVPN_VERSION_MARKER="'"$tmp_marker"'"
source lib/version_marker.sh
installed="$(installed_version_commit)"
source_commit="$(source_checkout_commit)"
if [[ "$installed" == "$source_commit" ]]; then
  echo "MATCH"
else
  echo "MISMATCH installed=$installed source=$source_commit"
fi
' 2>&1)"
grep -Fq "MATCH" <<<"$read_output" || {
  printf 'FAIL: installed_version_commit must match source_checkout_commit for a marker written from this exact checkout HEAD\n' >&2
  printf '%s\n' "$read_output" >&2
  exit 1
}

printf 'commit=0000000000000000000000000000000000000000\ninstalled_at=2020-01-01T00:00:00Z\n' >"$tmp_marker"
mismatch_output="$(cd "$ROOT_DIR" && bash -c '
set -euo pipefail
ROOT_DIR="'"$ROOT_DIR"'"
source lib/common.sh
WATCHDOGVPN_VERSION_MARKER="'"$tmp_marker"'"
source lib/version_marker.sh
installed="$(installed_version_commit)"
source_commit="$(source_checkout_commit)"
[[ "$installed" != "$source_commit" ]] && echo "MISMATCH_DETECTED" || echo "BUG_MATCHED"
' 2>&1)"
grep -Fq "MISMATCH_DETECTED" <<<"$mismatch_output" || {
  printf 'FAIL: a stale marker commit must be detected as different from the source checkout HEAD\n' >&2
  exit 1
}

rm -f "$tmp_marker"

echo "version marker checks passed"
