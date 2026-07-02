#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

# shellcheck source=../../lib/install_files.sh
. "$ROOT_DIR/lib/install_files.sh"
# shellcheck source=../../lib/runtime.sh
. "$ROOT_DIR/lib/runtime.sh"

sudo() {
  "$@"
}

make_legacy_state() {
  local source_dir="$1"
  install -d -m 0755 "$source_dir/rules"
  printf 'legacy-state\n' >"$source_dir/state.toml"
  printf 'legacy-profiles\n' >"$source_dir/profiles.json"
  printf 'legacy-rules\n' >"$source_dir/rules/custom.json"
}

INSTALL_DRY_RUN=0

missing_source="$TMP_DIR/missing"
empty_target="$TMP_DIR/empty-target"
WATCHDOGVPN_LEGACY_CONFIG_DIR="$missing_source" \
WATCHDOGVPN_SHARED_STATE_DIR="$empty_target" \
  migrate_watchdogvpn_shared_state
[[ ! -e "$empty_target/.migrated" ]]

source_dir="$TMP_DIR/source"
target_dir="$TMP_DIR/target"
make_legacy_state "$source_dir"
WATCHDOGVPN_LEGACY_CONFIG_DIR="$source_dir" \
WATCHDOGVPN_SHARED_STATE_DIR="$target_dir" \
  migrate_watchdogvpn_shared_state
[[ -f "$target_dir/.migrated" ]]
[[ -w "$target_dir" ]]
[[ "$(cat "$target_dir/state.toml")" == "legacy-state" ]]
[[ "$(cat "$target_dir/profiles.json")" == "legacy-profiles" ]]
[[ "$(cat "$target_dir/rules/custom.json")" == "legacy-rules" ]]

printf 'after-marker\n' >"$source_dir/providers.json"
WATCHDOGVPN_LEGACY_CONFIG_DIR="$source_dir" \
WATCHDOGVPN_SHARED_STATE_DIR="$target_dir" \
  migrate_watchdogvpn_shared_state
[[ ! -e "$target_dir/providers.json" ]]

non_clobber_source="$TMP_DIR/non-clobber-source"
non_clobber_target="$TMP_DIR/non-clobber-target"
make_legacy_state "$non_clobber_source"
install -d -m 0755 "$non_clobber_target"
printf 'existing-state\n' >"$non_clobber_target/state.toml"
WATCHDOGVPN_LEGACY_CONFIG_DIR="$non_clobber_source" \
WATCHDOGVPN_SHARED_STATE_DIR="$non_clobber_target" \
  migrate_watchdogvpn_shared_state
[[ -f "$non_clobber_target/.migrated" ]]
[[ "$(cat "$non_clobber_target/state.toml")" == "existing-state" ]]
[[ "$(cat "$non_clobber_target/profiles.json")" == "legacy-profiles" ]]

empty_source="$TMP_DIR/empty-source"
empty_source_target="$TMP_DIR/empty-source-target"
install -d -m 0755 "$empty_source"
WATCHDOGVPN_LEGACY_CONFIG_DIR="$empty_source" \
WATCHDOGVPN_SHARED_STATE_DIR="$empty_source_target" \
  migrate_watchdogvpn_shared_state
[[ ! -e "$empty_source_target/.migrated" ]]

dry_source="$TMP_DIR/dry-source"
dry_target="$TMP_DIR/dry-target"
make_legacy_state "$dry_source"
INSTALL_DRY_RUN=1 \
WATCHDOGVPN_LEGACY_CONFIG_DIR="$dry_source" \
WATCHDOGVPN_SHARED_STATE_DIR="$dry_target" \
  migrate_watchdogvpn_shared_state
[[ ! -e "$dry_target" ]]

INSTALL_DRY_RUN=0
bad_source="$TMP_DIR/bad-source"
bad_target="$TMP_DIR/bad-target"
make_legacy_state "$bad_source"
printf 'not-a-directory\n' >"$bad_target"
if WATCHDOGVPN_LEGACY_CONFIG_DIR="$bad_source" \
  WATCHDOGVPN_SHARED_STATE_DIR="$bad_target" \
  migrate_watchdogvpn_shared_state >/dev/null 2>&1; then
  printf 'FAIL: migration succeeded with an invalid target path\n' >&2
  exit 1
fi
[[ ! -e "$bad_target/.migrated" ]]

printf 'WatchdogVPN shared state migration checks passed\n'
