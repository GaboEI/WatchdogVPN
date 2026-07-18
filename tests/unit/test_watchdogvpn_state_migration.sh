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

# Regression guard for a real-host installer failure: the sudo() shadow above
# is a no-op passthrough for every other assertion in this file, so it can
# never reproduce the real privilege boundary between the invoking user and a
# directory created by genuine `sudo mktemp -d` (root-owned, mode 0700). That
# gap let a missing `sudo` on _watchdogvpn_migration_entries' find call
# silently return zero entries against the staging directory instead of
# failing, which made both the publishability check and the publish loop
# treat an unreadable staging directory as empty rather than erroring -
# install.sh then failed later at target-content-validate with the staged
# legacy state already discarded. This mocked-sudo suite cannot exercise the
# real permission boundary, so assert the fix statically; the actual
# privilege behavior was confirmed by reproducing and fixing the failure on a
# real installed host.
if ! declare -f _watchdogvpn_migration_entries | grep -Fq 'run_privileged_readonly find'; then
  printf 'FAIL: _watchdogvpn_migration_entries must list entries through the privileged read-only helper; it is called against the root-owned staging directory created by `sudo mktemp -d`, which the invoking user cannot read directly\n' >&2
  exit 1
fi

_watchdogvpn_migration_checkpoint() {
  [[ "${MIGRATION_FAIL_AT:-}" != "$1" ]]
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
[[ ! -e "$target_dir" ]]

install -d -m 0750 "$target_dir"
WATCHDOGVPN_LEGACY_CONFIG_DIR="$source_dir" \
WATCHDOGVPN_SHARED_STATE_DIR="$target_dir" \
  migrate_watchdogvpn_shared_state
[[ -f "$target_dir/.migrated" ]]
[[ -w "$target_dir" ]]
[[ "$(cat "$target_dir/state.toml")" == "legacy-state" ]]
[[ "$(cat "$target_dir/profiles.json")" == "legacy-profiles" ]]
[[ "$(cat "$target_dir/rules/custom.json")" == "legacy-rules" ]]
grep -Fxq 'watchdogvpn-shared-state-ready-v2' "$target_dir/.migrated"

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
# A marker-less conflicting target could be a truncated predecessor rather than
# trusted shared state. Refuse it fail-closed instead of preserving it and
# certifying the migration, then permit explicit recovery after resolution.
if WATCHDOGVPN_LEGACY_CONFIG_DIR="$non_clobber_source" \
  WATCHDOGVPN_SHARED_STATE_DIR="$non_clobber_target" \
  migrate_watchdogvpn_shared_state >/dev/null 2>&1; then
  printf 'FAIL: migration accepted an unmarked conflicting target\n' >&2
  exit 1
fi
[[ ! -e "$non_clobber_target/.migrated" ]]
[[ "$(cat "$non_clobber_target/state.toml")" == "existing-state" ]]
rm "$non_clobber_target/state.toml"
WATCHDOGVPN_LEGACY_CONFIG_DIR="$non_clobber_source" \
WATCHDOGVPN_SHARED_STATE_DIR="$non_clobber_target" \
  migrate_watchdogvpn_shared_state
[[ -f "$non_clobber_target/.migrated" ]]
[[ "$(cat "$non_clobber_target/state.toml")" == "legacy-state" ]]

empty_source="$TMP_DIR/empty-source"
empty_source_target="$TMP_DIR/empty-source-target"
install -d -m 0755 "$empty_source"
WATCHDOGVPN_LEGACY_CONFIG_DIR="$empty_source" \
WATCHDOGVPN_SHARED_STATE_DIR="$empty_source_target" \
  migrate_watchdogvpn_shared_state
# Non-default target that does not exist yet is never auto-created (only the
# literal default path is prepared via systemd), so there is nothing to mark
# ready yet.
[[ ! -e "$empty_source_target/.migrated" ]]

# Regression test for the fresh-install bug found in the Task 18.4
# shared-state audit: a machine with NO legacy per-user config ever must
# still get the shared state directory marked "ready" once it exists, or
# config/paths.py::resolve_config_dir() keeps routing the CLI to
# $HOME/.config/watchdogvpn forever while the daemon uses the shared
# directory - the two processes would silently never share state. This
# simulates the real production case (the target directory already exists,
# e.g. created by systemd's StateDirectory= on first daemon start, or by
# prepare_watchdogvpn_state_directory for the literal default path) with no
# legacy data to migrate.
no_legacy_source="$TMP_DIR/no-legacy-source"
ready_target="$TMP_DIR/ready-target"
install -d -m 0750 "$ready_target"
WATCHDOGVPN_LEGACY_CONFIG_DIR="$no_legacy_source" \
WATCHDOGVPN_SHARED_STATE_DIR="$ready_target" \
  migrate_watchdogvpn_shared_state
if [[ ! -f "$ready_target/.migrated" ]]; then
  printf 'FAIL: shared state must be marked ready even with no legacy data to migrate, once the target directory exists\n' >&2
  exit 1
fi

# Same fix, but the legacy source directory exists and is merely empty
# (rather than absent) - must behave identically.
empty_but_present_source="$TMP_DIR/empty-but-present-source"
empty_but_present_target="$TMP_DIR/empty-but-present-target"
install -d -m 0755 "$empty_but_present_source"
install -d -m 0750 "$empty_but_present_target"
WATCHDOGVPN_LEGACY_CONFIG_DIR="$empty_but_present_source" \
WATCHDOGVPN_SHARED_STATE_DIR="$empty_but_present_target" \
  migrate_watchdogvpn_shared_state
if [[ ! -f "$empty_but_present_target/.migrated" ]]; then
  printf 'FAIL: shared state must be marked ready even when the legacy source directory exists but is empty\n' >&2
  exit 1
fi

dry_source="$TMP_DIR/dry-source"
dry_target="$TMP_DIR/dry-target"
make_legacy_state "$dry_source"
install -d -m 0750 "$dry_target"
INSTALL_DRY_RUN=1 \
WATCHDOGVPN_LEGACY_CONFIG_DIR="$dry_source" \
WATCHDOGVPN_SHARED_STATE_DIR="$dry_target" \
  migrate_watchdogvpn_shared_state
[[ ! -e "$dry_target/.migrated" ]]

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

invalid_journal_source="$TMP_DIR/invalid-journal-source"
invalid_journal_target="$TMP_DIR/invalid-journal-target"
make_legacy_state "$invalid_journal_source"
install -d -m 0750 "$invalid_journal_target"
printf 'untrusted-journal\n' >"$invalid_journal_target/.migration-in-progress"
if WATCHDOGVPN_LEGACY_CONFIG_DIR="$invalid_journal_source" \
  WATCHDOGVPN_SHARED_STATE_DIR="$invalid_journal_target" \
  migrate_watchdogvpn_shared_state >/dev/null 2>&1; then
  printf 'FAIL: migration accepted an invalid recovery journal\n' >&2
  exit 1
fi
[[ ! -e "$invalid_journal_target/.migrated" ]]

# Every staging, validation, journal, publication, and marker boundary must
# leave the marker absent on interruption. A re-run sees the journal when one
# exists, replaces any partial publication from the staged legacy source, and
# certifies only a content-identical final target.
for fail_at in \
  'stage-copy:profiles.json' \
  'stage-copy:rules' \
  'stage-copy:state.toml' \
  'stage-validate' \
  'journal-publish' \
  'publish:profiles.json' \
  'publish:rules' \
  'publish:state.toml' \
  'target-validate' \
  'target-content-validate' \
  'marker-publish'; do
  interruption_source="$TMP_DIR/interruption-source-${fail_at//:/-}"
  interruption_target="$TMP_DIR/interruption-target-${fail_at//:/-}"
  make_legacy_state "$interruption_source"
  # A legacy marker must never be copied into the shared target as success.
  printf 'legacy-marker\n' >"$interruption_source/.migrated"
  install -d -m 0750 "$interruption_target"
  export MIGRATION_FAIL_AT="$fail_at"
  if WATCHDOGVPN_LEGACY_CONFIG_DIR="$interruption_source" \
    WATCHDOGVPN_SHARED_STATE_DIR="$interruption_target" \
    migrate_watchdogvpn_shared_state >/dev/null 2>&1; then
    printf 'FAIL: migration unexpectedly completed at interruption point %s\n' "$fail_at" >&2
    exit 1
  fi
  unset MIGRATION_FAIL_AT
  [[ ! -e "$interruption_target/.migrated" ]]
  WATCHDOGVPN_LEGACY_CONFIG_DIR="$interruption_source" \
  WATCHDOGVPN_SHARED_STATE_DIR="$interruption_target" \
    migrate_watchdogvpn_shared_state
  [[ -f "$interruption_target/.migrated" ]]
  [[ "$(cat "$interruption_target/state.toml")" == "legacy-state" ]]
  [[ "$(cat "$interruption_target/profiles.json")" == "legacy-profiles" ]]
  [[ "$(cat "$interruption_target/rules/custom.json")" == "legacy-rules" ]]
  [[ ! -e "$interruption_target/.migration-in-progress" ]]
done

# A journal can recover an interrupted atomic publication, but it must not
# overwrite a later divergent/truncated entry. That state remains unmarked and
# is rejected until repaired with the known-good legacy content.
divergent_source="$TMP_DIR/divergent-source"
divergent_target="$TMP_DIR/divergent-target"
make_legacy_state "$divergent_source"
install -d -m 0750 "$divergent_target"
export MIGRATION_FAIL_AT='publish:state.toml'
if WATCHDOGVPN_LEGACY_CONFIG_DIR="$divergent_source" \
  WATCHDOGVPN_SHARED_STATE_DIR="$divergent_target" \
  migrate_watchdogvpn_shared_state >/dev/null 2>&1; then
  printf 'FAIL: migration unexpectedly completed before divergent recovery test\n' >&2
  exit 1
fi
unset MIGRATION_FAIL_AT
printf 'truncated\n' >"$divergent_target/profiles.json"
if WATCHDOGVPN_LEGACY_CONFIG_DIR="$divergent_source" \
  WATCHDOGVPN_SHARED_STATE_DIR="$divergent_target" \
  migrate_watchdogvpn_shared_state >/dev/null 2>&1; then
  printf 'FAIL: migration accepted a divergent journaled target\n' >&2
  exit 1
fi
[[ ! -e "$divergent_target/.migrated" ]]
cp "$divergent_source/profiles.json" "$divergent_target/profiles.json"
WATCHDOGVPN_LEGACY_CONFIG_DIR="$divergent_source" \
WATCHDOGVPN_SHARED_STATE_DIR="$divergent_target" \
  migrate_watchdogvpn_shared_state
[[ -f "$divergent_target/.migrated" ]]
[[ "$(cat "$divergent_target/state.toml")" == "legacy-state" ]]

printf 'WatchdogVPN shared state migration checks passed\n'
