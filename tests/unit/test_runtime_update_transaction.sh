#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

# The transaction is intentionally testable without a privileged host. Its
# command boundary is the same `sudo` boundary the installer uses.
sudo() { "$@"; }

# shellcheck source=../../lib/common.sh
. "$ROOT_DIR/lib/common.sh"
# shellcheck source=../../lib/install_files.sh
. "$ROOT_DIR/lib/install_files.sh"
# shellcheck source=../../lib/runtime_transaction.sh
. "$ROOT_DIR/lib/runtime_transaction.sh"
# shellcheck source=../../lib/runtime.sh
. "$ROOT_DIR/lib/runtime.sh"

runtime="$TMP_DIR/runtime"
wrapper="$TMP_DIR/watchdog"
unit="$TMP_DIR/watchdogvpn.service"
marker="$TMP_DIR/installed-version"
manifest="$TMP_DIR/installed-provenance.json"
WATCHDOGVPN_VERSION_MARKER="$marker"
WATCHDOGVPN_PROVENANCE_MANIFEST="$manifest"

reset_generation() {
  rm -rf "$runtime" "$wrapper" "$unit" "$marker" "$manifest"
  mkdir -p "$runtime"
  printf 'old runtime\n' >"$runtime/generation"
  printf 'old wrapper\n' >"$wrapper"
  printf 'old unit\n' >"$unit"
  printf 'commit=old\n' >"$marker"
  printf 'old manifest\n' >"$manifest"
}

assert_old_generation() {
  [[ "$(<"$runtime/generation")" == "old runtime" ]] || {
    printf 'FAIL: prior runtime was not restored\n' >&2
    exit 1
  }
  [[ "$(<"$wrapper")" == "old wrapper" ]] || {
    printf 'FAIL: prior wrapper was not restored\n' >&2
    exit 1
  }
  [[ "$(<"$unit")" == "old unit" ]] || {
    printf 'FAIL: prior unit was not restored\n' >&2
    exit 1
  }
  [[ "$(<"$marker")" == "commit=old" ]] || {
    printf 'FAIL: prior installed marker was not restored\n' >&2
    exit 1
  }
  [[ "$(<"$manifest")" == "old manifest" ]] || {
    printf 'FAIL: prior installed provenance manifest was not restored\n' >&2
    exit 1
  }
}

# Copy, disk, permission, unit, restart, and smoke failures are all later
# failures from the updater's perspective. In every case, the runtime,
# wrapper, unit, and marker return as one prior generation.
for failure in copy disk permission unit restart smoke; do
  reset_generation
  runtime_transaction_begin >/dev/null
  runtime_transaction_snapshot_path "$runtime"
  runtime_transaction_snapshot_path "$wrapper"
  runtime_transaction_snapshot_path "$unit"
  runtime_transaction_snapshot_path "$marker"
  runtime_transaction_snapshot_path "$manifest"
  printf 'new runtime\n' >"$runtime/generation"
  printf 'new wrapper\n' >"$wrapper"
  printf 'new unit\n' >"$unit"
  printf 'commit=new\n' >"$marker"
  printf 'new manifest\n' >"$manifest"
  WATCHDOGVPN_RUNTIME_TRANSACTION_FAIL_STEP="$failure"
  if runtime_transaction_checkpoint "$failure"; then
    printf 'FAIL: injected %s failure was accepted\n' "$failure" >&2
    exit 1
  fi
  unset WATCHDOGVPN_RUNTIME_TRANSACTION_FAIL_STEP
  runtime_transaction_rollback >/dev/null
  assert_old_generation
done

# The large Python tree is staged and validated before the active directory is
# switched. A post-switch failure restores the complete old tree, not a mix of
# old and new individual files.
reset_generation
stage="$TMP_DIR/candidate"
mkdir -p "$stage"
printf 'new runtime\n' >"$stage/generation"
printf 'new-only\n' >"$stage/new-file"
runtime_transaction_begin >/dev/null
runtime_transaction_replace_directory_from_stage "$stage" "$runtime"
[[ "$(<"$runtime/generation")" == "new runtime" && -e "$runtime/new-file" ]] || {
  printf 'FAIL: complete candidate was not switched into place\n' >&2
  exit 1
}
runtime_transaction_snapshot_path "$marker"
runtime_transaction_snapshot_path "$manifest"
printf 'commit=new\n' >"$marker"
printf 'new manifest\n' >"$manifest"
runtime_transaction_rollback >/dev/null
assert_old_generation
[[ ! -e "$runtime/new-file" ]] || {
  printf 'FAIL: rollback retained a mixed-generation runtime file\n' >&2
  exit 1
}

# Deferred publication snapshots and restores the marker/manifest pair as one
# transaction boundary.
reset_generation
record_installed_version() {
  printf 'commit=new\n' >"$WATCHDOGVPN_VERSION_MARKER"
  printf 'new manifest\n' >"$WATCHDOGVPN_PROVENANCE_MANIFEST"
}
runtime_transaction_begin >/dev/null
runtime_transaction_publish_installed_version
runtime_transaction_rollback >/dev/null
assert_old_generation

# A candidate covers the whole shipped runtime, not just imported Python:
# wrappers, privileged helpers, units, TUI, and installed support tooling all
# exist before the active runtime can be changed.
runtime_transaction_begin >/dev/null
runtime_transaction_prepare_candidate "$ROOT_DIR"
candidate="$WATCHDOGVPN_RUNTIME_CANDIDATE_ROOT"
for required_path in \
  cli/main.py \
  daemon/main.py \
  bin/watchdogvpn \
  sbin/vpn_domain_bypass_apply.sh \
  systemd/watchdogvpn.service \
  tui/VPN \
  tui/watchdogvpn/actions.py \
  doctor.sh \
  lib/runtime_transaction.sh
do
  [[ -e "$candidate/$required_path" ]] || {
    printf 'FAIL: complete runtime candidate is missing %s\n' "$required_path" >&2
    exit 1
  }
done
if find "$candidate" \( -type d -name __pycache__ -o -type f \( -name '*.pyc' -o -name '*.pyo' \) \) -print -quit | grep -q .; then
  printf 'FAIL: runtime candidate retained executable Python bytecode caches\n' >&2
  exit 1
fi
runtime_transaction_rollback >/dev/null

# Static order is a release-safety contract: marker publication only follows
# the smoke test, and commit is last so later failures still roll back.
for script in install.sh update.sh; do
  begin_line="$(grep -nF 'runtime_transaction_begin' "$ROOT_DIR/$script" | head -n1 | cut -d: -f1)"
  smoke_line="$(grep -nF 'smoke_test_watchdogvpn_daemon' "$ROOT_DIR/$script" | tail -n1 | cut -d: -f1)"
  marker_line="$(grep -nF 'runtime_transaction_publish_installed_version' "$ROOT_DIR/$script" | head -n1 | cut -d: -f1)"
  commit_line="$(grep -nF 'runtime_transaction_commit' "$ROOT_DIR/$script" | tail -n1 | cut -d: -f1)"
  if [[ -z "$begin_line" || -z "$smoke_line" || -z "$marker_line" || -z "$commit_line" ]] \
    || ! ((begin_line < smoke_line && smoke_line < marker_line && marker_line < commit_line)); then
    printf 'FAIL: %s does not preserve transactional runtime/marker ordering\n' "$script" >&2
    exit 1
  fi
done

printf 'runtime update transaction checks passed\n'
