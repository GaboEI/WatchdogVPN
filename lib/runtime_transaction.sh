#!/usr/bin/env bash
set -euo pipefail

# A runtime update crosses several filesystem and service-manager boundaries.
# Backups alone are not a transaction: a later unit/restart/smoke failure used
# to leave the replacement files and installed-version marker in place.  This
# helper keeps exact pre-update snapshots until the new daemon has passed its
# smoke test, then either commits all touched paths or restores all of them.
WATCHDOGVPN_RUNTIME_TRANSACTION_ACTIVE=0
WATCHDOGVPN_RUNTIME_TRANSACTION_DIR=""
WATCHDOGVPN_RUNTIME_TRANSACTION_PATHS=()
WATCHDOGVPN_RUNTIME_TRANSACTION_PRESENT=()
WATCHDOGVPN_RUNTIME_TRANSACTION_SNAPSHOTS=()
WATCHDOGVPN_RUNTIME_TRANSACTION_CLEANUP_PATHS=()
WATCHDOGVPN_RUNTIME_CANDIDATE_ROOT=""

runtime_transaction_is_active() {
  [[ "${WATCHDOGVPN_RUNTIME_TRANSACTION_ACTIVE:-0}" == "1" ]]
}

runtime_transaction_checkpoint() {
  local checkpoint="$1"
  if [[ "${WATCHDOGVPN_RUNTIME_TRANSACTION_FAIL_STEP:-}" == "$checkpoint" ]]; then
    printf 'ERROR: injected WatchdogVPN runtime transaction failure at %s\n' "$checkpoint" >&2
    return 1
  fi
}

runtime_transaction_begin() {
  if runtime_transaction_is_active; then
    printf 'ERROR: WatchdogVPN runtime transaction is already active\n' >&2
    return 1
  fi

  WATCHDOGVPN_RUNTIME_TRANSACTION_PATHS=()
  WATCHDOGVPN_RUNTIME_TRANSACTION_PRESENT=()
  WATCHDOGVPN_RUNTIME_TRANSACTION_SNAPSHOTS=()
  WATCHDOGVPN_RUNTIME_TRANSACTION_CLEANUP_PATHS=()
  if [[ "${INSTALL_DRY_RUN:-0}" == "1" ]]; then
    WATCHDOGVPN_RUNTIME_TRANSACTION_ACTIVE=1
    printf '[DRY-RUN] begin transactional WatchdogVPN runtime update\n'
    return 0
  fi

  WATCHDOGVPN_RUNTIME_TRANSACTION_DIR="$(mktemp -d "${TMPDIR:-/var/tmp}/watchdogvpn-runtime-update.XXXXXX")" || return 1
  mkdir -p "$WATCHDOGVPN_RUNTIME_TRANSACTION_DIR/snapshots"
  WATCHDOGVPN_RUNTIME_TRANSACTION_ACTIVE=1
  printf '[INFO] staged transactional WatchdogVPN runtime update\n'
}

runtime_transaction_snapshot_path() {
  local path="$1" index snapshot existing_path
  runtime_transaction_is_active || return 0
  [[ "${INSTALL_DRY_RUN:-0}" == "1" ]] && return 0

  for existing_path in "${WATCHDOGVPN_RUNTIME_TRANSACTION_PATHS[@]}"; do
    [[ "$existing_path" == "$path" ]] && return 0
  done

  index="${#WATCHDOGVPN_RUNTIME_TRANSACTION_PATHS[@]}"
  snapshot="$WATCHDOGVPN_RUNTIME_TRANSACTION_DIR/snapshots/$index"
  WATCHDOGVPN_RUNTIME_TRANSACTION_PATHS+=("$path")
  WATCHDOGVPN_RUNTIME_TRANSACTION_SNAPSHOTS+=("$snapshot")
  if [[ -e "$path" || -L "$path" ]]; then
    run_step sudo cp -a -- "$path" "$snapshot"
    WATCHDOGVPN_RUNTIME_TRANSACTION_PRESENT+=("1")
  else
    WATCHDOGVPN_RUNTIME_TRANSACTION_PRESENT+=("0")
  fi
}

runtime_transaction_register_cleanup_path() {
  local path="$1"
  runtime_transaction_is_active || return 0
  WATCHDOGVPN_RUNTIME_TRANSACTION_CLEANUP_PATHS+=("$path")
}

runtime_transaction_prepare_candidate() {
  local source_root="$1" candidate package item
  runtime_transaction_is_active || {
    printf 'ERROR: runtime candidate requires an active transaction\n' >&2
    return 1
  }
  if [[ "${INSTALL_DRY_RUN:-0}" == "1" ]]; then
    WATCHDOGVPN_RUNTIME_CANDIDATE_ROOT="$source_root"
    return 0
  fi

  runtime_transaction_checkpoint disk
  candidate="$WATCHDOGVPN_RUNTIME_TRANSACTION_DIR/candidate"
  mkdir -p "$candidate"
  WATCHDOGVPN_RUNTIME_CANDIDATE_ROOT="$candidate"
  for package in "${PYTHON_RUNTIME_PACKAGES[@]}"; do
    runtime_transaction_checkpoint copy
    cp -a "$source_root/$package" "$candidate/"
  done
  for item in "${PYTHON_RUNTIME_SUPPORT_FILES[@]}" "${PYTHON_RUNTIME_SUPPORT_DIRS[@]}"; do
    runtime_transaction_checkpoint copy
    cp -a "$source_root/$item" "$candidate/"
  done
  _validate_staged_python_runtime "$candidate"
  _purge_python_bytecode "$candidate"
  printf '[INFO] validated complete WatchdogVPN runtime candidate\n'
}

runtime_transaction_replace_directory_from_stage() {
  local stage="$1" destination="$2" rollback_path
  runtime_transaction_is_active || {
    printf 'ERROR: directory replacement requires an active runtime transaction\n' >&2
    return 1
  }
  [[ -d "$stage" ]] || {
    printf 'ERROR: runtime candidate is not a directory: %s\n' "$stage" >&2
    return 1
  }

  runtime_transaction_snapshot_path "$destination"
  runtime_transaction_checkpoint package-switch
  rollback_path="${destination}.rollback.${BASHPID}.${RANDOM}"
  if [[ -e "$destination" || -L "$destination" ]]; then
    run_step sudo mv -- "$destination" "$rollback_path"
    runtime_transaction_register_cleanup_path "$rollback_path"
  fi
  if ! run_step sudo mv -- "$stage" "$destination"; then
    if [[ -e "$rollback_path" || -L "$rollback_path" ]]; then
      run_step sudo mv -- "$rollback_path" "$destination" || true
    fi
    return 1
  fi
}

runtime_transaction_rollback() {
  local index path snapshot present cleanup_path failed=0
  runtime_transaction_is_active || return 0
  if [[ "${INSTALL_DRY_RUN:-0}" == "1" ]]; then
    WATCHDOGVPN_RUNTIME_TRANSACTION_ACTIVE=0
    WATCHDOGVPN_RUNTIME_TRANSACTION_DIR=""
    WATCHDOGVPN_RUNTIME_CANDIDATE_ROOT=""
    return 0
  fi

  printf '[ROLLBACK] restoring prior WatchdogVPN runtime generation\n' >&2
  for ((index=${#WATCHDOGVPN_RUNTIME_TRANSACTION_PATHS[@]} - 1; index >= 0; index--)); do
    path="${WATCHDOGVPN_RUNTIME_TRANSACTION_PATHS[index]}"
    snapshot="${WATCHDOGVPN_RUNTIME_TRANSACTION_SNAPSHOTS[index]}"
    present="${WATCHDOGVPN_RUNTIME_TRANSACTION_PRESENT[index]}"
    if ! run_step sudo rm -rf -- "$path"; then
      failed=1
      continue
    fi
    if [[ "$present" == "1" ]] && ! run_step sudo cp -a -- "$snapshot" "$path"; then
      failed=1
    fi
  done
  for cleanup_path in "${WATCHDOGVPN_RUNTIME_TRANSACTION_CLEANUP_PATHS[@]}"; do
    run_step sudo rm -rf -- "$cleanup_path" || failed=1
  done
  run_step sudo rm -rf -- "$WATCHDOGVPN_RUNTIME_TRANSACTION_DIR" || failed=1
  WATCHDOGVPN_RUNTIME_TRANSACTION_ACTIVE=0
  WATCHDOGVPN_RUNTIME_TRANSACTION_DIR=""
  WATCHDOGVPN_RUNTIME_CANDIDATE_ROOT=""
  return "$failed"
}

runtime_transaction_commit() {
  local cleanup_path
  runtime_transaction_is_active || return 0
  if [[ "${INSTALL_DRY_RUN:-0}" == "1" ]]; then
    WATCHDOGVPN_RUNTIME_TRANSACTION_ACTIVE=0
    WATCHDOGVPN_RUNTIME_TRANSACTION_DIR=""
    WATCHDOGVPN_RUNTIME_CANDIDATE_ROOT=""
    return 0
  fi

  # Cleanup is deliberately best-effort: a completed generation must never be
  # rolled back merely because its private recovery evidence cannot be removed.
  for cleanup_path in "${WATCHDOGVPN_RUNTIME_TRANSACTION_CLEANUP_PATHS[@]}"; do
    run_step sudo rm -rf -- "$cleanup_path" || warn "could not remove retired runtime generation: $cleanup_path"
  done
  run_step sudo rm -rf -- "$WATCHDOGVPN_RUNTIME_TRANSACTION_DIR" || warn "could not remove runtime transaction staging"
  WATCHDOGVPN_RUNTIME_TRANSACTION_ACTIVE=0
  WATCHDOGVPN_RUNTIME_TRANSACTION_DIR=""
  WATCHDOGVPN_RUNTIME_CANDIDATE_ROOT=""
  ok "transactional WatchdogVPN runtime update committed"
}

runtime_transaction_publish_installed_version() {
  runtime_transaction_is_active || {
    printf 'ERROR: installed-version publication requires an active runtime transaction\n' >&2
    return 1
  }
  runtime_transaction_snapshot_path "$WATCHDOGVPN_VERSION_MARKER"
  runtime_transaction_snapshot_path "$WATCHDOGVPN_PROVENANCE_MANIFEST"
  runtime_transaction_checkpoint marker-publish
  record_installed_version
}

runtime_transaction_failure_trap() {
  local rc=$? rollback_rc=0 service_rc=0 operation="${1:-installer operation}"
  trap - ERR
  set +e
  if runtime_transaction_is_active; then
    runtime_transaction_rollback
    rollback_rc=$?
    if declare -F restore_watchdogvpn_service_after_runtime_rollback >/dev/null; then
      restore_watchdogvpn_service_after_runtime_rollback
      service_rc=$?
    fi
  fi
  if ((rollback_rc != 0 || service_rc != 0)); then
    fail "automatic runtime rollback was incomplete; do not trust the installed marker"
  fi
  print_installer_failure_recovery "$rc" "$operation"
  exit "$rc"
}
