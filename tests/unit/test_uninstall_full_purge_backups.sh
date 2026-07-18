#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
UNINSTALLER="$ROOT_DIR/uninstall.sh"
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

contains_file() {
  local path="$1" needle="$2" message="$3"
  if ! grep -Fq -- "$needle" "$path"; then
    printf 'FAIL: %s\n' "$message" >&2
    exit 1
  fi
}

# Behavioral regression for the shared removal primitive: install/update and
# non-full uninstall retain their recovery backups, while the full-purge mode
# can remove paths without creating a second copy of the data being deleted.
# All paths are isolated under TMP_DIR and sudo is stubbed locally.
(
  # shellcheck source=../../lib/install_files.sh
  . "$ROOT_DIR/lib/install_files.sh"
  sudo() { "$@"; }

  BACKUP_ROOT="$TMP_DIR/backups"
  with_backup="$TMP_DIR/with-backup"
  without_backup="$TMP_DIR/without-backup"
  printf 'preserve me\n' >"$with_backup"
  printf 'delete me\n' >"$without_backup"

  REMOVE_ROOT_PATH_BACKUPS=1
  remove_root_path "$with_backup" >/dev/null
  [[ ! -e "$with_backup" ]] || {
    printf 'FAIL: normal removal must delete the original path\n' >&2
    exit 1
  }
  find "$BACKUP_ROOT" -type f -name 'with-backup.*' -print -quit | grep -q . || {
    printf 'FAIL: normal removal must retain a recovery backup\n' >&2
    exit 1
  }

  before_count="$(find "$BACKUP_ROOT" -type f | wc -l)"
  REMOVE_ROOT_PATH_BACKUPS=0
  remove_root_path "$without_backup" >/dev/null
  after_count="$(find "$BACKUP_ROOT" -type f | wc -l)"
  [[ ! -e "$without_backup" ]] || {
    printf 'FAIL: full-purge removal must delete the original path\n' >&2
    exit 1
  }
  [[ "$before_count" == "$after_count" ]] || {
    printf 'FAIL: full-purge removal must not create a hidden backup copy\n' >&2
    exit 1
  }

  remove_root_path_no_backup "$BACKUP_ROOT" >/dev/null
  [[ ! -e "$BACKUP_ROOT" ]] || {
    printf 'FAIL: no-backup removal must delete the internal backup root\n' >&2
    exit 1
  }
)

# Wiring and safety contract: only the exact fixed product-owned backup root is
# removed. BACKUP_ROOT must never become the destructive full-purge target,
# because callers may override it with a user-owned location.
contains_file "$UNINSTALLER" 'INTERNAL_BACKUP_ROOT="/var/backups/watchdogvpn"' \
  "uninstall must define the fixed product-owned internal backup root"
contains_file "$UNINSTALLER" 'REMOVE_ROOT_PATH_BACKUPS=0' \
  "full purge must disable creation of new internal backups"
contains_file "$UNINSTALLER" 'remove_root_path_no_backup "$INTERNAL_BACKUP_ROOT"' \
  "full purge must delete the fixed internal backup root without backing it up again"
if grep -Fq 'remove_root_path_no_backup "$BACKUP_ROOT"' "$UNINSTALLER"; then
  printf 'FAIL: full purge must never recursively delete an overrideable BACKUP_ROOT\n' >&2
  exit 1
fi

bash -n "$UNINSTALLER"
bash -n "$ROOT_DIR/lib/install_files.sh"

printf 'uninstall full-purge backup checks passed\n'
