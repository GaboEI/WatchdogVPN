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

# A protected parent must not make a real root-owned path look absent. Model
# that boundary without touching /root: local shell tests see a nonexistent
# virtual path, while the privileged test/removal seam reports and removes it.
(
  # shellcheck source=../../lib/install_files.sh
  . "$ROOT_DIR/lib/install_files.sh"
  protected_path="/phase235-protected-parent/watchdogvpn"
  removal_marker="$TMP_DIR/protected-removal"
  sudo() {
    if [[ "$1" == "test" && "$2" == "-e" && "$3" == "$protected_path" ]]; then
      return 0
    fi
    if [[ "$1" == "rm" && "$2" == "-rf" && "$3" == "--" && "$4" == "$protected_path" ]]; then
      : >"$removal_marker"
      return 0
    fi
    return 1
  }
  INSTALL_DRY_RUN=0
  REMOVE_ROOT_PATH_BACKUPS=0
  remove_root_path "$protected_path" >/dev/null
  [[ -f "$removal_marker" ]] || {
    printf 'FAIL: privileged existence check did not remove a protected root path\n' >&2
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
contains_file "$ROOT_DIR/lib/install_files.sh" 'root_path_exists "$path" || return 0' \
  "root backups must use the privileged existence contract"
contains_file "$UNINSTALLER" 'remove_root_path_no_backup "$INTERNAL_BACKUP_ROOT"' \
  "full purge must delete the fixed internal backup root without backing it up again"
contains_file "$UNINSTALLER" 'remove_user_path "$HOME/.config/watchdogvpn"' \
  "full purge must delete the invoking user's preserved legacy migration source"
contains_file "$UNINSTALLER" 'remove_root_path /root/.config/watchdogvpn' \
  "full purge must delete the known root legacy copy left by historical sudo execution"
contains_file "$UNINSTALLER" 'sudo_invoker_home()' \
  "sudo uninstall must resolve the invoking user's home through NSS"
contains_file "$UNINSTALLER" 'remove_root_path "$sudo_user_home/.local/share/watchdogvpn"' \
  "sudo uninstall must remove runtime backups from the invoking user's home"
contains_file "$UNINSTALLER" 'remove_root_path "$sudo_user_home/.local/bin/watchdogvpn"' \
  "sudo uninstall must remove the invoking user's compatibility launcher"
contains_file "$UNINSTALLER" 'remove_root_path "$sudo_user_home/Desktop/watchdogvpn.desktop"' \
  "sudo uninstall must remove the invoking user's desktop launcher"
contains_file "$UNINSTALLER" '--preserve-working' \
  "uninstall DNS rescue must preserve an already-working resolver baseline"
contains_file "$UNINSTALLER" 'if ((FULL_PURGE == 1)); then' \
  "legacy user config deletion must remain gated to a confirmed full purge"
if grep -Fq 'remove_root_path_no_backup "$BACKUP_ROOT"' "$UNINSTALLER"; then
  printf 'FAIL: full purge must never recursively delete an overrideable BACKUP_ROOT\n' >&2
  exit 1
fi

bash -n "$UNINSTALLER"
bash -n "$ROOT_DIR/lib/install_files.sh"

printf 'uninstall full-purge backup checks passed\n'
