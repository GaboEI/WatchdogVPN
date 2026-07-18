#!/usr/bin/env bash
set -euo pipefail

INSTALL_DRY_RUN="${INSTALL_DRY_RUN:-0}"
BACKUP_ROOT="${BACKUP_ROOT:-/var/backups/watchdogvpn}"
REMOVE_ROOT_PATH_BACKUPS="${REMOVE_ROOT_PATH_BACKUPS:-1}"

run_step() {
  if [[ "$INSTALL_DRY_RUN" == "1" ]]; then
    printf '[DRY-RUN] %s\n' "$*"
    return 0
  fi
  "$@"
}

root_path_exists() {
  local path="$1"
  if [[ -e "$path" || -L "$path" ]]; then
    return 0
  fi

  # Shell -e/-L checks suppress EACCES just like pathlib.Path.exists(): an
  # unprivileged installer process sees /root-owned children as "absent" and
  # silently skips both backup and removal. Live mutations have already passed
  # the caller's sudo privilege check, so preserve the real distinction here.
  if [[ "${INSTALL_DRY_RUN:-0}" == "1" ]]; then
    sudo -n test -e "$path" 2>/dev/null || sudo -n test -L "$path" 2>/dev/null
  else
    sudo test -e "$path" || sudo test -L "$path"
  fi
}

download_release_asset() {
  local url="$1" destination="$2" timeout="$3" label="$4"

  if run_step curl --fail --show-error --location \
    --connect-timeout 15 \
    --max-time "$timeout" \
    "$url" \
    -o "$destination"; then
    return 0
  fi

  # Some bridged IPv4-only networks accept the GitHub release redirect but
  # blackhole the CDN connection selected by curl's normal address-family
  # choice. Retry once over IPv4 before failing; the caller still verifies the
  # pinned archive checksum before installing anything.
  warn "$label download failed on the default network path; retrying once over IPv4"
  run_step curl --ipv4 --fail --show-error --location \
    --connect-timeout 15 \
    --max-time "$timeout" \
    "$url" \
    -o "$destination"
}

backup_path() {
  local path="$1" stamp backup
  root_path_exists "$path" || return 0
  stamp="$(date +%Y%m%d-%H%M%S)"
  backup="$BACKUP_ROOT$path.$stamp"
  if [[ "$INSTALL_DRY_RUN" == "1" ]]; then
    printf '[DRY-RUN] backup %s -> %s\n' "$path" "$backup"
    return 0
  fi
  run_step sudo install -d -m 0755 "$(dirname "$backup")"
  run_step sudo cp -a "$path" "$backup"
  printf '[BACKUP] %s -> %s\n' "$path" "$backup"
}

install_root_file() {
  local src="$1" dest="$2" mode="$3"
  backup_path "$dest"
  if declare -F runtime_transaction_is_active >/dev/null && runtime_transaction_is_active; then
    runtime_transaction_checkpoint copy
    runtime_transaction_snapshot_path "$dest"
  fi
  run_step sudo install -m "$mode" -o root -g root "$src" "$dest"
}

install_user_file() {
  local src="$1" dest="$2" mode="$3"
  if declare -F runtime_transaction_is_active >/dev/null && runtime_transaction_is_active; then
    runtime_transaction_checkpoint copy
    runtime_transaction_snapshot_path "$dest"
  fi
  run_step install -d -m 0755 "$(dirname "$dest")"
  if [[ -e "$dest" ]]; then
    if [[ "$INSTALL_DRY_RUN" == "1" ]]; then
      printf '[DRY-RUN] backup user file %s\n' "$dest"
    else
      local stamp backup
      stamp="$(date +%Y%m%d-%H%M%S)"
      backup="$dest.$stamp.bak"
      cp -a "$dest" "$backup"
      printf '[BACKUP] %s -> %s\n' "$dest" "$backup"
    fi
  fi
  run_step install -m "$mode" "$src" "$dest"
}

install_user_dir() {
  local src="$1" dest="$2"
  if declare -F runtime_transaction_is_active >/dev/null && runtime_transaction_is_active; then
    runtime_transaction_checkpoint copy
    runtime_transaction_snapshot_path "$dest"
  fi
  run_step install -d -m 0755 "$(dirname "$dest")"
  if [[ -e "$dest" ]]; then
    if [[ "$INSTALL_DRY_RUN" == "1" ]]; then
      printf '[DRY-RUN] backup user directory %s\n' "$dest"
    else
      local stamp backup
      stamp="$(date +%Y%m%d-%H%M%S)"
      backup="$dest.$stamp.bak"
      cp -a "$dest" "$backup"
      printf '[BACKUP] %s -> %s\n' "$dest" "$backup"
    fi
  fi
  if [[ "$INSTALL_DRY_RUN" == "1" ]]; then
    printf '[DRY-RUN] install user directory %s -> %s\n' "$src" "$dest"
    return 0
  fi
  rm -rf -- "$dest"
  cp -a "$src" "$dest"
}

create_root_dir() {
  local path="$1" mode="${2:-0755}"
  run_step sudo install -d -m "$mode" -o root -g root "$path"
}

create_owned_dir() {
  local path="$1" owner="$2" group="$3" mode="${4:-0755}"
  run_step sudo install -d -m "$mode" -o "$owner" -g "$group" "$path"
}

create_config_if_missing() {
  local src="$1" dest="$2" mode="${3:-0644}" group="${4:-root}"
  if [[ -e "$dest" ]] || { [[ "$INSTALL_DRY_RUN" != "1" ]] && sudo test -e "$dest"; }; then
    printf '[KEEP] existing config: %s\n' "$dest"
    return 0
  fi
  run_step sudo install -m "$mode" -o root -g "$group" "$src" "$dest"
}

create_system_user_no_home() {
  local user="$1" shell
  if getent passwd "$user" >/dev/null 2>&1; then
    printf '[KEEP] service user exists: %s\n' "$user"
    return 0
  fi
  shell="/usr/sbin/nologin"
  [[ -x "$shell" ]] || shell="/usr/bin/nologin"
  [[ -x "$shell" ]] || shell="/bin/false"
  run_step sudo useradd --system --no-create-home --shell "$shell" "$user"
}

remove_root_path() {
  local path="$1"
  if ! root_path_exists "$path"; then
    printf '[KEEP] absent: %s\n' "$path"
    return 0
  fi
  if [[ "$REMOVE_ROOT_PATH_BACKUPS" == "1" ]]; then
    backup_path "$path"
  fi
  if declare -F runtime_transaction_is_active >/dev/null && runtime_transaction_is_active; then
    runtime_transaction_snapshot_path "$path"
  fi
  run_step sudo rm -rf -- "$path"
}

remove_root_path_no_backup() {
  local path="$1"
  if ! root_path_exists "$path"; then
    printf '[KEEP] absent: %s\n' "$path"
    return 0
  fi
  run_step sudo rm -rf -- "$path"
}

remove_user_path() {
  local path="$1"
  if [[ ! -e "$path" && ! -L "$path" ]]; then
    printf '[KEEP] absent: %s\n' "$path"
    return 0
  fi
  if declare -F runtime_transaction_is_active >/dev/null && runtime_transaction_is_active; then
    runtime_transaction_snapshot_path "$path"
  fi
  if [[ "$INSTALL_DRY_RUN" == "1" ]]; then
    printf '[DRY-RUN] remove user path %s\n' "$path"
    return 0
  fi
  rm -rf -- "$path"
}
