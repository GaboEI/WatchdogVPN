#!/usr/bin/env bash
set -euo pipefail

INSTALL_DRY_RUN="${INSTALL_DRY_RUN:-0}"
BACKUP_ROOT="${BACKUP_ROOT:-/var/backups/watchdogvpn}"

run_step() {
  if [[ "$INSTALL_DRY_RUN" == "1" ]]; then
    printf '[DRY-RUN] %s\n' "$*"
    return 0
  fi
  "$@"
}

backup_path() {
  local path="$1" stamp backup
  [[ -e "$path" ]] || return 0
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
  run_step sudo install -m "$mode" -o root -g root "$src" "$dest"
}

install_user_file() {
  local src="$1" dest="$2" mode="$3"
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
  local src="$1" dest="$2" mode="${3:-0644}"
  if [[ -e "$dest" ]]; then
    printf '[KEEP] existing config: %s\n' "$dest"
    return 0
  fi
  run_step sudo install -m "$mode" -o root -g root "$src" "$dest"
}

create_service_user() {
  local user="${1:-adgvpn}" home="${2:-/var/lib/adguardvpn}" shell
  if getent passwd "$user" >/dev/null 2>&1; then
    printf '[KEEP] service user exists: %s\n' "$user"
    create_owned_dir "$home" "$user" "$user" 0755
    return 0
  fi
  shell="/usr/sbin/nologin"
  [[ -x "$shell" ]] || shell="/usr/bin/nologin"
  [[ -x "$shell" ]] || shell="/bin/false"
  run_step sudo useradd --system --home-dir "$home" --create-home --shell "$shell" "$user"
  create_owned_dir "$home" "$user" "$user" 0755
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
  if [[ ! -e "$path" && ! -L "$path" ]]; then
    printf '[KEEP] absent: %s\n' "$path"
    return 0
  fi
  backup_path "$path"
  run_step sudo rm -rf -- "$path"
}

remove_user_path() {
  local path="$1"
  if [[ ! -e "$path" && ! -L "$path" ]]; then
    printf '[KEEP] absent: %s\n' "$path"
    return 0
  fi
  if [[ "$INSTALL_DRY_RUN" == "1" ]]; then
    printf '[DRY-RUN] remove user path %s\n' "$path"
    return 0
  fi
  rm -rf -- "$path"
}
