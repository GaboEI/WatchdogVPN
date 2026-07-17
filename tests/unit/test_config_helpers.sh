#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

# shellcheck source=../../lib/common.sh
. "$ROOT_DIR/lib/common.sh"
# shellcheck source=../../lib/install_files.sh
. "$ROOT_DIR/lib/install_files.sh"

create_owned_dir() {
  local path="$1" owner="$2" group="$3" mode="${4:-0755}"
  install -d -m "$mode" "$path"
}

create_config_if_missing() {
  local src="$1" dest="$2" mode="${3:-0644}" group="${4:-root}"
  [[ -e "$dest" ]] && return 0
  # No parent-dir creation here: the real lib/install_files.sh implementation
  # doesn't create it either (it relies on create_root_dir having already
  # run). Doing so here previously clobbered the config dir's mode back to
  # 0755 after create_root_dir had already set it to 0750, masking that
  # regression in this test.
  install -m "$mode" "$src" "$dest"
}

backup_path() {
  local path="$1" stamp backup
  [[ -e "$path" ]] || return 0
  stamp="test"
  backup="$BACKUP_ROOT$path.$stamp"
  install -d -m 0755 "$(dirname "$backup")"
  cp -a "$path" "$backup"
}

run_step() {
  if [[ "$1" == "sudo" ]]; then
    shift
  fi
  case "$1" in
    chown|chmod)
      return 0
      ;;
  esac
  "$@"
}

WATCHDOGVPN_ETC_CONFIG_DIR="$TMP_DIR/etc/watchdogvpn"
WATCHDOGVPN_CONFIG_FILE="$WATCHDOGVPN_ETC_CONFIG_DIR/config.toml"
WATCHDOGVPN_CONFIG_EXAMPLE="$WATCHDOGVPN_ETC_CONFIG_DIR/config.toml.example"
WATCHDOGVPN_REPO_CONFIG_EXAMPLE="$ROOT_DIR/examples/watchdogvpn-config.toml.example"
BACKUP_ROOT="$TMP_DIR/backups"
INSTALL_DRY_RUN=0

# shellcheck source=../../lib/config.sh
. "$ROOT_DIR/lib/config.sh"

validate_config_example "$WATCHDOGVPN_REPO_CONFIG_EXAMPLE"

install_config_defaults

[[ -d "$WATCHDOGVPN_ETC_CONFIG_DIR" ]]
[[ -f "$WATCHDOGVPN_CONFIG_FILE" ]]
[[ -f "$WATCHDOGVPN_CONFIG_EXAMPLE" ]]

# Regression guard: install_config_defaults() used to create this directory
# at 0755, while systemd/watchdogvpn.service declares
# ConfigurationDirectoryMode=0750 for it, so the daemon logged a mode-mismatch
# warning on every single start, on every install, including a fully clean
# one. install -d re-applies the mode on every run, so this must stay pinned
# to 0750 or the drift silently comes back.
config_dir_mode="$(stat -c %a "$WATCHDOGVPN_ETC_CONFIG_DIR")"
if [[ "$config_dir_mode" != "750" ]]; then
  printf 'FAIL: %s has mode %s, expected 750 to match ConfigurationDirectoryMode\n' \
    "$WATCHDOGVPN_ETC_CONFIG_DIR" "$config_dir_mode" >&2
  exit 1
fi

config_has_key language.current "$WATCHDOGVPN_CONFIG_FILE"
config_has_key backend.mode "$WATCHDOGVPN_CONFIG_FILE"
config_has_key backend.active "$WATCHDOGVPN_CONFIG_FILE"
config_has_key custom_vps.enabled "$WATCHDOGVPN_CONFIG_FILE"
config_has_key dns.profile "$WATCHDOGVPN_CONFIG_FILE"
config_has_key tui.theme "$WATCHDOGVPN_CONFIG_FILE"
config_has_key reporting.sanitize_ipv4 "$WATCHDOGVPN_CONFIG_FILE"

if config_has_key dns.missing_key "$WATCHDOGVPN_CONFIG_FILE"; then
  printf 'FAIL: config_has_key returned true for a missing key\n' >&2
  exit 1
fi

if config_has_key malformed "$WATCHDOGVPN_CONFIG_FILE"; then
  printf 'FAIL: config_has_key returned true for malformed key\n' >&2
  exit 1
fi

printf 'current = "es"\n' >>"$WATCHDOGVPN_CONFIG_FILE"
install_config_defaults
grep -Fq 'current = "es"' "$WATCHDOGVPN_CONFIG_FILE"

backup_config_file
find "$BACKUP_ROOT" -type f -path '*/etc/watchdogvpn/config.toml.*' | grep -q .

rm -rf "$BACKUP_ROOT"
cat >"$WATCHDOGVPN_CONFIG_FILE" <<'EOF'
[language]
current = "es"
custom_language_note = "keep"

[custom]
local_value = "preserve"
EOF

migrate_config_missing_keys

grep -Fq 'current = "es"' "$WATCHDOGVPN_CONFIG_FILE"
grep -Fq 'custom_language_note = "keep"' "$WATCHDOGVPN_CONFIG_FILE"
grep -Fq 'local_value = "preserve"' "$WATCHDOGVPN_CONFIG_FILE"
grep -Fq 'auto_detect = true' "$WATCHDOGVPN_CONFIG_FILE"
grep -Fq '[dns]' "$WATCHDOGVPN_CONFIG_FILE"
grep -Fq '[backend]' "$WATCHDOGVPN_CONFIG_FILE"
grep -Fq 'mode = "custom-vps"' "$WATCHDOGVPN_CONFIG_FILE"
grep -Fq 'active = "custom-vps"' "$WATCHDOGVPN_CONFIG_FILE"
grep -Fq '[custom_vps]' "$WATCHDOGVPN_CONFIG_FILE"
grep -Fq 'enabled = false' "$WATCHDOGVPN_CONFIG_FILE"
grep -Fq 'sanitize_ipv6 = true' "$WATCHDOGVPN_CONFIG_FILE"
if grep -Fq 'current = "en"' "$WATCHDOGVPN_CONFIG_FILE"; then
  printf 'FAIL: migration overwrote existing language.current\n' >&2
  exit 1
fi
find "$BACKUP_ROOT" -type f -path '*/etc/watchdogvpn/config.toml.*' | grep -q .

printf 'config helper checks passed\n'
