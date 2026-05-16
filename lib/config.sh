#!/usr/bin/env bash
set -euo pipefail

WATCHDOGVPN_CONFIG_DIR="${WATCHDOGVPN_CONFIG_DIR:-/etc/watchdogvpn}"
WATCHDOGVPN_CONFIG_FILE="${WATCHDOGVPN_CONFIG_FILE:-$WATCHDOGVPN_CONFIG_DIR/config.toml}"
WATCHDOGVPN_CONFIG_EXAMPLE="${WATCHDOGVPN_CONFIG_EXAMPLE:-$WATCHDOGVPN_CONFIG_DIR/config.toml.example}"
WATCHDOGVPN_REPO_CONFIG_EXAMPLE="${WATCHDOGVPN_REPO_CONFIG_EXAMPLE:-$ROOT_DIR/examples/watchdogvpn-config.toml.example}"

config_required_sections() {
  printf '%s\n' language timers dns tui reporting
}

validate_config_example() {
  local file="${1:-$WATCHDOGVPN_REPO_CONFIG_EXAMPLE}" section

  [[ -f "$file" ]] || {
    fail "missing config example: $file"
    return 1
  }

  for section in $(config_required_sections); do
    grep -Fq "[$section]" "$file" || {
      fail "missing config section: [$section]"
      return 1
    }
  done

  if grep -Eiq '(password|passwd|token|secret|private[_-]?key|api[_-]?key)[[:space:]]*=' "$file"; then
    fail "config example must not define secrets"
    return 1
  fi
}

install_config_defaults() {
  validate_config_example "$WATCHDOGVPN_REPO_CONFIG_EXAMPLE"
  create_root_dir "$WATCHDOGVPN_CONFIG_DIR" 0755
  create_config_if_missing "$WATCHDOGVPN_REPO_CONFIG_EXAMPLE" "$WATCHDOGVPN_CONFIG_EXAMPLE" 0644
  create_config_if_missing "$WATCHDOGVPN_REPO_CONFIG_EXAMPLE" "$WATCHDOGVPN_CONFIG_FILE" 0644
}

backup_config_file() {
  backup_path "$WATCHDOGVPN_CONFIG_FILE"
}

config_has_key() {
  local key="$1" file="${2:-$WATCHDOGVPN_CONFIG_FILE}" section name
  section="${key%%.*}"
  name="${key#*.}"

  [[ "$section" != "$key" && -n "$section" && -n "$name" ]] || return 2
  [[ -f "$file" ]] || return 1

  awk -v section="$section" -v name="$name" '
    $0 ~ "^[[:space:]]*\\[" section "\\][[:space:]]*$" {in_section=1; next}
    $0 ~ "^[[:space:]]*\\[[^]]+\\][[:space:]]*$" {in_section=0}
    in_section && $0 ~ "^[[:space:]]*" name "[[:space:]]*=" {found=1; exit}
    END {exit found ? 0 : 1}
  ' "$file"
}
