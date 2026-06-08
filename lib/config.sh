#!/usr/bin/env bash
set -euo pipefail

WATCHDOGVPN_CONFIG_DIR="${WATCHDOGVPN_CONFIG_DIR:-/etc/watchdogvpn}"
WATCHDOGVPN_CONFIG_FILE="${WATCHDOGVPN_CONFIG_FILE:-$WATCHDOGVPN_CONFIG_DIR/config.toml}"
WATCHDOGVPN_CONFIG_EXAMPLE="${WATCHDOGVPN_CONFIG_EXAMPLE:-$WATCHDOGVPN_CONFIG_DIR/config.toml.example}"
WATCHDOGVPN_REPO_CONFIG_EXAMPLE="${WATCHDOGVPN_REPO_CONFIG_EXAMPLE:-$ROOT_DIR/examples/watchdogvpn-config.toml.example}"

config_required_sections() {
  printf '%s\n' backend language timers dns tui reporting
}

config_section_exists() {
  local section="$1" file="${2:-$WATCHDOGVPN_CONFIG_FILE}"
  [[ -f "$file" ]] || return 1
  grep -Eq "^[[:space:]]*\\[$section\\][[:space:]]*$" "$file"
}

config_section_defaults() {
  local section="$1" file="${2:-$WATCHDOGVPN_REPO_CONFIG_EXAMPLE}"
  awk -v section="$section" '
    $0 ~ "^[[:space:]]*\\[" section "\\][[:space:]]*$" {in_section=1; next}
    $0 ~ "^[[:space:]]*\\[[^]]+\\][[:space:]]*$" {if (in_section) exit}
    in_section && $0 ~ "^[[:space:]]*[A-Za-z0-9_.-]+[[:space:]]*=" {print}
  ' "$file"
}

config_key_name() {
  local line="$1" key
  key="${line%%=*}"
  key="${key#"${key%%[![:space:]]*}"}"
  key="${key%"${key##*[![:space:]]}"}"
  printf '%s\n' "$key"
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
  migrate_config_missing_keys
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

insert_config_line() {
  local file="$1" section="$2" line="$3" tmp
  tmp="$(mktemp)"
  awk -v section="$section" -v line="$line" '
    $0 ~ "^[[:space:]]*\\[" section "\\][[:space:]]*$" {
      in_section=1
      print
      next
    }
    $0 ~ "^[[:space:]]*\\[[^]]+\\][[:space:]]*$" && in_section && !inserted {
      print line
      inserted=1
      in_section=0
    }
    {print}
    END {
      if (in_section && !inserted) {
        print line
      }
    }
  ' "$file" >"$tmp"
  mv "$tmp" "$file"
}

replace_config_file() {
  local src="$1"
  if [[ "${INSTALL_DRY_RUN:-0}" == "1" ]]; then
    printf '[DRY-RUN] migrate missing config keys in %s\n' "$WATCHDOGVPN_CONFIG_FILE"
    return 0
  fi

  if [[ -w "$WATCHDOGVPN_CONFIG_FILE" ]]; then
    install -m 0644 "$src" "$WATCHDOGVPN_CONFIG_FILE"
    return 0
  fi

  run_step sudo install -m 0644 -o root -g root "$src" "$WATCHDOGVPN_CONFIG_FILE"
}

migrate_config_missing_keys() {
  local section line key work changed=0

  validate_config_example "$WATCHDOGVPN_REPO_CONFIG_EXAMPLE"
  [[ -f "$WATCHDOGVPN_CONFIG_FILE" ]] || return 0

  work="$(mktemp)"
  cp -a "$WATCHDOGVPN_CONFIG_FILE" "$work"

  for section in $(config_required_sections); do
    if ! config_section_exists "$section" "$work"; then
      {
        printf '\n[%s]\n' "$section"
        config_section_defaults "$section"
      } >>"$work"
      changed=1
      continue
    fi

    while IFS= read -r line; do
      [[ -n "$line" ]] || continue
      key="$(config_key_name "$line")"
      if ! config_has_key "$section.$key" "$work"; then
        insert_config_line "$work" "$section" "$line"
        changed=1
      fi
    done < <(config_section_defaults "$section")
  done

  if ((changed == 0)); then
    rm -f "$work"
    return 0
  fi

  backup_config_file
  replace_config_file "$work"
  rm -f "$work"
}
