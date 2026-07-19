#!/usr/bin/env bash
set -euo pipefail

# A normal shell existence test cannot distinguish an absent path from a path
# hidden behind a parent directory the current user may not traverse. Keep that
# distinction explicit so doctor never reports a protected installed artifact
# as missing.
_doctor_path_exists() {
  local path="$1"
  [[ -e "$path" || -L "$path" ]]
}

_doctor_path_parent_searchable() {
  local path="$1"
  [[ -x "$(dirname -- "$path")" ]]
}

doctor_path_presence_state() {
  local path="$1"

  if _doctor_path_exists "$path"; then
    printf 'present\n'
  elif _doctor_path_parent_searchable "$path"; then
    printf 'absent\n'
  else
    printf 'protected\n'
  fi
}
