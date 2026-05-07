#!/usr/bin/env bash
set -euo pipefail

PROJECT_NAME="WatchdogVPN"

info() {
  printf '[INFO] %s\n' "$*"
}

ok() {
  printf '[OK] %s\n' "$*"
}

warn() {
  printf '[WARN] %s\n' "$*"
}

fail() {
  printf '[FAIL] %s\n' "$*"
}

have_cmd() {
  command -v "$1" >/dev/null 2>&1
}

repo_root() {
  local src
  src="${BASH_SOURCE[0]}"
  while [[ -L "$src" ]]; do
    src="$(readlink "$src")"
  done
  cd "$(dirname "$src")/.." && pwd
}
