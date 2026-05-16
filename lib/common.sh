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

print_title() {
  local title="$1"
  printf '\n%s\n' "$title"
  printf '%*s\n' "${#title}" '' | tr ' ' '-'
}

print_section() {
  printf '\n== %s ==\n' "$1"
}

print_field() {
  printf '%-22s %s\n' "$1:" "$2"
}

yes_no_word() {
  case "${1:-0}" in
    1|yes|YES|true|TRUE) printf 'yes' ;;
    *) printf 'no' ;;
  esac
}

print_unsupported_distro() {
  fail "unsupported distro: ${DISTRO_NAME:-unknown} (${DISTRO_ID:-unknown})"
  cat <<'EOF'
WatchdogVPN currently supports Ubuntu, Debian, Arch Linux and validated
Arch-derived systems such as CachyOS when running systemd. Other Arch-derived
distributions may use the Arch adapter when their /etc/os-release metadata
declares a compatible ID_LIKE value.

Next step:
  Run ./doctor.sh to collect diagnostics, or install on a supported distro.
EOF
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
