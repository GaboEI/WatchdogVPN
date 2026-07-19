#!/usr/bin/env bash
set -euo pipefail

PROJECT_NAME="WatchdogVPN"

supports_color() {
  [[ -t 1 && -z "${NO_COLOR:-}" ]]
}

paint_label() {
  local code="$1" text="$2"
  if supports_color; then
    printf '\033[%sm%s\033[0m' "$code" "$text"
  else
    printf '%s' "$text"
  fi
}

info() {
  printf '[INFO] %s\n' "$*"
}

ok() {
  paint_label 32 '[OK]'
  printf ' %s\n' "$*"
}

warn() {
  paint_label 33 '[WARN]'
  printf ' %s\n' "$*"
}

fail() {
  paint_label 31 '[FAIL]'
  printf ' %s\n' "$*"
}

print_installer_failure_recovery() {
  local rc="${1:-1}" operation="${2:-operation}" backup_root="${BACKUP_ROOT:-/var/backups/watchdogvpn}"

  {
    printf '\n== Failure recovery ==\n'
    printf '[FAIL] %s failed with exit code %s.\n' "$operation" "$rc"
    printf 'User configuration, runtime state and logs are preserved by default:\n'
    printf '  /etc/watchdogvpn/\n'
    printf '  /etc/vpn-domain-bypass.conf\n'
    printf '  /var/lib/watchdogvpn/\n'
    printf '  /var/log/myvpn/\n'
    printf 'Product-managed files are backed up before replacement/removal when possible:\n'
    printf '  %s\n' "$backup_root"
    printf 'Next steps:\n'
    printf '  1. Review the error immediately above this block.\n'
    printf '  2. Run ./doctor.sh to inspect installed/source skew, PATH, services and legacy artifacts.\n'
    printf '  3. After fixing the reported issue, rerun ./update.sh or ./install.sh.\n'
  } >&2
}

install_failure_trap() {
  local rc=$?
  trap - ERR
  print_installer_failure_recovery "$rc" "${1:-installer operation}"
  exit "$rc"
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

init_process_name() {
  local name=""
  [[ -r /proc/1/comm ]] || return 1
  IFS= read -r name </proc/1/comm || true
  [[ -n "$name" ]] || return 1
  printf '%s\n' "$name"
}

verify_sha256() {
  local file="$1" expected="$2" actual
  actual="$(sha256sum "$file" | awk '{print $1}')"
  [[ "$actual" == "$expected" ]]
}

repo_root() {
  local src
  src="${BASH_SOURCE[0]}"
  while [[ -L "$src" ]]; do
    src="$(readlink "$src")"
  done
  cd "$(dirname "$src")/.." && pwd
}
