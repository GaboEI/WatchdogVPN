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

# Minimum Python (3.MINOR) WatchdogVPN's runtime requires. The real floor is
# 3.10: dataclass(slots=True), used pervasively across the whole codebase
# (core/, dns/, rules/, drivers/, daemon/, etc.), was added in 3.10. Several
# distros' default `python3` predate this: openSUSE Leap 15.x ships 3.6 (also
# too old for `from __future__ import annotations`, which only needs 3.7+),
# and RHEL9-family (RHEL/CentOS/Rocky/AlmaLinux) ships 3.9 as its platform
# Python - new enough for `__future__ import annotations` but still one
# minor version short of slots=True, which silently raised
# "dataclass() got an unexpected keyword argument 'slots'" at daemon startup
# before this floor was corrected to 10. Instead of assuming the system
# `python3` is new enough (and instead of retargeting the OS default, which
# system tools depend on), the resolver below selects a modern interpreter
# the adapter has provided.
WATCHDOGVPN_MIN_PYTHON_MINOR="${WATCHDOGVPN_MIN_PYTHON_MINOR:-10}"

_watchdogvpn_python_ok() {
  command -v "$1" >/dev/null 2>&1 || return 1
  "$1" -c "import sys; sys.exit(0 if sys.version_info[:2] >= (3, ${WATCHDOGVPN_MIN_PYTHON_MINOR}) else 1)" \
    >/dev/null 2>&1
}

# Resolve the Python interpreter WatchdogVPN should use, printing its absolute
# path. Resolution order: an explicit WATCHDOGVPN_PYTHON override, then the
# DISTRO_PYTHON the loaded distro adapter declares (openSUSE pins python3.11),
# then the system `python3` when it already meets the minimum (so Arch/Fedora/
# Debian/Ubuntu behaviour is unchanged), then the newest available python3.X.
# The result is cached per process. Returns non-zero when no adequate
# interpreter exists (for example before the adapter has installed one).
watchdogvpn_python() {
  if [[ -n "${_WATCHDOGVPN_PYTHON_RESOLVED:-}" ]]; then
    printf '%s\n' "$_WATCHDOGVPN_PYTHON_RESOLVED"
    return 0
  fi
  local cand
  for cand in "${WATCHDOGVPN_PYTHON:-}" "${DISTRO_PYTHON:-}" python3 \
    python3.14 python3.13 python3.12 python3.11 python3.10; do
    [[ -n "$cand" ]] || continue
    if _watchdogvpn_python_ok "$cand"; then
      _WATCHDOGVPN_PYTHON_RESOLVED="$(command -v "$cand")"
      printf '%s\n' "$_WATCHDOGVPN_PYTHON_RESOLVED"
      return 0
    fi
  done
  return 1
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
WatchdogVPN currently supports Ubuntu, Debian, Arch Linux, explicit
Fedora/Red Hat-family IDs, explicit openSUSE IDs and validated Arch-derived
systems such as CachyOS when running systemd. Other Arch-derived distributions
may use the Arch adapter when their /etc/os-release metadata declares a
compatible ID_LIKE value.

Next step:
  Run ./doctor.sh to collect diagnostics, or install on a supported distro.
EOF
}

print_future_distro() {
  fail "distro support is planned for a future release: ${DISTRO_NAME:-unknown} (${DISTRO_ID:-unknown})"
  cat <<'EOF'
This distribution is recognized but is not yet supported by this release of
WatchdogVPN. Support status may change once certification evidence is
completed.

Next step:
  Run ./doctor.sh for the current readiness report, or check the compatibility
  matrix in the project documentation.
EOF
}

print_undetermined_distro() {
  fail "distro support cannot be determined: ${DISTRO_NAME:-unknown} (${DISTRO_ID:-unknown})"
  cat <<'EOF'
WatchdogVPN could not load its compatibility engine. The distribution could not
be classified. Ensure python3 is available and the manifest
compat/compatibility.json is intact.

Next step:
  Install python3 and run ./doctor.sh again.
EOF
}

have_cmd() {
  local command_name="$1" candidate search_path
  local search_paths="${WATCHDOGVPN_COMMAND_PATHS:-/usr/local/sbin:/usr/sbin:/sbin}"

  command -v "$command_name" >/dev/null 2>&1 && return 0

  # Some supported distributions keep administrative binaries out of an
  # unprivileged user's PATH. Debian fresh installs, for example, expose
  # logrotate, useradd, openvpn, sysctl, nft and iptables under /usr/sbin.
  # Installer/doctor checks must validate system capability rather than the
  # caller's interactive PATH shape.
  IFS=: read -r -a search_path <<<"$search_paths"
  for candidate in "${search_path[@]}"; do
    candidate="${candidate%/}/$command_name"
    [[ -x "$candidate" ]] && return 0
  done

  return 1
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
