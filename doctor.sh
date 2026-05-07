#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# shellcheck source=lib/common.sh
. "$ROOT_DIR/lib/common.sh"
# shellcheck source=lib/distro.sh
. "$ROOT_DIR/lib/distro.sh"
# shellcheck source=lib/packages.sh
. "$ROOT_DIR/lib/packages.sh"

FAIL_COUNT=0
WARN_COUNT=0

mark_fail() {
  fail "$*"
  FAIL_COUNT=$((FAIL_COUNT + 1))
}

mark_warn() {
  warn "$*"
  WARN_COUNT=$((WARN_COUNT + 1))
}

check_command() {
  local cmd="$1"
  if have_cmd "$cmd"; then
    ok "command: $cmd"
  else
    mark_fail "missing command: $cmd"
  fi
}

printf '%s - Doctor\n\n' "$PROJECT_NAME"

detect_distro
info "distro: $DISTRO_NAME ($DISTRO_ID)"

if [[ "${DISTRO_SUPPORTED:-0}" == "1" ]]; then
  ok "distro supported"
  adapter="$(distro_adapter_path "$ROOT_DIR")"
  if [[ -r "$adapter" ]]; then
    # shellcheck disable=SC1090
    . "$adapter"
    ok "distro adapter: distros/$DISTRO_ID.sh"
  else
    mark_fail "missing distro adapter: $adapter"
  fi
elif [[ "${DISTRO_FUTURE:-0}" == "1" ]]; then
  mark_fail "Fedora support is planned for a future release"
else
  mark_fail "unsupported distro for initial release"
fi

if [[ "$(ps -p 1 -o comm= 2>/dev/null || true)" == "systemd" ]]; then
  ok "init: systemd"
else
  mark_fail "systemd is required"
fi

for cmd in $(required_commands); do
  check_command "$cmd"
done

if systemctl list-unit-files NetworkManager.service >/dev/null 2>&1; then
  ok "NetworkManager service known"
else
  mark_fail "NetworkManager service not found"
fi

if have_cmd adguardvpn-cli || [[ -x /usr/local/bin/adguardvpn-cli ]]; then
  ok "adguardvpn-cli detected"
else
  mark_fail "adguardvpn-cli not detected"
fi

if [[ -x "$ROOT_DIR/bin/vpn_auth_check" ]]; then
  ok "repo helper: vpn_auth_check"
else
  mark_fail "repo helper missing: bin/vpn_auth_check"
fi

if [[ -x "$ROOT_DIR/bin/vpn_truth_check" ]]; then
  ok "repo helper: vpn_truth_check"
else
  mark_fail "repo helper missing: bin/vpn_truth_check"
fi

for cmd in $(optional_commands); do
  if have_cmd "$cmd"; then
    ok "optional command: $cmd"
  else
    mark_warn "optional command missing: $cmd"
  fi
done

printf '\nResult: '
if (( FAIL_COUNT > 0 )); then
  printf 'FAIL (%d fail, %d warn)\n' "$FAIL_COUNT" "$WARN_COUNT"
  exit 1
fi

if (( WARN_COUNT > 0 )); then
  printf 'WARN (%d warn)\n' "$WARN_COUNT"
  exit 0
fi

printf 'OK\n'
