#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

paint_label() {
  :
}

fail() {
  printf 'FAIL_STUB: %s\n' "$*" >&2
  return 0
}

# shellcheck source=lib/runtime.sh
source "$ROOT_DIR/lib/runtime.sh"

MOCK_DROPINS=""
systemctl() {
  case "$*" in
    *FragmentPath*)
      echo "/etc/systemd/system/watchdogvpn.service"
      return 0
      ;;
    *ExecStart*)
      echo "/usr/local/bin/watchdogvpn-daemon"
      return 0
      ;;
    *DropInPaths*)
      printf '%s\n' "$MOCK_DROPINS"
      return 0
      ;;
    *)
      return 0
      ;;
  esac
}

case1_rc=0
MOCK_DROPINS="/usr/lib/systemd/system/service.d/10-timeout-abort.conf"
if verify_watchdogvpn_effective_unit; then
  case1_rc=0
else
  case1_rc=1
fi
if [[ "$case1_rc" -ne 0 ]]; then
  printf 'FAIL: a global package drop-in (/usr/lib/systemd/system/service.d/*) must be tolerated\n' >&2
  exit 1
fi
printf 'CASE1_OK: global package drop-in tolerated\n'

case2_rc=0
MOCK_DROPINS="/etc/systemd/system/watchdogvpn.service.d/evil.conf"
if verify_watchdogvpn_effective_unit 2>/dev/null; then
  case2_rc=0
else
  case2_rc=1
fi
if [[ "$case2_rc" -ne 1 ]]; then
  printf 'FAIL: a service-specific drop-in (watchdogvpn.service.d/*) must be rejected\n' >&2
  exit 1
fi
printf 'CASE2_OK: service-specific drop-in rejected\n'

MOCK_DROPINS="/usr/lib/systemd/system/service.d/10-timeout-abort.conf /etc/systemd/system/watchdogvpn.service.d/evil.conf"
if verify_watchdogvpn_effective_unit 2>/dev/null; then
  printf 'FAIL: mixed global+service-specific drop-ins must be rejected\n' >&2
  exit 1
fi
printf 'CASE3_OK: mixed drop-ins rejected based on the service-specific one\n'

printf 'OK: test_watchdogvpn_effective_unit_dropins\n'