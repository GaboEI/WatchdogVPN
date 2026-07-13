#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

# shellcheck source=../../lib/common.sh
. "$ROOT_DIR/lib/common.sh"
# shellcheck source=../../lib/install_files.sh
. "$ROOT_DIR/lib/install_files.sh"
# shellcheck source=../../lib/systemd.sh
. "$ROOT_DIR/lib/systemd.sh"

sudo() { "$@"; }

STUB_ACTIVE=0
STUB_MAIN_PID=0
STUB_RESTART_CALLED=0
STUB_RESTART_PID=0
systemctl() {
  case "$1" in
    is-active)
      ((STUB_ACTIVE == 1))
      ;;
    show)
      printf '%s\n' "$STUB_MAIN_PID"
      ;;
    restart)
      STUB_RESTART_CALLED=1
      STUB_MAIN_PID="$STUB_RESTART_PID"
      STUB_ACTIVE=1
      ;;
    *)
      return 0
      ;;
  esac
}

INSTALL_DRY_RUN=0
marker="$TMP_DIR/hibernating"
WATCHDOGVPN_HIBERNATE_MARKER="$marker"

# An active daemon must enter a different, nonzero process generation.
STUB_ACTIVE=1
STUB_MAIN_PID=111
STUB_RESTART_PID=222
STUB_RESTART_CALLED=0
capture_watchdogvpn_service_state >/dev/null
restart_watchdogvpn_service_after_runtime_update >/dev/null
if ((STUB_RESTART_CALLED != 1)); then
  printf 'FAIL: an active pre-update daemon must be restarted\n' >&2
  exit 1
fi
if [[ "$WATCHDOGVPN_DAEMON_PID_BEFORE_UPDATE" != "111" \
  || "$WATCHDOGVPN_DAEMON_PID_AFTER_UPDATE" != "222" ]]; then
  printf 'FAIL: daemon generation evidence was not retained\n' >&2
  exit 1
fi

# A dry run reports the lifecycle action without mutating the service or
# requiring the process generation to have changed already.
INSTALL_DRY_RUN=1
STUB_ACTIVE=1
STUB_MAIN_PID=223
STUB_RESTART_PID=224
STUB_RESTART_CALLED=0
capture_watchdogvpn_service_state >/dev/null
restart_watchdogvpn_service_after_runtime_update >/dev/null
if ((STUB_RESTART_CALLED != 0)) \
  || [[ "$STUB_MAIN_PID" != "223" ]] \
  || [[ -n "$WATCHDOGVPN_DAEMON_PID_AFTER_UPDATE" ]]; then
  printf 'FAIL: dry-run must not restart or claim a new daemon generation\n' >&2
  exit 1
fi
INSTALL_DRY_RUN=0

# A successful-looking restart that leaves the old PID must fail closed.
STUB_ACTIVE=1
STUB_MAIN_PID=333
STUB_RESTART_PID=333
STUB_RESTART_CALLED=0
capture_watchdogvpn_service_state >/dev/null
if restart_watchdogvpn_service_after_runtime_update >/dev/null 2>&1; then
  printf 'FAIL: an unchanged daemon PID must reject the update\n' >&2
  exit 1
fi

# A missing post-restart PID must also fail closed.
STUB_ACTIVE=1
STUB_MAIN_PID=444
STUB_RESTART_PID=0
STUB_RESTART_CALLED=0
capture_watchdogvpn_service_state >/dev/null
if restart_watchdogvpn_service_after_runtime_update >/dev/null 2>&1; then
  printf 'FAIL: a missing post-update daemon PID must reject the update\n' >&2
  exit 1
fi

# An inactive pre-update service has no stale imported modules. The normal
# hibernate-aware enable path owns whether it starts, so no restart is needed.
STUB_ACTIVE=0
STUB_MAIN_PID=0
STUB_RESTART_PID=555
STUB_RESTART_CALLED=0
capture_watchdogvpn_service_state >/dev/null
restart_watchdogvpn_service_after_runtime_update >/dev/null
if ((STUB_RESTART_CALLED != 0)); then
  printf 'FAIL: an inactive pre-update daemon must not be force-restarted\n' >&2
  exit 1
fi

# Panic/sleep is authoritative even if service state is inconsistent. Updating
# files must never wake or restart the daemon behind the hibernate marker.
STUB_ACTIVE=1
STUB_MAIN_PID=666
STUB_RESTART_PID=777
STUB_RESTART_CALLED=0
capture_watchdogvpn_service_state >/dev/null
: >"$marker"
restart_watchdogvpn_service_after_runtime_update >/dev/null
rm -f "$marker"
if ((STUB_RESTART_CALLED != 0)); then
  printf 'FAIL: update must not restart a hibernating daemon\n' >&2
  exit 1
fi

# Static order: capture before replacement; restart after enable and before
# the IPC smoke test that certifies the new daemon process.
capture_line="$(grep -nF 'capture_watchdogvpn_service_state' "$ROOT_DIR/update.sh" | head -n1 | cut -d: -f1)"
install_line="$(grep -nF 'install_runtime_files' "$ROOT_DIR/update.sh" | head -n1 | cut -d: -f1)"
enable_line="$(grep -nF 'enable_systemd_units' "$ROOT_DIR/update.sh" | head -n1 | cut -d: -f1)"
restart_line="$(grep -nF 'restart_watchdogvpn_service_after_runtime_update' "$ROOT_DIR/update.sh" | head -n1 | cut -d: -f1)"
smoke_line="$(grep -nF 'smoke_test_watchdogvpn_daemon' "$ROOT_DIR/update.sh" | head -n1 | cut -d: -f1)"
if ! ((capture_line < install_line && enable_line < restart_line && restart_line < smoke_line)); then
  printf 'FAIL: update daemon capture/restart/smoke ordering is unsafe\n' >&2
  exit 1
fi

printf 'update daemon restart checks passed\n'
