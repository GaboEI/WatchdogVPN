#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

# shellcheck source=../../lib/runtime.sh
. "$ROOT_DIR/lib/runtime.sh"

sudo() {
  printf '%s\0' "$@" >"$TMP_DIR/sudo-argv"
  printf '{"ok":true}\n'
}

getent() {
  if [[ "$1" == "passwd" && "$2" == "phase235-user" ]]; then
    printf 'phase235-user:x:1234:4321::/home/phase235-user:/bin/bash\n'
    return 0
  fi
  return 1
}

id() {
  case "$1" in
    -u) printf '1234\n' ;;
    -g) printf '4321\n' ;;
    *) return 1 ;;
  esac
}

SUDO_USER=phase235-user
USER=stale-session-user
socket_path="$TMP_DIR/control.sock"
watchdog_status_with_refreshed_groups "$socket_path" >"$TMP_DIR/status"

python3 - "$TMP_DIR/sudo-argv" "$socket_path" <<'PY'
import sys
from pathlib import Path

argv = Path(sys.argv[1]).read_bytes().rstrip(b"\0").decode().split("\0")
expected = [
    "setpriv",
    "--reuid",
    "1234",
    "--regid",
    "4321",
    "--init-groups",
    "--",
    "env",
    "HOME=/home/phase235-user",
    "USER=phase235-user",
    "LOGNAME=phase235-user",
    f"WATCHDOGVPN_SOCKET_PATH={sys.argv[2]}",
    "/usr/local/bin/watchdog",
    "status",
    "--json",
]
if argv != expected:
    raise SystemExit(f"unexpected refreshed-group smoke command: {argv!r}")
PY

if ! grep -Fq '"ok":true' "$TMP_DIR/status"; then
  printf 'FAIL: refreshed-group smoke helper did not preserve status output\n' >&2
  exit 1
fi

printf 'install smoke refreshed-group tests passed\n'
