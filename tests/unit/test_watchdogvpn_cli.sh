#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SCRIPT="$ROOT_DIR/bin/watchdogvpn"
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

make_cmd() {
  local path="$1"
  shift
  {
    printf '#!/usr/bin/env bash\n'
    printf '%s\n' "$@"
  } >"$path"
  chmod +x "$path"
}

make_cmd "$TMP_DIR/truth" \
  'printf "STATUS=UP\nTUN=UP\nROUTE=TUN\nIP=OK\nIP_ADDR=198.51.100.10\n"'
make_cmd "$TMP_DIR/auth" \
  'printf "AUTH=OK\nREASON=license_valid\nDETAIL=user@example.com 203.0.113.4\n"'
make_cmd "$TMP_DIR/vpnctl" \
  'printf "VPN STATUS: UP\npublic ip: 198.51.100.10\n"'
make_cmd "$TMP_DIR/dnsctl" \
  'case "${1:-}" in current) printf "profile_guess=quad9-doh\n";; local-test) printf "OK example.com 198.51.100.20\n";; esac'

output="$(
  WATCHDOGVPN_REPORT_DIR="$TMP_DIR" \
  WATCHDOGVPN_TRUTH_BIN="$TMP_DIR/truth" \
  WATCHDOGVPN_AUTH_BIN="$TMP_DIR/auth" \
  WATCHDOGVPN_VPNCTL_BIN="$TMP_DIR/vpnctl" \
  WATCHDOGVPN_DNSCTL_BIN="$TMP_DIR/dnsctl" \
  "$SCRIPT" report
)"

report="$(printf '%s\n' "$output" | sed -n 's/^Report written: //p')"
[[ -f "$report" ]]

grep -Fq "WatchdogVPN diagnostic report" "$report"
grep -Fq "== VPN truth ==" "$report"
grep -Fq "== DNS local test ==" "$report"
grep -Fq "<redacted-email>" "$report"
grep -Fq "<redacted-ip>" "$report"
if grep -Eq '198\.51\.100|203\.0\.113|user@example\.com' "$report"; then
  printf 'FAIL: report contains unsanitized sensitive sample data\n' >&2
  exit 1
fi

"$SCRIPT" help >/dev/null
"$SCRIPT" version | grep -Fq "WatchdogVPN"

printf 'watchdogvpn CLI checks passed\n'
