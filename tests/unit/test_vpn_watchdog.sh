#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SCRIPT="$ROOT_DIR/sbin/vpn_watchdog.sh"

tmpdir="$(mktemp -d)"
cleanup() { rm -rf "$tmpdir"; }
trap cleanup EXIT

make_common_helpers() {
  cat > "$tmpdir/auth_ok" <<'EOF'
#!/usr/bin/env bash
printf 'AUTH=OK\nREASON=ok\nDETAIL=\n'
EOF

  cat > "$tmpdir/curl" <<'EOF'
#!/usr/bin/env bash
printf 'DE\n'
EOF

  chmod +x "$tmpdir/auth_ok" "$tmpdir/curl"
}

write_truth() {
  local status="$1" tun="$2" route="$3" ip="$4" ip_addr="$5"
  cat > "$tmpdir/truth" <<EOF
#!/usr/bin/env bash
printf 'STATUS=%s\\n' "$status"
printf 'TUN=%s\\n' "$tun"
printf 'ROUTE=%s\\n' "$route"
printf 'IP=%s\\n' "$ip"
printf 'IP_ADDR=%s\\n' "$ip_addr"
EOF
  chmod +x "$tmpdir/truth"
}

write_rotate_recorder() {
  cat > "$tmpdir/rotate" <<EOF
#!/usr/bin/env bash
printf 'rotate\\n' >> "$tmpdir/rotate.calls"
exit 0
EOF
  chmod +x "$tmpdir/rotate"
}

run_watchdog() {
  PATH="$tmpdir:$PATH" \
  VPN_WATCHDOG_FORCE=1 \
  VPN_WATCHDOG_MIN_RUN_GAP=0 \
  VPN_WATCHDOG_SETTLE_SECONDS=0 \
  VPN_WATCHDOG_LOG_FILE="$tmpdir/watchdog.log" \
  VPN_WATCHDOG_LAST_RUN_FILE="$tmpdir/last_run" \
  VPN_WATCHDOG_UNKNOWN_IP_COUNT_FILE="$tmpdir/unknown_count" \
  VPN_WATCHDOG_AUTH_NOTIFY_FILE="$tmpdir/auth_notify" \
  VPN_WATCHDOG_TRUTH_BIN="$tmpdir/truth" \
  VPN_WATCHDOG_AUTH_BIN="$tmpdir/auth_ok" \
  VPN_WATCHDOG_ROTATE_SCRIPT="$tmpdir/rotate" \
  VPN_WATCHDOG_NOTIFY_BIN="$tmpdir/missing_notify" \
  UNKNOWN_IP_THRESHOLD=2 \
  bash "$SCRIPT"
}

assert_no_rotate() {
  if [[ -s "$tmpdir/rotate.calls" ]]; then
    printf 'Expected no rotate calls, got:\\n%s\\n' "$(cat "$tmpdir/rotate.calls")" >&2
    exit 1
  fi
}

assert_rotate_count() {
  local expected="$1" actual=0
  [[ -f "$tmpdir/rotate.calls" ]] && actual="$(wc -l < "$tmpdir/rotate.calls" | tr -d ' ')"
  if [[ "$actual" != "$expected" ]]; then
    printf 'Expected %s rotate call(s), got %s\\n' "$expected" "$actual" >&2
    [[ -f "$tmpdir/watchdog.log" ]] && cat "$tmpdir/watchdog.log" >&2
    exit 1
  fi
}

make_common_helpers
write_rotate_recorder

write_truth "UP" "UP" "TUN" "OK" "198.51.100.10"
run_watchdog
assert_no_rotate
grep -q "OK status='UP'" "$tmpdir/watchdog.log"

: > "$tmpdir/watchdog.log"
: > "$tmpdir/rotate.calls"
write_truth "DOWN" "DOWN" "DEFAULT" "FAIL" "none"
run_watchdog
assert_rotate_count 1
grep -q "POLICY_FAIL state='DOWN'" "$tmpdir/watchdog.log"

: > "$tmpdir/watchdog.log"
: > "$tmpdir/rotate.calls"
rm -f "$tmpdir/unknown_count"
write_truth "DEGRADED" "UP" "TUN" "FAIL" "none"
run_watchdog
assert_no_rotate
grep -q "SOFT_FAIL state='UNKNOWN_IP' count=1/2" "$tmpdir/watchdog.log"
run_watchdog
assert_rotate_count 1
grep -q "POLICY_FAIL state='UNKNOWN_IP' threshold_reached=2/2" "$tmpdir/watchdog.log"

echo "vpn_watchdog unit checks passed"
