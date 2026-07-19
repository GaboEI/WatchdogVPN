#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SCRIPT="$ROOT_DIR/bin/vpn_truth_check"

tmpdir="$(mktemp -d)"
cleanup() { rm -rf "$tmpdir"; }
trap cleanup EXIT

write_fake_commands() {
  local tun="$1" route="$2" public_ip="$3"

  cat > "$tmpdir/ip" <<EOF
#!/usr/bin/env bash
set -euo pipefail
case "\${1:-}" in
  link)
    if [[ "$tun" == "UP" ]]; then
      printf '9: tun0: <POINTOPOINT,NOARP,UP,LOWER_UP> mtu 1420 qdisc noqueue state UNKNOWN mode DEFAULT group default qlen 500\\n'
    else
      printf 'Device "tun0" does not exist.\\n' >&2
      exit 1
    fi
    ;;
  route)
    if [[ "$route" == "TUN" ]]; then
      printf '1.1.1.1 dev tun0 src 10.8.0.2 uid 1000\\n'
    elif [[ "$route" == "DEFAULT" ]]; then
      printf '1.1.1.1 via 192.168.1.1 dev wlan0 src 192.168.1.10 uid 1000\\n'
    else
      exit 1
    fi
    ;;
  *)
    exit 1
    ;;
esac
EOF

  cat > "$tmpdir/curl" <<EOF
#!/usr/bin/env bash
set -euo pipefail
if [[ "$public_ip" == "none" ]]; then
  exit 28
fi
printf '%s\\n' "$public_ip"
EOF

  cat > "$tmpdir/vpn_backend" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
case "${1:-}" in
  active) printf 'custom-vps\n' ;;
  truth-interface) printf 'tun0\n' ;;
  *) exit 0 ;;
esac
EOF

  chmod +x "$tmpdir/ip" "$tmpdir/curl" "$tmpdir/vpn_backend"
}

assert_contains() {
  local haystack="$1" needle="$2"
  if [[ "$haystack" != *"$needle"* ]]; then
    printf 'Expected output to contain %q, got:\\n%s\\n' "$needle" "$haystack" >&2
    exit 1
  fi
}

assert_exit() {
  local name="$1" mode="$2" expected="$3" actual="$4"
  if (( actual != expected )); then
    printf '%s (%s): expected exit %s, got %s\n' "$name" "$mode" "$expected" "$actual" >&2
    exit 1
  fi
}

run_case() {
  local name="$1" tun="$2" route="$3" public_ip="$4" expected_status="$5" expected_exit="$6"
  local output rc json

  write_fake_commands "$tun" "$route" "$public_ip"

  # WDCLI-008: every mode's real process exit code must now agree with
  # status_code($STATUS), not just --quiet - captured with set +e around
  # each call since these can legitimately exit nonzero (DEGRADED/DOWN).
  set +e
  output="$(
    PATH="$tmpdir:$PATH" \
    VPN_TRUTH_BACKEND_BIN="$tmpdir/vpn_backend" \
    VPN_TRUTH_WATCHDOG_BIN="$tmpdir/missing-watchdog" \
    "$SCRIPT" --shell
  )"
  rc=$?
  set -e
  assert_exit "$name" "--shell" "$expected_exit" "$rc"
  assert_contains "$output" "SOURCE=legacy"
  assert_contains "$output" "BACKEND=custom-vps"
  assert_contains "$output" "INTERFACE=tun0"
  assert_contains "$output" "STATUS=$expected_status"

  set +e
  PATH="$tmpdir:$PATH" \
    VPN_TRUTH_BACKEND_BIN="$tmpdir/vpn_backend" \
    VPN_TRUTH_WATCHDOG_BIN="$tmpdir/missing-watchdog" \
    "$SCRIPT" --quiet >/dev/null
  rc=$?
  set -e
  assert_exit "$name" "--quiet" "$expected_exit" "$rc"

  set +e
  json="$(
    PATH="$tmpdir:$PATH" \
    VPN_TRUTH_BACKEND_BIN="$tmpdir/vpn_backend" \
    VPN_TRUTH_WATCHDOG_BIN="$tmpdir/missing-watchdog" \
    "$SCRIPT" --json
  )"
  rc=$?
  set -e
  assert_exit "$name" "--json" "$expected_exit" "$rc"
  assert_contains "$json" '"source":"legacy"'
  assert_contains "$json" "\"backend\":\"custom-vps\""
  assert_contains "$json" "\"interface\":\"tun0\""
  assert_contains "$json" "\"status\":\"$expected_status\""
  assert_contains "$json" "\"exit_code\":$expected_exit"
}

write_fake_managed_commands() {
  local actual="$1" desired="$2" runtime_active="$3" tun_active="$4"
  local proxy_active="$5" kill_switch_consistent="$6" failure="$7"
  local interface_state="$8" public_ip="$9" artifacts_json="${10}"

  cat > "$tmpdir/watchdog" <<EOF
#!/usr/bin/env bash
set -euo pipefail
[[ "\${1:-}" == "status" && "\${2:-}" == "--json" ]] || exit 64
cat <<'JSON'
{"ok":true,"payload":{"lifecycle":{"daemon_reachable":true,"desired_state":"$desired","actual_runtime_state":"$actual","runtime_active":$runtime_active,"tun_active":$tun_active,"proxy_active":$proxy_active,"kill_switch_consistent":$kill_switch_consistent,"failure_or_degraded":$failure,"runtime_artifacts":$artifacts_json}}}
JSON
EOF

  cat > "$tmpdir/ip" <<EOF
#!/usr/bin/env bash
set -euo pipefail
if [[ "\${1:-}" == "link" && "\${2:-}" == "show" && "\${3:-}" == "wdvpn-tun0" && "$interface_state" == "UP" ]]; then
  printf '9: wdvpn-tun0: <POINTOPOINT,NOARP,UP,LOWER_UP> mtu 9000 qdisc noqueue state UNKNOWN mode DEFAULT group default qlen 500\n'
  exit 0
fi
exit 1
EOF

  cat > "$tmpdir/curl" <<EOF
#!/usr/bin/env bash
set -euo pipefail
if [[ "$public_ip" == "none" ]]; then
  exit 28
fi
printf '%s\n' "$public_ip"
EOF

  chmod +x "$tmpdir/watchdog" "$tmpdir/ip" "$tmpdir/curl"
}

run_managed_case() {
  local name="$1" actual="$2" desired="$3" runtime_active="$4" tun_active="$5"
  local proxy_active="$6" kill_switch_consistent="$7" failure="$8"
  local interface_state="$9" public_ip="${10}" artifacts_json="${11}"
  local expected_status="${12}" expected_tun="${13}" expected_route="${14}" expected_exit="${15}"
  local output rc json

  write_fake_managed_commands \
    "$actual" "$desired" "$runtime_active" "$tun_active" "$proxy_active" \
    "$kill_switch_consistent" "$failure" "$interface_state" "$public_ip" "$artifacts_json"

  set +e
  output="$(
    PATH="$tmpdir:$PATH" \
    VPN_TRUTH_BACKEND_BIN="$tmpdir/vpn_backend" \
    VPN_TRUTH_WATCHDOG_BIN="$tmpdir/watchdog" \
    "$SCRIPT" --shell
  )"
  rc=$?
  set -e

  assert_exit "$name" "--shell" "$expected_exit" "$rc"
  assert_contains "$output" "SOURCE=daemon"
  assert_contains "$output" "BACKEND=watchdogvpn"
  assert_contains "$output" "STATUS=$expected_status"
  assert_contains "$output" "TUN=$expected_tun"
  assert_contains "$output" "ROUTE=$expected_route"

  set +e
  json="$(
    PATH="$tmpdir:$PATH" \
    VPN_TRUTH_BACKEND_BIN="$tmpdir/vpn_backend" \
    VPN_TRUTH_WATCHDOG_BIN="$tmpdir/watchdog" \
    "$SCRIPT" --json
  )"
  rc=$?
  set -e
  assert_exit "$name" "--json" "$expected_exit" "$rc"
  assert_contains "$json" '"source":"daemon"'
  assert_contains "$json" '"backend":"watchdogvpn"'
  assert_contains "$json" "\"status\":\"$expected_status\""
  assert_contains "$json" "\"exit_code\":$expected_exit"
}

run_case "healthy vpn" "UP" "TUN" "198.51.100.20" "UP" 0
run_case "tun up but default route" "UP" "DEFAULT" "198.51.100.20" "DEGRADED" 1
run_case "tun up but public ip failed" "UP" "TUN" "none" "DEGRADED" 1
run_case "tun down" "DOWN" "DEFAULT" "198.51.100.20" "DOWN" 2

run_managed_case \
  "healthy managed TUN" connected on true true true true false \
  UP 198.51.100.20 \
  '["interface:wdvpn-tun0","routing:ip-rule/sing-box","owned_listener:tcp/2080"]' \
  UP UP TUN 0

run_managed_case \
  "managed TUN missing from kernel" connected on true true true true false \
  DOWN 198.51.100.20 \
  '["interface:wdvpn-tun0","routing:ip-rule/sing-box","owned_listener:tcp/2080"]' \
  DEGRADED DOWN TUN 1

run_managed_case \
  "managed kill switch inconsistent" connected on true true true false false \
  UP 198.51.100.20 \
  '["interface:wdvpn-tun0","routing:ip-rule/sing-box"]' \
  DEGRADED UP TUN 1

run_managed_case \
  "managed desired-state mismatch" connected off true true true true false \
  UP 198.51.100.20 \
  '["interface:wdvpn-tun0","routing:ip-rule/sing-box"]' \
  DEGRADED UP TUN 1

run_managed_case \
  "managed standby" standby off false false false true false \
  DOWN none '[]' \
  DOWN DOWN DEFAULT 2

run_managed_case \
  "healthy managed proxy" connected on true false true true false \
  DOWN 198.51.100.20 \
  '["owned_listener:tcp/2080","owned_process:sing-box"]' \
  UP DOWN PROXY 0

run_managed_case \
  "managed proxy without egress" connected on true false true true false \
  DOWN none \
  '["owned_listener:tcp/2080","owned_process:sing-box"]' \
  DEGRADED DOWN PROXY 1

# A reachable executable that does not return a valid daemon envelope must not
# suppress the bounded custom-vps compatibility check.
write_fake_commands "UP" "TUN" "198.51.100.20"
cat > "$tmpdir/watchdog" <<'EOF'
#!/usr/bin/env bash
printf 'not-json\n'
EOF
chmod +x "$tmpdir/watchdog"
set +e
malformed_fallback="$({
  PATH="$tmpdir:$PATH" \
  VPN_TRUTH_BACKEND_BIN="$tmpdir/vpn_backend" \
  VPN_TRUTH_WATCHDOG_BIN="$tmpdir/watchdog" \
  "$SCRIPT" --shell
} 2>/dev/null)"
malformed_fallback_rc=$?
set -e
assert_exit "malformed daemon fallback" "--shell" 0 "$malformed_fallback_rc"
assert_contains "$malformed_fallback" "SOURCE=legacy"
assert_contains "$malformed_fallback" "STATUS=UP"

echo "vpn_truth_check unit checks passed"
