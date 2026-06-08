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

  chmod +x "$tmpdir/ip" "$tmpdir/curl"
}

assert_contains() {
  local haystack="$1" needle="$2"
  if [[ "$haystack" != *"$needle"* ]]; then
    printf 'Expected output to contain %q, got:\\n%s\\n' "$needle" "$haystack" >&2
    exit 1
  fi
}

run_case() {
  local name="$1" tun="$2" route="$3" public_ip="$4" expected_status="$5" expected_exit="$6"
  local output rc json

  write_fake_commands "$tun" "$route" "$public_ip"

  output="$(PATH="$tmpdir:$PATH" "$SCRIPT" --shell)"
  assert_contains "$output" "BACKEND=adguard"
  assert_contains "$output" "INTERFACE=tun0"
  assert_contains "$output" "STATUS=$expected_status"

  set +e
  PATH="$tmpdir:$PATH" "$SCRIPT" --quiet >/dev/null
  rc=$?
  set -e
  if (( rc != expected_exit )); then
    printf '%s: expected quiet exit %s, got %s\\n' "$name" "$expected_exit" "$rc" >&2
    exit 1
  fi

  json="$(PATH="$tmpdir:$PATH" "$SCRIPT" --json)"
  assert_contains "$json" "\"backend\":\"adguard\""
  assert_contains "$json" "\"interface\":\"tun0\""
  assert_contains "$json" "\"status\":\"$expected_status\""
  assert_contains "$json" "\"exit_code\":$expected_exit"
}

run_case "healthy vpn" "UP" "TUN" "198.51.100.20" "UP" 0
run_case "tun up but default route" "UP" "DEFAULT" "198.51.100.20" "DEGRADED" 1
run_case "tun up but public ip failed" "UP" "TUN" "none" "DEGRADED" 1
run_case "tun down" "DOWN" "DEFAULT" "198.51.100.20" "DOWN" 2

echo "vpn_truth_check unit checks passed"
