#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SCRIPT="$ROOT_DIR/bin/vpnctl"

tmpdir="$(mktemp -d)"
cleanup() { rm -rf "$tmpdir"; }
trap cleanup EXIT

# WDCLI-008: vpnctl status must exit with a code that agrees with the
# STATUS word it prints, mirroring vpn_truth_check's own status_code()
# mapping (UP=0, DEGRADED=1, DOWN=2). Previously it fell through to
# whatever the last echo returned - always 0, even when STATUS=DOWN.

write_fake_truth() {
  local status="$1" tun="$2" route="$3" ip_addr="$4" truth_exit="$5"

  # Simulates a fixed vpn_truth_check: emits shell KEY=VALUE lines (the
  # format vpnctl's load_truth() parses) and exits nonzero for a
  # DEGRADED/DOWN status, same as the real script now does.
  cat > "$tmpdir/vpn_truth_check" <<EOF
#!/usr/bin/env bash
printf 'BACKEND=custom-vps\n'
printf 'INTERFACE=tun0\n'
printf 'STATUS=$status\n'
printf 'TUN=$tun\n'
printf 'ROUTE=$route\n'
printf 'IP=OK\n'
printf 'IP_ADDR=$ip_addr\n'
exit $truth_exit
EOF
  chmod +x "$tmpdir/vpn_truth_check"
}

assert_contains() {
  local haystack="$1" needle="$2"
  if [[ "$haystack" != *"$needle"* ]]; then
    printf 'Expected output to contain %q, got:\n%s\n' "$needle" "$haystack" >&2
    exit 1
  fi
}

run_case() {
  local name="$1" status="$2" tun="$3" route="$4" ip_addr="$5" truth_exit="$6" expected_exit="$7"
  local output rc

  write_fake_truth "$status" "$tun" "$route" "$ip_addr" "$truth_exit"

  set +e
  output="$(
    VPNCTL_TRUTH_BIN="$tmpdir/vpn_truth_check" \
    VPNCTL_BACKEND_BIN="$tmpdir/does-not-exist" \
    VPNCTL_MANUAL_STATE_BIN="$tmpdir/does-not-exist" \
    "$SCRIPT" status
  )"
  rc=$?
  set -e

  if (( rc != expected_exit )); then
    printf '%s: expected vpnctl status exit %s, got %s\n' "$name" "$expected_exit" "$rc" >&2
    printf 'output:\n%s\n' "$output" >&2
    exit 1
  fi
  assert_contains "$output" "STATUS: $status"
}

# truth_exit deliberately differs from expected_exit in some cases below to
# prove vpnctl computes its own exit from $STATUS, not by forwarding
# vpn_truth_check's process exit code (they're separate executables).
run_case "healthy vpn" "UP" "UP" "TUN" "198.51.100.20" 0 0
run_case "degraded vpn" "DEGRADED" "UP" "DEFAULT" "198.51.100.20" 1 1
run_case "down vpn" "DOWN" "DOWN" "UNKNOWN" "none" 2 2

# Under `set -euo pipefail`, vpnctl's own load_truth() invokes the truth
# binary via process substitution (< <(...)) - confirm a nonzero exit
# there does NOT abort vpnctl status itself (process substitutions are
# exempt from errexit propagation in Bash).
run_case "process substitution survives nonzero truth exit" "DOWN" "DOWN" "UNKNOWN" "none" 2 2

# A fresh non-interactive install intentionally has no legacy Custom VPS
# service. Status must still report daemon-first truth instead of aborting with
# the backend validator's configuration error. Mutating connect/restart paths
# continue to call validate_backend and fail closed.
cat >"$tmpdir/incomplete_backend" <<'EOF'
#!/usr/bin/env bash
case "${1:-}" in
  active) printf 'custom-vps\n' ;;
  configured) exit 1 ;;
  validate|service-name) printf 'backend custom-vps is not configured\n' >&2; exit 65 ;;
  *) exit 64 ;;
esac
EOF
chmod +x "$tmpdir/incomplete_backend"
write_fake_truth "DOWN" "DOWN" "UNKNOWN" "none" 2
set +e
incomplete_output="$(
  VPNCTL_TRUTH_BIN="$tmpdir/vpn_truth_check" \
  VPNCTL_BACKEND_BIN="$tmpdir/incomplete_backend" \
  VPNCTL_MANUAL_STATE_BIN="$tmpdir/does-not-exist" \
  "$SCRIPT" status 2>&1
)"
incomplete_rc=$?
set -e
[[ "$incomplete_rc" == "2" ]] || {
  printf 'incomplete backend status: expected truth exit 2, got %s\n' "$incomplete_rc" >&2
  exit 1
}
assert_contains "$incomplete_output" "VPN STATUS: DOWN"
assert_contains "$incomplete_output" "service: not configured"
if [[ "$incomplete_output" == *"backend custom-vps is not configured"* ]]; then
  printf 'incomplete backend status must not leak a validation abort\n' >&2
  exit 1
fi

echo "vpnctl unit checks passed"
