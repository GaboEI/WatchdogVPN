#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
VPNCTL="$ROOT_DIR/bin/vpnctl"
MANUAL_STATE="$ROOT_DIR/bin/vpn_manual_state"

tmpdir="$(mktemp -d)"
cleanup() { rm -rf "$tmpdir"; }
trap cleanup EXIT

make_cmd() {
  local path="$1"
  shift
  {
    printf '#!/usr/bin/env bash\n'
    printf 'set -euo pipefail\n'
    printf '%s\n' "$@"
  } > "$path"
  chmod +x "$path"
}

make_cmd "$tmpdir/sudo" \
  'exec "$@"'

make_cmd "$tmpdir/systemctl" \
  'printf "systemctl %s\n" "$*" >>"'"$tmpdir"'/systemctl.calls"' \
  'if [[ "${1:-}" == "is-active" || "${1:-}" == "is-enabled" ]]; then' \
  '  printf "unknown\n"' \
  'fi'

make_cmd "$tmpdir/ip" \
  'if [[ "${1:-}" == "route" ]]; then' \
  '  printf "1.1.1.1 via 192.0.2.1 dev wlan0 src 192.0.2.20 uid 1000\n"' \
  '  exit 0' \
  'fi' \
  'exit 1'

make_cmd "$tmpdir/getent" \
  'if [[ "${1:-}" == "hosts" ]]; then' \
  '  printf "93.184.216.34 example.com\n"' \
  '  exit 0' \
  'fi' \
  'exit 1'

make_cmd "$tmpdir/truth_down" \
  'printf "STATUS=DOWN\nTUN=DOWN\nROUTE=DEFAULT\nIP=OK\nIP_ADDR=203.0.113.10\n"'

make_cmd "$tmpdir/vpn_notify" \
  'printf "notify %s\n" "$*" >>"'"$tmpdir"'/notify.calls"'

STATE_FILE="$tmpdir/runtime-state"

cat >"$tmpdir/backend_custom" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
case "${1:-}" in
  active) printf "custom-vps\n" ;;
  validate) exit 0 ;;
  supports-rotation) printf "false\n" ;;
  service-name) printf "custom-vps.service\n" ;;
  *) exit 0 ;;
esac
EOF
chmod +x "$tmpdir/backend_custom"

run_vpnctl() {
  PATH="$tmpdir:$PATH" \
  WATCHDOGVPN_MANUAL_STATE_FILE="$STATE_FILE" \
  VPNCTL_MANUAL_STATE_BIN="$MANUAL_STATE" \
  VPNCTL_TRUTH_BIN="$tmpdir/truth_down" \
  VPNCTL_BACKEND_BIN="$tmpdir/backend_custom" \
  VPNCTL_NOTIFY_BIN="$tmpdir/vpn_notify" \
  "$VPNCTL" "$@"
}

disconnect_output="$(run_vpnctl disconnect)"
grep -Fq "VPN STATUS: OFF (manual-off)" <<< "$disconnect_output"
grep -Fq "DNS sin VPN: OK" <<< "$disconnect_output"
grep -Fq "MODE=manual-off" "$STATE_FILE"
grep -Fq "BACKEND=custom-vps" "$STATE_FILE"
grep -Fq "systemctl stop custom-vps.service" "$tmpdir/systemctl.calls"
grep -Fq "notify VPN desconectada" "$tmpdir/notify.calls"

: > "$tmpdir/systemctl.calls"
connect_output="$(run_vpnctl connect)"
grep -Fq "systemctl start custom-vps.service" "$tmpdir/systemctl.calls"
if [[ -e "$STATE_FILE" ]]; then
  printf 'FAIL: connect should clear manual-off state\n' >&2
  exit 1
fi
grep -Fq "Custom VPS iniciado" <<< "$connect_output"

# A backend that fails validate must abort before touching systemctl/state.
cat >"$tmpdir/backend_block" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
case "${1:-}" in
  active) printf "custom-vps\n" ;;
  validate)
    printf "backend custom-vps requires custom_vps.service_name\n" >&2
    exit 65
    ;;
  *) exit 65 ;;
esac
EOF
chmod +x "$tmpdir/backend_block"
: > "$tmpdir/systemctl.calls"
set +e
PATH="$tmpdir:$PATH" \
WATCHDOGVPN_MANUAL_STATE_FILE="$STATE_FILE" \
VPNCTL_MANUAL_STATE_BIN="$MANUAL_STATE" \
VPNCTL_TRUTH_BIN="$tmpdir/truth_down" \
VPNCTL_BACKEND_BIN="$tmpdir/backend_block" \
VPNCTL_NOTIFY_BIN="$tmpdir/vpn_notify" \
"$VPNCTL" connect >"$tmpdir/vpnctl-block.out" 2>&1
block_rc=$?
set -e
if ((block_rc != 65)); then
  printf 'FAIL: unsupported backend should exit 65, got %s\n' "$block_rc" >&2
  cat "$tmpdir/vpnctl-block.out" >&2
  exit 1
fi
if [[ -s "$tmpdir/systemctl.calls" ]]; then
  printf 'FAIL: unsupported backend must not touch systemd\n' >&2
  cat "$tmpdir/systemctl.calls" >&2
  exit 1
fi

# An "adguard" active backend (leftover from a pre-removal install) must be
# rejected outright, not silently treated as valid.
cat >"$tmpdir/backend_adguard" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
case "${1:-}" in
  active) printf "adguard\n" ;;
  validate)
    printf "unsupported backend: adguard\n" >&2
    printf "implemented backends: custom-vps\n" >&2
    exit 65
    ;;
  *) exit 65 ;;
esac
EOF
chmod +x "$tmpdir/backend_adguard"
set +e
PATH="$tmpdir:$PATH" \
WATCHDOGVPN_MANUAL_STATE_FILE="$STATE_FILE" \
VPNCTL_MANUAL_STATE_BIN="$MANUAL_STATE" \
VPNCTL_TRUTH_BIN="$tmpdir/truth_down" \
VPNCTL_BACKEND_BIN="$tmpdir/backend_adguard" \
VPNCTL_NOTIFY_BIN="$tmpdir/vpn_notify" \
"$VPNCTL" status >"$tmpdir/vpnctl-adguard.out" 2>&1
adguard_rc=$?
set -e
if ((adguard_rc != 65)); then
  printf 'FAIL: adguard backend should be rejected with rc 65, got %s\n' "$adguard_rc" >&2
  cat "$tmpdir/vpnctl-adguard.out" >&2
  exit 1
fi

echo "manual-off checks passed"
