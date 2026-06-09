#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
VPNCTL="$ROOT_DIR/bin/vpnctl"
MANUAL_STATE="$ROOT_DIR/bin/vpn_manual_state"
WATCHDOG="$ROOT_DIR/sbin/vpn_watchdog.sh"
DISPATCHER="$ROOT_DIR/networkmanager/dispatcher.d/99-vpn-rotate"
ROTATE="$ROOT_DIR/sbin/vpn_rotate.sh"

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
  'printf "sudo %s\n" "$*" >>"'"$tmpdir"'/sudo.calls"' \
  'if [[ "${1:-}" == "-u" ]]; then' \
  '  shift 2' \
  '  [[ "${1:-}" == "-H" ]] && shift' \
  'fi' \
  'exec "$@"'

make_cmd "$tmpdir/systemctl" \
  'printf "systemctl %s\n" "$*" >>"'"$tmpdir"'/systemctl.calls"'

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

make_cmd "$tmpdir/truth_up" \
  'printf "STATUS=UP\nTUN=UP\nROUTE=TUN\nIP=OK\nIP_ADDR=198.51.100.10\n"'

make_cmd "$tmpdir/adguardvpn-cli" \
  'case "${1:-}" in' \
  '  status) printf "VPN is disconnected\n" ;;' \
  '  disconnect) printf "disconnected\n" ;;' \
  '  *) printf "adguard %s\n" "$*" ;;' \
  'esac'

make_cmd "$tmpdir/vpn_set" \
  'printf "vpn_set %s\n" "$*" >>"'"$tmpdir"'/vpn_set.calls"'

make_cmd "$tmpdir/vpn_notify" \
  'printf "notify %s\n" "$*" >>"'"$tmpdir"'/notify.calls"'

STATE_FILE="$tmpdir/runtime-state"

run_vpnctl() {
  PATH="$tmpdir:$PATH" \
  WATCHDOGVPN_MANUAL_STATE_FILE="$STATE_FILE" \
  VPNCTL_MANUAL_STATE_BIN="$MANUAL_STATE" \
  VPNCTL_TRUTH_BIN="$tmpdir/truth_down" \
  VPNCTL_BACKEND_BIN="$ROOT_DIR/bin/vpn_backend" \
  VPNCTL_ADGUARDVPN_CLI="$tmpdir/adguardvpn-cli" \
  VPNCTL_VPN_SET="$tmpdir/vpn_set" \
  VPNCTL_NOTIFY_BIN="$tmpdir/vpn_notify" \
  "$VPNCTL" "$@"
}

disconnect_output="$(run_vpnctl disconnect)"
grep -Fq "VPN STATUS: OFF (manual-off)" <<< "$disconnect_output"
grep -Fq "DNS sin VPN: OK" <<< "$disconnect_output"
grep -Fq "MODE=manual-off" "$STATE_FILE"
grep -Fq "BACKEND=adguard" "$STATE_FILE"
grep -Fq "systemctl stop vpn-watchdog.timer vpn-rotate.timer vpn-rotate-firstboot.timer vpn-watchdog.service vpn-rotate.service" "$tmpdir/systemctl.calls"
grep -Fq "systemctl stop adguardvpn.service" "$tmpdir/systemctl.calls"
grep -Fq "notify VPN desconectada" "$tmpdir/notify.calls"

connect_output="$(run_vpnctl connect DK)"
grep -Fq "vpn_set DK" "$tmpdir/vpn_set.calls"
grep -Fq "systemctl start vpn-watchdog.timer vpn-rotate.timer" "$tmpdir/systemctl.calls"
if [[ -e "$STATE_FILE" ]]; then
  printf 'FAIL: connect should clear manual-off state\n' >&2
  exit 1
fi
grep -Fq "VPN STATUS: DOWN (REAL)" <<< "$connect_output"

cat >"$tmpdir/backend_block" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
case "${1:-}" in
  active) printf "custom-vps\n" ;;
  validate)
    printf "unsupported backend: custom-vps\n" >&2
    exit 65
    ;;
  *) exit 65 ;;
esac
EOF
chmod +x "$tmpdir/backend_block"
: > "$tmpdir/systemctl.calls"
: > "$tmpdir/vpn_set.calls"
set +e
PATH="$tmpdir:$PATH" \
WATCHDOGVPN_MANUAL_STATE_FILE="$STATE_FILE" \
VPNCTL_MANUAL_STATE_BIN="$MANUAL_STATE" \
VPNCTL_TRUTH_BIN="$tmpdir/truth_down" \
VPNCTL_BACKEND_BIN="$tmpdir/backend_block" \
VPNCTL_ADGUARDVPN_CLI="$tmpdir/adguardvpn-cli" \
VPNCTL_VPN_SET="$tmpdir/vpn_set" \
VPNCTL_NOTIFY_BIN="$tmpdir/vpn_notify" \
"$VPNCTL" connect DK >"$tmpdir/vpnctl-block.out" 2>&1
block_rc=$?
set -e
if ((block_rc != 65)); then
  printf 'FAIL: unsupported backend should exit 65, got %s\n' "$block_rc" >&2
  cat "$tmpdir/vpnctl-block.out" >&2
  exit 1
fi
if [[ -s "$tmpdir/systemctl.calls" || -s "$tmpdir/vpn_set.calls" ]]; then
  printf 'FAIL: unsupported backend must not touch automation or vpn_set\n' >&2
  cat "$tmpdir/systemctl.calls" "$tmpdir/vpn_set.calls" >&2
  exit 1
fi

make_cmd "$tmpdir/manual_on" \
  'case "${1:-}" in' \
  '  is-manual-off) exit 0 ;;' \
  '  status) printf "MODE=manual-off\nBACKEND=adguard\nREASON=user-request\nSINCE=test\n" ;;' \
  '  *) exit 0 ;;' \
  'esac'

make_cmd "$tmpdir/auth_ok" \
  'printf "AUTH=OK\nREASON=ok\nDETAIL=\n"'

make_cmd "$tmpdir/rotate_recorder" \
  'printf "rotate\n" >>"'"$tmpdir"'/rotate.calls"'

PATH="$tmpdir:$PATH" \
VPN_WATCHDOG_FORCE=1 \
VPN_WATCHDOG_MIN_RUN_GAP=0 \
VPN_WATCHDOG_LOG_FILE="$tmpdir/watchdog.log" \
VPN_WATCHDOG_LAST_RUN_FILE="$tmpdir/last_run" \
VPN_WATCHDOG_UNKNOWN_IP_COUNT_FILE="$tmpdir/unknown_count" \
VPN_WATCHDOG_AUTH_BIN="$tmpdir/auth_ok" \
VPN_WATCHDOG_TRUTH_BIN="$tmpdir/truth_down" \
VPN_WATCHDOG_ROTATE_SCRIPT="$tmpdir/rotate_recorder" \
VPN_WATCHDOG_NOTIFY_BIN="$tmpdir/missing_notify" \
VPN_WATCHDOG_MANUAL_STATE_BIN="$tmpdir/manual_on" \
bash "$WATCHDOG"

grep -Fq "SKIP manual-off" "$tmpdir/watchdog.log"
if [[ -e "$tmpdir/rotate.calls" ]]; then
  printf 'FAIL: watchdog must not rotate during manual-off\n' >&2
  exit 1
fi

: > "$tmpdir/systemctl.calls"
PATH="$tmpdir:$PATH" \
VPN_DISPATCHER_STABILIZE_SECONDS=0 \
VPN_DISPATCHER_LOG_FILE="$tmpdir/dispatcher.log" \
VPN_DISPATCHER_MANUAL_STATE_BIN="$tmpdir/manual_on" \
bash "$DISPATCHER" wlan0 up

grep -Fq "SKIP manual-off" "$tmpdir/dispatcher.log"
if [[ -s "$tmpdir/systemctl.calls" ]]; then
  printf 'FAIL: dispatcher must not start rotation during manual-off\n' >&2
  cat "$tmpdir/systemctl.calls" >&2
  exit 1
fi

grep -Fq 'MANUAL_STATE_BIN="${VPN_ROTATE_MANUAL_STATE_BIN:-/usr/local/bin/vpn_manual_state}"' "$ROTATE"
grep -Fq "SKIP manual-off: user requested VPN off" "$ROTATE"

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
: > "$tmpdir/systemctl.calls"
: > "$tmpdir/vpn_set.calls"
custom_connect_output="$(
  PATH="$tmpdir:$PATH" \
  WATCHDOGVPN_MANUAL_STATE_FILE="$STATE_FILE" \
  VPNCTL_MANUAL_STATE_BIN="$MANUAL_STATE" \
  VPNCTL_TRUTH_BIN="$tmpdir/truth_down" \
  VPNCTL_BACKEND_BIN="$tmpdir/backend_custom" \
  VPNCTL_ADGUARDVPN_CLI="$tmpdir/adguardvpn-cli" \
  VPNCTL_VPN_SET="$tmpdir/vpn_set" \
  VPNCTL_NOTIFY_BIN="$tmpdir/vpn_notify" \
  "$VPNCTL" connect
)"
grep -Fq "Custom VPS iniciado" <<< "$custom_connect_output"
grep -Fq "systemctl start vpn-watchdog.timer" "$tmpdir/systemctl.calls"
grep -Fq "systemctl start custom-vps.service" "$tmpdir/systemctl.calls"
if [[ -s "$tmpdir/vpn_set.calls" ]]; then
  printf 'FAIL: custom-vps connect must not call vpn_set\n' >&2
  cat "$tmpdir/vpn_set.calls" >&2
  exit 1
fi

: > "$tmpdir/systemctl.calls"
custom_disconnect_output="$(
  PATH="$tmpdir:$PATH" \
  WATCHDOGVPN_MANUAL_STATE_FILE="$STATE_FILE" \
  VPNCTL_MANUAL_STATE_BIN="$MANUAL_STATE" \
  VPNCTL_TRUTH_BIN="$tmpdir/truth_down" \
  VPNCTL_BACKEND_BIN="$tmpdir/backend_custom" \
  VPNCTL_ADGUARDVPN_CLI="$tmpdir/adguardvpn-cli" \
  VPNCTL_VPN_SET="$tmpdir/vpn_set" \
  VPNCTL_NOTIFY_BIN="$tmpdir/vpn_notify" \
  "$VPNCTL" disconnect
)"
grep -Fq "VPN STATUS: OFF (manual-off)" <<< "$custom_disconnect_output"
grep -Fq "systemctl stop custom-vps.service" "$tmpdir/systemctl.calls"

echo "manual-off checks passed"
