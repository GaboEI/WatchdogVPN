#!/usr/bin/env bash
set -u
set -o pipefail

VERSION="2026-04-29.1"
BASE_DIR="${VPN_STRESS_BASE_DIR:-$HOME/vpn-stress-runs}"
DURATION_RAW="4h"
MODE="normal"
EVENTS=0
DISRUPTIVE=0

TRUTH_BIN="/usr/local/bin/vpn_truth_check"
ROTATE_SCRIPT="/usr/local/sbin/vpn_rotate.sh"
WATCHDOG_SCRIPT="/usr/local/sbin/vpn_watchdog.sh"
BYPASS_SCRIPT="/usr/local/sbin/vpn_domain_bypass_apply.sh"
TUI_BIN="${VPN_TUI_BIN:-$HOME/.local/bin/VPN}"

DNS_DOMAINS=(
  "google.com"
  "www.google.com"
  "gemini.google.com"
  "notebooklm.google.com"
  "notion.so"
  "www.notion.so"
  "youtube.com"
  "www.youtube.com"
  "chatgpt.com"
  "ifconfig.me"
  "ipinfo.io"
  "connectivity-check.ubuntu.com"
  "avito.ru"
  "ozon.ru"
  "market.yandex.ru"
)

HTTP_URLS=(
  "https://www.google.com/generate_204"
  "https://gemini.google.com/"
  "https://notebooklm.google.com/"
  "https://www.youtube.com/generate_204"
  "https://www.notion.so/"
  "https://chatgpt.com/"
  "https://ifconfig.me/ip"
  "https://ipinfo.io/json"
  "https://connectivity-check.ubuntu.com/"
)

usage() {
  cat <<USAGE
vpn_stress_test.sh [options]

Options:
  --duration 4h|240m|14400s   Total runtime. Default: 4h
  --mode normal|aggressive    Load profile. Default: normal
  --events                    Run controlled VPN events: bypass, watchdog, rotate
  --disruptive                Also stop adguardvpn.service once to test recovery
  --base-dir PATH             Output directory. Default: $HOME/vpn-stress-runs
  -h, --help                  Show help

This test writes logs only. It does not change persistent config.
When events are enabled, sudo is used with -n. If no sudo ticket exists, events are skipped and logged.
USAGE
}

parse_duration_seconds() {
  local value="$1"
  case "$value" in
    *h) echo $(( ${value%h} * 3600 )) ;;
    *m) echo $(( ${value%m} * 60 )) ;;
    *s) echo "${value%s}" ;;
    *) echo "$value" ;;
  esac
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --duration)
      DURATION_RAW="${2:-}"
      shift 2
      ;;
    --mode)
      MODE="${2:-}"
      shift 2
      ;;
    --events)
      EVENTS=1
      shift
      ;;
    --disruptive)
      EVENTS=1
      DISRUPTIVE=1
      shift
      ;;
    --base-dir)
      BASE_DIR="${2:-}"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown option: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

if [[ "$MODE" != "normal" && "$MODE" != "aggressive" ]]; then
  echo "Invalid mode: $MODE" >&2
  exit 2
fi

DURATION_SECONDS="$(parse_duration_seconds "$DURATION_RAW")"
if ! [[ "$DURATION_SECONDS" =~ ^[0-9]+$ ]] || (( DURATION_SECONDS < 60 )); then
  echo "Invalid duration: $DURATION_RAW" >&2
  exit 2
fi

case "$MODE" in
  normal)
    MONITOR_INTERVAL=15
    DNS_INTERVAL=20
    HTTP_INTERVAL=30
    SYSTEM_INTERVAL=60
    ;;
  aggressive)
    MONITOR_INTERVAL=8
    DNS_INTERVAL=10
    HTTP_INTERVAL=15
    SYSTEM_INTERVAL=45
    ;;
esac

RUN_ID="$(date '+%Y%m%d-%H%M%S')"
RUN_DIR="$BASE_DIR/$RUN_ID"
mkdir -p "$RUN_DIR"

EVENTS_LOG="$RUN_DIR/events.log"
TRUTH_LOG="$RUN_DIR/truth.log"
DNS_LOG="$RUN_DIR/dns.log"
HTTP_LOG="$RUN_DIR/http.log"
SYSTEM_LOG="$RUN_DIR/system.log"
COMMAND_LOG="$RUN_DIR/commands.log"
SUMMARY="$RUN_DIR/summary.txt"

LOCK_FILE="/tmp/vpn-stress-test.lock"
exec 9>"$LOCK_FILE"
if ! flock -n 9; then
  echo "Another vpn_stress_test.sh is already running." >&2
  exit 1
fi

START_EPOCH="$(date +%s)"
END_EPOCH=$(( START_EPOCH + DURATION_SECONDS ))
STOP_FILE="$RUN_DIR/STOP"
SUDO_KEEPALIVE_PID=""
CHILD_PIDS=()

ts() {
  date '+%Y-%m-%d %H:%M:%S'
}

log_event() {
  printf '[%s] %s\n' "$(ts)" "$*" | tee -a "$EVENTS_LOG"
}

append_cmd() {
  local label="$1"
  local timeout_s="$2"
  local rc
  shift 2
  {
    printf '[%s] CMD %s: %s\n' "$(ts)" "$label" "$*"
    timeout "${timeout_s}s" "$@" 2>&1
    rc=$?
    printf '[%s] END %s rc=%s\n\n' "$(ts)" "$label" "$rc"
  } >> "$COMMAND_LOG"
}

sudo_available() {
  sudo -n -v >/dev/null 2>&1
}

start_sudo_keepalive() {
  if sudo_available; then
    (
      while [[ ! -e "$STOP_FILE" ]]; do
        sudo -n -v >/dev/null 2>&1 || true
        sleep 45
      done
    ) &
    SUDO_KEEPALIVE_PID="$!"
    log_event "sudo keepalive started pid=$SUDO_KEEPALIVE_PID"
  else
    log_event "sudo ticket unavailable; sudo events will be skipped"
  fi
}

write_metadata() {
  {
    echo "vpn_stress_test version: $VERSION"
    echo "run_id: $RUN_ID"
    echo "mode: $MODE"
    echo "duration_raw: $DURATION_RAW"
    echo "duration_seconds: $DURATION_SECONDS"
    echo "events: $EVENTS"
    echo "disruptive: $DISRUPTIVE"
    echo "start: $(date -Is)"
    echo
    echo "uname:"
    uname -a
    echo
    echo "resolv.conf:"
    sed -n '1,80p' /etc/resolv.conf 2>&1
    echo
    echo "active units:"
    systemctl is-active adguardvpn.service vpn-rotate.timer vpn-watchdog.timer vpn-domain-bypass.timer 2>&1
    echo
    echo "enabled units:"
    systemctl is-enabled adguardvpn.service vpn-rotate.timer vpn-watchdog.timer vpn-domain-bypass.timer 2>&1
    echo
    if git -C "$(pwd)" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
      echo
      echo "git repo:"
      git -C "$(pwd)" rev-parse --short HEAD 2>&1
    fi
  } > "$RUN_DIR/metadata.txt"
}

monitor_loop() {
  while (( "$(date +%s)" < END_EPOCH )) && [[ ! -e "$STOP_FILE" ]]; do
    {
      printf '[%s] SNAPSHOT\n' "$(ts)"
      timeout 8s "$TRUTH_BIN" 2>&1 | sed 's/^/truth: /'
      timeout 5s ip link show tun0 2>&1 | sed 's/^/link: /'
      timeout 5s ip route get 1.1.1.1 2>&1 | sed 's/^/route4: /'
      timeout 5s ip -6 route get 2606:4700:4700::1111 2>&1 | sed 's/^/route6: /'
      echo
    } >> "$TRUTH_LOG"
    sleep "$MONITOR_INTERVAL"
  done
}

dns_loop() {
  local domain raw rc count ips status
  while (( "$(date +%s)" < END_EPOCH )) && [[ ! -e "$STOP_FILE" ]]; do
    for domain in "${DNS_DOMAINS[@]}"; do
      raw="$(timeout 8s getent ahostsv4 "$domain" 2>&1)"
      rc=$?
      ips="$(printf '%s\n' "$raw" | awk '{print $1}' | grep -E '^[0-9]+\.' | sort -u | paste -sd, -)"
      count=0
      [[ -n "$ips" ]] && count="$(printf '%s\n' "$ips" | tr ',' '\n' | wc -l)"
      status="OK"
      if (( rc != 0 || count == 0 )); then
        status="FAIL"
      fi
      printf '[%s] %s domain=%s rc=%s count=%s ips=%s raw=%q\n' "$(ts)" "$status" "$domain" "$rc" "$count" "${ips:-none}" "$raw" >> "$DNS_LOG"
    done
    sleep "$DNS_INTERVAL"
  done
}

http_loop() {
  local url raw rc status
  while (( "$(date +%s)" < END_EPOCH )) && [[ ! -e "$STOP_FILE" ]]; do
    for url in "${HTTP_URLS[@]}"; do
      raw="$(timeout 18s curl -4 -L -sS -o /dev/null \
        --connect-timeout 6 \
        --max-time 15 \
        -w 'code=%{http_code} remote_ip=%{remote_ip} time=%{time_total} size=%{size_download}' \
        "$url" 2>&1)"
      rc=$?
      status="OK"
      if (( rc != 0 )); then
        status="FAIL"
      fi
      printf '[%s] %s url=%s rc=%s %s\n' "$(ts)" "$status" "$url" "$rc" "$raw" >> "$HTTP_LOG"
    done
    sleep "$HTTP_INTERVAL"
  done
}

system_loop() {
  while (( "$(date +%s)" < END_EPOCH )) && [[ ! -e "$STOP_FILE" ]]; do
    {
      printf '[%s] SYSTEM\n' "$(ts)"
      timeout 8s systemctl is-active adguardvpn.service vpn-rotate.timer vpn-watchdog.timer vpn-domain-bypass.timer 2>&1 | sed 's/^/active: /'
      timeout 8s systemctl list-timers --all 'vpn-*' 'adguard*' 2>&1 | sed 's/^/timer: /'
      timeout 8s python3 -m py_compile "$TUI_BIN" 2>&1 | sed 's/^/tui: /'
      echo
    } >> "$SYSTEM_LOG"

    sleep "$SYSTEM_INTERVAL"
  done
}

wait_until_or_stop() {
  local target="$1"
  while (( "$(date +%s)" < target )) && (( "$(date +%s)" < END_EPOCH )) && [[ ! -e "$STOP_FILE" ]]; do
    sleep 2
  done
}

run_sudo_event() {
  local label="$1"
  local timeout_s="$2"
  local rc
  shift 2
  if ! sudo_available; then
    log_event "SKIP $label: sudo ticket unavailable"
    return 0
  fi
  log_event "START $label"
  {
    printf '[%s] EVENT %s\n' "$(ts)" "$label"
    timeout "${timeout_s}s" sudo -n "$@" 2>&1
    rc=$?
    printf '[%s] EVENT_END %s rc=%s\n\n' "$(ts)" "$label" "$rc"
  } >> "$COMMAND_LOG"
  log_event "END $label"
}

events_loop() {
  local next_bypass next_watchdog next_rotate disruptive_done now second_disruptive_done
  next_bypass=$(( START_EPOCH + 300 ))
  next_watchdog=$(( START_EPOCH + 600 ))
  next_rotate=$(( START_EPOCH + 1200 ))
  disruptive_done=0
  second_disruptive_done=0

  while (( "$(date +%s)" < END_EPOCH )) && [[ ! -e "$STOP_FILE" ]]; do
    now="$(date +%s)"

    if (( now >= next_bypass )); then
      run_sudo_event "domain-bypass-apply" 90 "$BYPASS_SCRIPT"
      next_bypass=$(( now + 900 ))
    fi

    if (( now >= next_watchdog )); then
      run_sudo_event "watchdog-force" 120 env VPN_WATCHDOG_FORCE=1 "$WATCHDOG_SCRIPT"
      next_watchdog=$(( now + 1200 ))
    fi

    if (( now >= next_rotate )); then
      run_sudo_event "rotate-force" 180 env VPN_ROTATE_FORCE=1 "$ROTATE_SCRIPT"
      next_rotate=$(( now + 1800 ))
    fi

    if (( DISRUPTIVE == 1 && disruptive_done == 0 && now >= START_EPOCH + DURATION_SECONDS / 3 )); then
      run_sudo_event "controlled-vpn-stop-for-watchdog-recovery" 30 systemctl stop adguardvpn.service
      disruptive_done=1
      log_event "watching recovery after controlled stop"
    fi

    if (( DISRUPTIVE == 1 && second_disruptive_done == 0 && DURATION_SECONDS >= 10800 && now >= START_EPOCH + (DURATION_SECONDS * 2 / 3) )); then
      run_sudo_event "controlled-watchdog-service-force" 120 env VPN_WATCHDOG_FORCE=1 "$WATCHDOG_SCRIPT"
      second_disruptive_done=1
    fi

    sleep 5
  done
}

generate_summary() {
  local end_iso
  end_iso="$(date -Is)"
  {
    echo "VPN stress test summary"
    echo "run_dir: $RUN_DIR"
    echo "version: $VERSION"
    echo "mode: $MODE"
    echo "events: $EVENTS"
    echo "disruptive: $DISRUPTIVE"
    echo "start_epoch: $START_EPOCH"
    echo "end: $end_iso"
    echo
    echo "Counts:"
    printf 'dns_failures: '
    grep -c ' FAIL domain=' "$DNS_LOG" 2>/dev/null || true
    printf 'http_failures: '
    grep -c ' FAIL url=' "$HTTP_LOG" 2>/dev/null || true
    printf 'events_started: '
    grep -c 'START ' "$EVENTS_LOG" 2>/dev/null || true
    printf 'events_skipped: '
    grep -c 'SKIP ' "$EVENTS_LOG" 2>/dev/null || true
    echo
    echo "Last truth snapshot:"
    tail -n 30 "$TRUTH_LOG" 2>/dev/null || true
    echo
    echo "Last HTTP failures:"
    grep ' FAIL url=' "$HTTP_LOG" 2>/dev/null | tail -n 20 || true
    echo
    echo "Last DNS failures:"
    grep ' FAIL domain=' "$DNS_LOG" 2>/dev/null | tail -n 20 || true
    echo
  } > "$SUMMARY"
}

cleanup() {
  touch "$STOP_FILE" 2>/dev/null || true
  for pid in "${CHILD_PIDS[@]}"; do
    kill "$pid" >/dev/null 2>&1 || true
  done
  if [[ -n "$SUDO_KEEPALIVE_PID" ]]; then
    kill "$SUDO_KEEPALIVE_PID" >/dev/null 2>&1 || true
  fi
  generate_summary
  log_event "finished; summary=$SUMMARY"
}

trap cleanup EXIT INT TERM

write_metadata
log_event "started run_dir=$RUN_DIR mode=$MODE duration=$DURATION_RAW events=$EVENTS disruptive=$DISRUPTIVE"
start_sudo_keepalive
append_cmd "initial-truth" 10 "$TRUTH_BIN"
append_cmd "initial-status" 10 systemctl status adguardvpn.service vpn-rotate.timer vpn-watchdog.timer vpn-domain-bypass.timer --no-pager -n 12

monitor_loop &
CHILD_PIDS+=("$!")
dns_loop &
CHILD_PIDS+=("$!")
http_loop &
CHILD_PIDS+=("$!")
system_loop &
CHILD_PIDS+=("$!")

if (( EVENTS == 1 )); then
  events_loop &
  CHILD_PIDS+=("$!")
fi

while (( "$(date +%s)" < END_EPOCH )) && [[ ! -e "$STOP_FILE" ]]; do
  sleep 10
done

exit 0
