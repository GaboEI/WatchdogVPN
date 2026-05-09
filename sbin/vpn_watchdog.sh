#!/usr/bin/env bash
set -euo pipefail

LOG_FILE="${VPN_WATCHDOG_LOG_FILE:-/var/log/myvpn/vpn-watchdog.log}"
LAST_RUN_FILE="${VPN_WATCHDOG_LAST_RUN_FILE:-/run/vpn-watchdog.last_run}"
MIN_RUN_GAP="${VPN_WATCHDOG_MIN_RUN_GAP:-30}"

ROTATE_SCRIPT="${VPN_WATCHDOG_ROTATE_SCRIPT:-/usr/local/sbin/vpn_rotate.sh}"
TRUTH_BIN="${VPN_WATCHDOG_TRUTH_BIN:-/usr/local/bin/vpn_truth_check}"
AUTH_BIN="${VPN_WATCHDOG_AUTH_BIN:-/usr/local/bin/vpn_auth_check}"
NOTIFY_BIN="${VPN_WATCHDOG_NOTIFY_BIN:-/usr/local/bin/vpn_notify}"
LOG_COMPONENT="watchdog"

UNKNOWN_IP_COUNT_FILE="${VPN_WATCHDOG_UNKNOWN_IP_COUNT_FILE:-/run/vpn-watchdog.unknown_ip_count}"
AUTH_NOTIFY_FILE="${VPN_WATCHDOG_AUTH_NOTIFY_FILE:-/run/vpn-watchdog.auth_notify.last}"
AUTH_NOTIFY_GAP="${VPN_WATCHDOG_AUTH_NOTIFY_GAP:-1800}"
UNKNOWN_IP_THRESHOLD="${UNKNOWN_IP_THRESHOLD:-3}"
SETTLE_SECONDS="${VPN_WATCHDOG_SETTLE_SECONDS:-6}"
FORCE="${VPN_WATCHDOG_FORCE:-0}"
for arg in "$@"; do
  case "$arg" in
    --force|-f)
      FORCE=1
      ;;
  esac
done

log() {
  local msg="$*" level="INFO" event first
  case "$msg" in
    ERROR*|*_ERROR*|*ERROR*) level="ERROR" ;;
    WARN*|SKIP*|SOFT_FAIL*|POLICY_FAIL*|REMEDIATION_FAIL*|*FAIL*) level="WARN" ;;
  esac
  first="${msg%% *}"
  first="${first%:}"
  event="$(printf '%s' "$first" | tr '[:upper:]' '[:lower:]' | sed -E 's/[^a-z0-9]+/_/g; s/^_+|_+$//g')"
  [[ -n "$event" ]] || event="message"
  printf '%s | %s | %s | %s | %s\n' "$(date --iso-8601=seconds)" "$LOG_COMPONENT" "$level" "$event" "$msg" >> "$LOG_FILE" 2>/dev/null || true
}

auth_log() {
  local msg="$*" level="INFO" event first
  case "$msg" in
    ERROR*|*_ERROR*|*ERROR*|SESSION_EXPIRED*) level="ERROR" ;;
    WARN*|AUTH_UNKNOWN*|*UNKNOWN*) level="WARN" ;;
  esac
  first="${msg%% *}"
  first="${first%:}"
  event="$(printf '%s' "$first" | tr '[:upper:]' '[:lower:]' | sed -E 's/[^a-z0-9]+/_/g; s/^_+|_+$//g')"
  [[ -n "$event" ]] || event="message"
  printf '%s | auth | %s | %s | %s\n' "$(date --iso-8601=seconds)" "$level" "$event" "$msg" >> "$LOG_FILE" 2>/dev/null || true
}

now_epoch() { date +%s; }

recently_ran() {
  local now last=0
  now="$(now_epoch)"
  [[ -f "$LAST_RUN_FILE" ]] && last="$(cat "$LAST_RUN_FILE" 2>/dev/null || echo 0)"
  [[ "$last" =~ ^[0-9]+$ ]] || last=0
  (( now - last < MIN_RUN_GAP ))
}

mark_run() {
  now_epoch > "$LAST_RUN_FILE" 2>/dev/null || true
}

read_unknown_ip_count() {
  local count=0
  [[ -f "$UNKNOWN_IP_COUNT_FILE" ]] && count="$(cat "$UNKNOWN_IP_COUNT_FILE" 2>/dev/null || echo 0)"
  [[ "$count" =~ ^[0-9]+$ ]] || count=0
  printf '%s' "$count"
}

write_unknown_ip_count() {
  printf '%s\n' "${1:-0}" > "$UNKNOWN_IP_COUNT_FILE" 2>/dev/null || true
}

reset_unknown_ip_count() {
  write_unknown_ip_count 0
}

bump_unknown_ip_count() {
  local count
  count="$(read_unknown_ip_count)"
  count=$((count + 1))
  write_unknown_ip_count "$count"
  printf '%s' "$count"
}

get_country_code() {
  local ip="$1" cc=""

  cc="$(curl -4 -fsS --max-time 4 "https://ipapi.co/${ip}/country/" 2>/dev/null || true)"
  cc="$(printf '%s' "$cc" | tr -d '[:space:]' | tr '[:lower:]' '[:upper:]')"
  if [[ "$cc" =~ ^[A-Z][A-Z]$ ]]; then
    printf '%s' "$cc"
    return 0
  fi

  cc="$(curl -4 -fsS --max-time 4 "https://ipwho.is/${ip}" 2>/dev/null \
    | sed -n 's/.*"country_code":"\([A-Za-z][A-Za-z]\)".*/\1/p' \
    | head -n1 \
    | tr '[:lower:]' '[:upper:]' || true)"
  if [[ "$cc" =~ ^[A-Z][A-Z]$ ]]; then
    printf '%s' "$cc"
    return 0
  fi

  printf 'UNK'
}

read_auth() {
  local key value

  AUTH_STATE="UNKNOWN"
  AUTH_REASON="not_checked"
  AUTH_DETAIL=""

  [[ -x "$AUTH_BIN" ]] || return 1

  while IFS='=' read -r key value; do
    case "$key" in
      AUTH)
        AUTH_STATE="$value"
        ;;
      REASON)
        AUTH_REASON="$value"
        ;;
      DETAIL)
        AUTH_DETAIL="$value"
        ;;
    esac
  done < <("$AUTH_BIN" 2>/dev/null || true)

  [[ -n "${AUTH_STATE:-}" ]]
}

notify_auth_expired() {
  local now last=0

  [[ -x "$NOTIFY_BIN" ]] || return 0

  now="$(now_epoch)"
  [[ -f "$AUTH_NOTIFY_FILE" ]] && last="$(cat "$AUTH_NOTIFY_FILE" 2>/dev/null || echo 0)"
  [[ "$last" =~ ^[0-9]+$ ]] || last=0
  (( now - last >= AUTH_NOTIFY_GAP )) || return 0

  printf '%s\n' "$now" > "$AUTH_NOTIFY_FILE" 2>/dev/null || true
  "$NOTIFY_BIN" \
    "Sesion de AdGuard VPN expirada" \
    "La recuperacion automatica esta pausada hasta que vuelvas a iniciar sesion." \
    critical >/dev/null 2>&1 || true
}

read_truth() {
  local key value

  STATUS="DOWN"
  TUN="DOWN"
  ROUTE="UNKNOWN"
  IP="FAIL"
  IP_ADDR="none"

  [[ -x "$TRUTH_BIN" ]] || return 1

  while IFS='=' read -r key value; do
    case "$key" in
      STATUS|TUN|ROUTE|IP|IP_ADDR)
        printf -v "$key" '%s' "$value"
        ;;
    esac
  done < <("$TRUTH_BIN" 2>/dev/null || true)

  [[ -n "${STATUS:-}" ]]
}

set_health_state() {
  # Return values:
  # OK, DOWN, RUSSIAN_IP, UNKNOWN_IP
  local cc

  if ! read_truth; then
    HEALTH_STATE="DOWN"
    return 0
  fi

  if [[ "$STATUS" == "DOWN" ]]; then
    HEALTH_STATE="DOWN"
    return 0
  fi

  if [[ "$STATUS" == "DEGRADED" || "$IP" != "OK" || ! "$IP_ADDR" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    HEALTH_STATE="UNKNOWN_IP"
    return 0
  fi

  cc="$(get_country_code "$IP_ADDR")"
  if [[ "$cc" == "RU" ]]; then
    HEALTH_STATE="RUSSIAN_IP"
    return 0
  fi

  HEALTH_STATE="OK"
}

run_rotate_remediation() {
  local cc

  if [[ ! -x "$ROTATE_SCRIPT" ]]; then
    log "ERROR missing executable: $ROTATE_SCRIPT"
    return 1
  fi

  log "REMEDIATION start via rotate_script='$ROTATE_SCRIPT'"

  if ! VPN_ROTATE_FORCE=1 "$ROTATE_SCRIPT"; then
    log "REMEDIATION_ERROR rotate_script_failed"
    return 1
  fi

  sleep "$SETTLE_SECONDS"
  set_health_state

  if [[ "$HEALTH_STATE" == "OK" ]]; then
    cc="UNK"
    [[ "$IP_ADDR" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] && cc="$(get_country_code "$IP_ADDR")"
    reset_unknown_ip_count
    log "SUCCESS via rotate status='${STATUS:-unknown}' ip='${IP_ADDR:-none}' country='${cc}'"
    return 0
  fi

  log "REMEDIATION_FAIL state='$HEALTH_STATE' status='${STATUS:-unknown}' ip='${IP_ADDR:-none}' after rotate"
  return 1
}

if [[ "$FORCE" != "1" ]] && recently_ran; then
  log "SKIP run: min gap ${MIN_RUN_GAP}s"
  exit 0
fi
if [[ "$FORCE" == "1" ]]; then
  log "FORCE override: bypassing min gap ${MIN_RUN_GAP}s"
fi
mark_run

if read_auth; then
  case "$AUTH_STATE" in
    EXPIRED)
      reset_unknown_ip_count
      auth_log "SESSION_EXPIRED action=user_reauth_required reason='${AUTH_REASON:-unknown}' detail='${AUTH_DETAIL:-}'"
      notify_auth_expired
      exit 0
      ;;
    UNKNOWN)
      auth_log "AUTH_UNKNOWN reason='${AUTH_REASON:-unknown}' detail='${AUTH_DETAIL:-}' -> continue health check"
      ;;
  esac
else
  auth_log "AUTH_UNKNOWN reason='helper_unavailable' bin='$AUTH_BIN' -> continue health check"
fi

set_health_state
case "$HEALTH_STATE" in
  OK)
    cc="UNK"
    [[ "$IP_ADDR" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] && cc="$(get_country_code "$IP_ADDR")"
    reset_unknown_ip_count
    log "OK status='${STATUS:-unknown}' ip='${IP_ADDR:-none}' country='${cc}'"
    exit 0
    ;;
  DOWN|RUSSIAN_IP)
    reset_unknown_ip_count
    log "POLICY_FAIL state='$HEALTH_STATE' -> start remediation"
    if run_rotate_remediation; then
      exit 0
    fi
    exit 0
    ;;
  UNKNOWN_IP)
    unknown_ip_count="$(bump_unknown_ip_count)"
    log "SOFT_FAIL state='UNKNOWN_IP' count=${unknown_ip_count}/${UNKNOWN_IP_THRESHOLD}"
    if (( unknown_ip_count < UNKNOWN_IP_THRESHOLD )); then
      exit 0
    fi
    log "POLICY_FAIL state='UNKNOWN_IP' threshold_reached=${unknown_ip_count}/${UNKNOWN_IP_THRESHOLD} -> start remediation"
    if run_rotate_remediation; then
      exit 0
    fi
    exit 0
    ;;
esac

exit 0
