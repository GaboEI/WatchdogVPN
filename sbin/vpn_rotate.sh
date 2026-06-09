#!/usr/bin/env bash
set -euo pipefail

# ====== CONFIG ======
CLI="/usr/local/bin/adguardvpn-cli"
AS_USER="adgvpn"
VPN_SET="/usr/local/sbin/vpn_set"
TRUTH_BIN="/usr/local/bin/vpn_truth_check"
MANUAL_STATE_BIN="${VPN_ROTATE_MANUAL_STATE_BIN:-/usr/local/bin/vpn_manual_state}"
BACKEND_BIN="${VPN_ROTATE_BACKEND_BIN:-/usr/local/bin/vpn_backend}"

STATE_DIR="/var/lib/vpn-rotate"
STATE_FILE="$STATE_DIR/state.txt"
LOCK_FILE="$STATE_DIR/lock"

LOG_FILE="/var/log/myvpn/vpn-rotate.log"
LOG_COMPONENT="rotate"

TOP_N=30
RECENT_KEEP=5
MIN_SECONDS_BETWEEN=120
MAX_ATTEMPTS_PER_RUN="${VPN_ROTATE_MAX_ATTEMPTS:-8}"
MAX_FAILS_BEFORE_ROLLBACK="${VPN_ROTATE_FAILS_BEFORE_ROLLBACK:-4}"
MAX_DEGRADED_SECONDS_BEFORE_ROLLBACK="${VPN_ROTATE_DEGRADED_ROLLBACK_SECONDS:-60}"
# ====================

FORCE="${VPN_ROTATE_FORCE:-0}"
for arg in "$@"; do
  case "$arg" in
    --force|-f)
      FORCE=1
      ;;
  esac
done

now_epoch="$(date +%s)"

if (( EUID != 0 )); then
  echo "vpn_rotate.sh debe ejecutarse como root" >&2
  exit 1
fi

log() {
  # log robusto (no rompe si /var/log no writable por algo raro)
  local msg="$*" level="INFO" event first
  case "$msg" in
    ERROR*|*_ERROR*|*ERROR*) level="ERROR" ;;
    WARN*|SKIP*|FALLBACK*|TRY_FAIL*|ROLLBACK_FAIL*|ROLLBACK_SKIP*|*FAIL*) level="WARN" ;;
  esac
  first="${msg%% *}"
  first="${first%:}"
  event="$(printf '%s' "$first" | tr '[:upper:]' '[:lower:]' | sed -E 's/[^a-z0-9]+/_/g; s/^_+|_+$//g')"
  [[ -n "$event" ]] || event="message"
  printf '%s | %s | %s | %s | %s\n' "$(date --iso-8601=seconds)" "$LOG_COMPONENT" "$level" "$event" "$msg" >> "$LOG_FILE" 2>/dev/null || true
}

manual_off_active() {
  [[ -x "$MANUAL_STATE_BIN" ]] && "$MANUAL_STATE_BIN" is-manual-off >/dev/null 2>&1
}

backend_supports_rotation() {
  if [[ -x "$BACKEND_BIN" ]]; then
    "$BACKEND_BIN" supports-rotation 2>/dev/null || printf 'true'
  else
    printf 'true'
  fi
}

# Normaliza un candidato ISO: quita ANSI/basura y deja solo [A-Z]{2}
clean_iso() {
  local raw="${1:-}"
  printf '%s' "$raw" \
    | sed -E $'s/\x1B\[[0-9;]*[[:alpha:]]//g' \
    | tr -cd '[:alpha:]' \
    | tr '[:lower:]' '[:upper:]'
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

truth_summary() {
  printf 'STATUS=%s TUN=%s ROUTE=%s IP=%s IP_ADDR=%s' \
    "${STATUS:-DOWN}" "${TUN:-DOWN}" "${ROUTE:-UNKNOWN}" "${IP:-FAIL}" "${IP_ADDR:-none}"
}

vpn_snapshot() {
  if read_truth; then
    log "SNAPSHOT $(truth_summary)"
  else
    log "SNAPSHOT truth_unavailable bin='${TRUTH_BIN}'"
  fi
}

read_env_iso() {
  local raw=""
  raw="$(sed -n 's/^LOCATION="\?\([^"]*\)"\?/\1/p' /etc/adguardvpn.env 2>/dev/null | head -n1 || true)"
  clean_iso "$raw"
}

save_state() {
  local chosen_iso="$1"
  shift || true
  local items=("$chosen_iso")
  local r recent

  for r in "$@"; do
    [[ -z "$r" ]] && continue
    [[ "$r" == "$chosen_iso" ]] && continue
    items+=("$r")
  done
  items=( "${items[@]:0:$RECENT_KEEP}" )
  recent="$(IFS=,; echo "${items[*]}")"

  printf "%s|%s|%s\n" "$(date +%s)" "$chosen_iso" "$recent" > "$STATE_FILE"
  chmod 600 "$STATE_FILE"
  log "STATE_SAVED epoch=$(date +%s) last_iso='$chosen_iso' recent='$recent'"
}

# ─────────────────────────────────────────────
# Preparar carpeta/lock
mkdir -p "$STATE_DIR"
chown root:root "$STATE_DIR"
chmod 700 "$STATE_DIR"

# Evitar ejecuciones simultáneas (timer + network + manual)
exec 9>"$LOCK_FILE"
flock -n 9 || exit 0

log "---- vpn_rotate start ----"
vpn_snapshot

if manual_off_active; then
  log "SKIP manual-off: user requested VPN off"
  log "---- vpn_rotate end manual-off ----"
  exit 0
fi

if [[ "$(backend_supports_rotation)" != "true" ]]; then
  log "SKIP backend does not support rotation"
  log "---- vpn_rotate end unsupported-backend ----"
  exit 0
fi

if [[ ! "$TOP_N" =~ ^[0-9]+$ ]] || (( TOP_N < 1 )); then
  log "ERROR: TOP_N invalido: '$TOP_N'"
  exit 1
fi
if ! [[ "$MAX_ATTEMPTS_PER_RUN" =~ ^[0-9]+$ ]] || (( MAX_ATTEMPTS_PER_RUN < 1 )); then
  log "ERROR: MAX_ATTEMPTS_PER_RUN invalido: '$MAX_ATTEMPTS_PER_RUN'"
  exit 1
fi
if ! [[ "$MAX_FAILS_BEFORE_ROLLBACK" =~ ^[0-9]+$ ]] || (( MAX_FAILS_BEFORE_ROLLBACK < 1 )); then
  log "ERROR: MAX_FAILS_BEFORE_ROLLBACK invalido: '$MAX_FAILS_BEFORE_ROLLBACK'"
  exit 1
fi
if ! [[ "$MAX_DEGRADED_SECONDS_BEFORE_ROLLBACK" =~ ^[0-9]+$ ]] || (( MAX_DEGRADED_SECONDS_BEFORE_ROLLBACK < 10 )); then
  log "ERROR: MAX_DEGRADED_SECONDS_BEFORE_ROLLBACK invalido: '$MAX_DEGRADED_SECONDS_BEFORE_ROLLBACK'"
  exit 1
fi

# ─────────────────────────────────────────────
# Leer estado: last_epoch|last_iso|recent_csv
last_epoch="0"
last_iso=""
recent_csv=""

if [[ -f "$STATE_FILE" ]]; then
  IFS="|" read -r last_epoch last_iso recent_csv < "$STATE_FILE" || true
fi

last_iso="$(clean_iso "$last_iso")"
[[ ${#last_iso} -ne 2 ]] && last_iso=""

# Limpia "recent" heredado por si tenía basura ANSI
IFS="," read -r -a recent_raw <<< "${recent_csv:-}"
recent_arr=()
for r in "${recent_raw[@]}"; do
  r="$(clean_iso "$r")"
  [[ ${#r} -eq 2 ]] && recent_arr+=("$r")
done

log "STATE last_epoch=${last_epoch:-0} last_iso='${last_iso:-}' recent='${recent_arr[*]:-}'"

rollback_iso="$last_iso"
if [[ -z "$rollback_iso" ]]; then
  rollback_iso="$(read_env_iso)"
fi
if [[ ${#rollback_iso} -eq 2 ]]; then
  log "ROLLBACK_CANDIDATE iso='$rollback_iso'"
else
  rollback_iso=""
  log "ROLLBACK_CANDIDATE none"
fi

# Anti-bucle por tiempo (basado en el estado del script, no en 'status')
if [[ "$FORCE" != "1" && "${last_epoch:-0}" =~ ^[0-9]+$ ]]; then
  delta=$(( now_epoch - last_epoch ))
  if (( delta < MIN_SECONDS_BETWEEN )); then
    log "SKIP anti-bucle: delta=${delta}s < ${MIN_SECONDS_BETWEEN}s"
    exit 0
  fi
elif [[ "$FORCE" == "1" ]]; then
  log "FORCE override: bypassing anti-bucle"
fi

# ─────────────────────────────────────────────
# Obtener top locations EXACTAMENTE como tu vpn_l, limpiando ANSI
mapfile -t top_iso < <(
  timeout 15s sudo -u "$AS_USER" -H "$CLI" list-locations 2>/dev/null \
  | sed -E $'s/\x1B\[[0-9;]*[[:alpha:]]//g' \
  | awk 'NR==1{next} {print $1}' \
  | tr -cd '[:alnum:]\n' \
  | tr '[:lower:]' '[:upper:]' \
  | awk 'length($0)==2 && $0 ~ /^[A-Z][A-Z]$/' \
  | head -n "$TOP_N"
)

if (( ${#top_iso[@]} == 0 )); then
  log "ERROR: list-locations devolvió 0 ubicaciones válidas"
  exit 1
fi

log "TOP${TOP_N} ISO: ${top_iso[*]}"

is_blocked() {
  local candidate="$1"
  [[ -n "$last_iso" && "$candidate" == "$last_iso" ]] && return 0
  for r in "${recent_arr[@]}"; do
    [[ -n "$r" && "$candidate" == "$r" ]] && return 0
  done
  return 1
}

# ─────────────────────────────────────────────
# Filtrar candidatos
candidates=()
for iso in "${top_iso[@]}"; do
  if ! is_blocked "$iso"; then
    candidates+=("$iso")
  fi
done

# Fallback si todo quedó bloqueado
if (( ${#candidates[@]} == 0 )); then
  candidates=("${top_iso[@]}")
  log "FALLBACK: todos bloqueados, usando TOP completo"
fi

# ─────────────────────────────────────────────
# Selección secuencial con validación real
if [[ ! -x "$VPN_SET" ]]; then
  log "ERROR: VPN_SET no existe o no es ejecutable: $VPN_SET"
  exit 1
fi

vpn_ready() {
  read_truth || return 1
  [[ "$STATUS" == "UP" ]] || return 1
  sleep 1
  read_truth || return 1
  [[ "$STATUS" == "UP" ]]
}

rollback_to_last_good() {
  local reason="$1"
  local iso="${rollback_iso:-}"
  local rc

  if [[ ${#iso} -ne 2 ]]; then
    log "ROLLBACK_SKIP reason='$reason' no_valid_rollback_iso"
    return 1
  fi

  log "ROLLBACK_START reason='$reason' iso='$iso'"
  set +e
  VPN_SET_NOTIFY_PENDING=0 "$VPN_SET" "$iso" >/dev/null 2>&1
  rc=$?
  set -e

  sleep 4
  if (( rc == 0 )) && vpn_ready; then
    log "ROLLBACK_OK iso='$iso' $(truth_summary)"
    save_state "$iso" "${recent_arr[@]}"
    return 0
  fi

  if read_truth; then
    log "ROLLBACK_FAIL iso='$iso' rc=$rc $(truth_summary)"
  else
    log "ROLLBACK_FAIL iso='$iso' rc=$rc truth_unavailable"
  fi
  return 1
}

chosen_iso=""
attempts=0
failures=0
rollback_attempted=0
rotation_started_epoch="$(date +%s)"

for iso in "${candidates[@]}"; do
  (( attempts >= TOP_N )) && break
  (( attempts >= MAX_ATTEMPTS_PER_RUN )) && break
  attempts=$((attempts + 1))

  log "TRY iso='$iso' attempt=${attempts}/${TOP_N} max_run=${MAX_ATTEMPTS_PER_RUN}"

  set +e
  VPN_SET_NOTIFY_PENDING=0 "$VPN_SET" "$iso" >/dev/null 2>&1
  rc=$?
  set -e

  # Dar tiempo a que tun0/ruta/IP salgan de transición antes de validar o reintentar.
  sleep 4

  if (( rc != 0 )); then
    log "TRY_FAIL iso='$iso' rc=$rc"
    vpn_snapshot
    failures=$((failures + 1))
    sleep 1
    elapsed=$(( $(date +%s) - rotation_started_epoch ))
    if (( rollback_attempted == 0 )) && (( failures >= MAX_FAILS_BEFORE_ROLLBACK || elapsed >= MAX_DEGRADED_SECONDS_BEFORE_ROLLBACK )); then
      rollback_attempted=1
      if rollback_to_last_good "failures=${failures} elapsed=${elapsed}s"; then
        log "---- vpn_rotate end rollback ----"
        exit 0
      fi
    fi
    continue
  fi

  if vpn_ready; then
    chosen_iso="$iso"
    log "TRY_OK iso='$iso' $(truth_summary)"
    vpn_snapshot
    break
  fi

  if read_truth; then
    log "TRY_FAIL iso='$iso' $(truth_summary)"
  else
    log "TRY_FAIL iso='$iso' truth_unavailable"
  fi
  vpn_snapshot
  failures=$((failures + 1))
  sleep 1
  elapsed=$(( $(date +%s) - rotation_started_epoch ))
  if (( rollback_attempted == 0 )) && (( failures >= MAX_FAILS_BEFORE_ROLLBACK || elapsed >= MAX_DEGRADED_SECONDS_BEFORE_ROLLBACK )); then
    rollback_attempted=1
    if rollback_to_last_good "failures=${failures} elapsed=${elapsed}s"; then
      log "---- vpn_rotate end rollback ----"
      exit 0
    fi
  fi
done

if [[ -z "$chosen_iso" ]]; then
  log "ERROR: ningún candidato validó conectividad real attempts=${attempts} failures=${failures}"
  if (( rollback_attempted == 0 )); then
    rollback_to_last_good "no_candidate_validated attempts=${attempts}" || true
  fi
  exit 1
fi

# ─────────────────────────────────────────────
# Guardar estado SOLO si hubo conectividad real
save_state "$chosen_iso" "${recent_arr[@]}"
log "---- vpn_rotate end ----"
