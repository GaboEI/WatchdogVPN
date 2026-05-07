#!/usr/bin/env bash
set -euo pipefail

field="${1:-}"

fmt_duration() {
  local total="${1:-0}" d h m s out=""
  [[ "$total" =~ ^[0-9]+$ ]] || { echo "-"; return 0; }
  d=$(( total / 86400 ))
  h=$(( (total % 86400) / 3600 ))
  m=$(( (total % 3600) / 60 ))
  s=$(( total % 60 ))
  (( d > 0 )) && out+="${d}d "
  (( h > 0 || d > 0 )) && out+="${h}h "
  (( m > 0 || h > 0 || d > 0 )) && out+="${m}m "
  out+="${s}s"
  echo "${out}"
}

public_ip() {
  for u in https://ifconfig.me https://api.ipify.org https://ipinfo.io/ip; do
    x="$(curl -4 -s --max-time 4 "$u" 2>/dev/null | tr -d '[:space:]' || true)"
    [[ "$x" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] && { echo "$x"; return 0; }
  done
  echo "-"
}

country_code() {
  local ip
  ip="$(public_ip)"
  [[ "$ip" == "-" ]] && { echo "UNK"; return 0; }
  curl -4 -s --max-time 4 "https://ipwho.is/$ip" 2>/dev/null \
    | sed -n 's/.*"country_code":"\([A-Za-z][A-Za-z]\)".*/\1/p' \
    | tr '[:lower:]' '[:upper:]' \
    | head -n1 || true
}

timer_state() {
  local unit="$1"
  local state interval
  state="$(systemctl is-active "$unit" 2>/dev/null || echo unknown)"
  interval="$(awk -F= '/^[[:space:]]*OnUnitActiveSec=/{gsub(/^[[:space:]]+|[[:space:]]+$/, "", $2); print $2}' "/etc/systemd/system/$unit" 2>/dev/null | head -n1)"
  case "$state" in
    active) state="on" ;;
    inactive|failed|dead) state="off" ;;
    *) state="?" ;;
  esac
  echo "${state} ${interval:-?}"
}

connection_age() {
  local state ts epoch now
  state="$(systemctl is-active adguardvpn.service 2>/dev/null || echo unknown)"
  [[ "$state" == "active" ]] || { echo "-"; return 0; }
  ts="$(systemctl show -p ActiveEnterTimestamp --value adguardvpn.service 2>/dev/null || true)"
  [[ -n "$ts" ]] || { echo "-"; return 0; }
  epoch="$(date -d "$ts" +%s 2>/dev/null || true)"
  [[ "$epoch" =~ ^[0-9]+$ ]] || { echo "-"; return 0; }
  now="$(date +%s)"
  fmt_duration $(( now - epoch ))
}

next_rotation() {
  local state ts epoch now
  state="$(systemctl is-active vpn-rotate.timer 2>/dev/null || echo unknown)"
  [[ "$state" == "active" ]] || { echo "-"; return 0; }
  ts="$(systemctl show -p NextElapseUSecRealtime --value vpn-rotate.timer 2>/dev/null || true)"
  [[ -n "$ts" && "$ts" != "0" ]] || { echo "-"; return 0; }
  epoch="$(date -d "$ts" +%s 2>/dev/null || true)"
  [[ "$epoch" =~ ^[0-9]+$ ]] || { echo "-"; return 0; }
  now="$(date +%s)"
  (( epoch > now )) || { echo "soon"; return 0; }
  fmt_duration $(( epoch - now ))
}

case "$field" in
  vpn)
    systemctl is-active adguardvpn.service 2>/dev/null | tr '[:lower:]' '[:upper:]'
    ;;
  tun)
    ip link show tun0 >/dev/null 2>&1 && echo UP || echo DOWN
    ;;
  location)
    sudo -n sed -n 's/^LOCATION="\?\([^"]*\)"\?/\1/p' /etc/adguardvpn.env 2>/dev/null | head -n1 || echo "-"
    ;;
  route)
    ip -4 route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="dev"){print $(i+1); exit}}' || echo "-"
    ;;
  ip)
    public_ip
    ;;
  country)
    country_code
    ;;
  age)
    connection_age
    ;;
  bypass)
    awk '!/^[[:space:]]*(#|$)/{n++} END{print n+0 " domains"}' /etc/vpn-domain-bypass.conf 2>/dev/null
    ;;
  rotate)
    timer_state vpn-rotate.timer
    ;;
  next_rotate)
    next_rotation
    ;;
  watchdog)
    timer_state vpn-watchdog.timer
    ;;
  event)
    tail -n 1 /var/log/myvpn/vpn-events.log 2>/dev/null | sed 's/^[^]]*] //' | cut -c1-26 || echo "-"
    ;;
  *)
    echo "-"
    ;;
esac
