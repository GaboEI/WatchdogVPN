#!/usr/bin/env bash
set -euo pipefail

CONF_FILE="/etc/vpn-domain-bypass.conf"
STATE_FILE="/run/vpn-domain-bypass.priorities"
LOG_FILE="/var/log/vpn-domain-bypass.log"
LOG_COMPONENT="domain_bypass"
BASE_PRIO="${BASE_PRIO:-30760}"
MAX_RULES="${MAX_RULES:-512}"
VPN_LOOKUP_TABLE="${VPN_LOOKUP_TABLE:-880}"
VPN_FALLBACK_PRIO="${VPN_FALLBACK_PRIO:-32000}"
DNS_TIMEOUT="${DNS_TIMEOUT:-4}"
MIN_IPS_FOR_REPLACE="${MIN_IPS_FOR_REPLACE:-20}"

if (( EUID != 0 )); then
  echo "vpn_domain_bypass_apply.sh debe ejecutarse como root" >&2
  exit 1
fi

log() {
  local msg="$*" level="INFO" event first
  case "$msg" in
    ERROR*|*_ERROR*|*ERROR*) level="ERROR" ;;
    WARN*|SKIP*|*FAIL*) level="WARN" ;;
  esac
  first="${msg%% *}"
  first="${first%:}"
  event="$(printf '%s' "$first" | tr '[:upper:]' '[:lower:]' | sed -E 's/[^a-z0-9]+/_/g; s/^_+|_+$//g')"
  [[ -n "$event" ]] || event="message"
  printf '%s | %s | %s | %s | %s\n' "$(date --iso-8601=seconds)" "$LOG_COMPONENT" "$level" "$event" "$msg" >> "$LOG_FILE" 2>/dev/null || true
}

mapfile -t old_state < <(cat "$STATE_FILE" 2>/dev/null || true)

clear_old_rules() {
  local entry fam prio
  for entry in "${old_state[@]}"; do
    fam="${entry%%:*}"
    prio="${entry#*:}"
    [[ "$prio" =~ ^[0-9]+$ ]] || continue
    if [[ "$fam" == "6" ]]; then
      while ip -6 rule del priority "$prio" >/dev/null 2>&1; do :; done
    else
      while ip rule del priority "$prio" >/dev/null 2>&1; do :; done
    fi
  done
  : > "$STATE_FILE"
}

is_ipv4() {
  local ip="$1"
  [[ "$ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]
}

is_ipv6() {
  local ip="$1"
  [[ "$ip" == *:* ]]
}

if [[ ! -f "$CONF_FILE" ]]; then
  clear_old_rules
  log "WARN: missing conf $CONF_FILE (rules cleared)"
  ip route flush cache
  exit 0
fi

mapfile -t domains < <(awk '!/^[[:space:]]*(#|$)/ {print tolower($1)}' "$CONF_FILE" | sort -u)
if (( ${#domains[@]} == 0 )); then
  clear_old_rules
  log "WARN: no domains in $CONF_FILE (rules cleared)"
  ip route flush cache
  exit 0
fi

declare -A ips4=()
declare -A ips6=()
for d in "${domains[@]}"; do
  q="$d"
  [[ "$q" == \*.* ]] && q="${q#*.}"
  while read -r ip _; do
    if is_ipv4 "$ip"; then
      ips4["$ip"]=1
    elif is_ipv6 "$ip"; then
      ips6["$ip"]=1
    fi
  done < <(timeout "$DNS_TIMEOUT" getent ahosts "$q" 2>/dev/null || true)
done

if (( ${#ips4[@]} == 0 && ${#ips6[@]} == 0 )); then
  log "WARN: DNS returned 0 IP addresses (keeping previous rules)"
  ip route flush cache || true
  ip -6 route flush cache || true
  exit 0
fi

resolved_total=$(( ${#ips4[@]} + ${#ips6[@]} ))
if (( ${#old_state[@]} > 0 && resolved_total < MIN_IPS_FOR_REPLACE )); then
  log "WARN: DNS returned only ${resolved_total} IPs below MIN_IPS_FOR_REPLACE=${MIN_IPS_FOR_REPLACE} (keeping previous rules)"
  ip route flush cache || true
  ip -6 route flush cache || true
  exit 0
fi

clear_old_rules

prio="$BASE_PRIO"
count=0
for ip in $(printf '%s\n' "${!ips4[@]}" | sort -V); do
  if (( count >= MAX_RULES )); then
    break
  fi
  if ip rule add priority "$prio" to "$ip/32" lookup main >/dev/null 2>&1; then
    printf '4:%s\n' "$prio" >> "$STATE_FILE"
    count=$((count + 1))
    prio=$((prio + 1))
  fi
done

for ip in $(printf '%s\n' "${!ips6[@]}" | sort -V); do
  if (( count >= MAX_RULES )); then
    break
  fi
  if ip -6 rule add priority "$prio" to "$ip/128" lookup main >/dev/null 2>&1; then
    printf '6:%s\n' "$prio" >> "$STATE_FILE"
    count=$((count + 1))
    prio=$((prio + 1))
  fi
done

# Keep the VPN catch-all rule after all bypass rules so it cannot shadow them.
while read -r old_prio; do
  [[ -n "$old_prio" ]] || continue
  [[ "$old_prio" == "$VPN_FALLBACK_PRIO" ]] && continue
  while ip rule del priority "$old_prio" >/dev/null 2>&1; do :; done
done < <(ip rule show | awk -v table="$VPN_LOOKUP_TABLE" '$0 ~ ("lookup " table "$") {sub(/:$/, "", $1); print $1}')

while ip rule del priority "$VPN_FALLBACK_PRIO" >/dev/null 2>&1; do :; done
ip rule add priority "$VPN_FALLBACK_PRIO" lookup "$VPN_LOOKUP_TABLE" >/dev/null 2>&1 || true

ip route flush cache || true
ip -6 route flush cache || true
log "APPLIED domains=${#domains[@]} ips4=${#ips4[@]} ips6=${#ips6[@]} rules=$count base_prio=$BASE_PRIO vpn_fallback_prio=$VPN_FALLBACK_PRIO"
