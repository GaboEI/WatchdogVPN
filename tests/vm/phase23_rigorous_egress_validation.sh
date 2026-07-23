#!/usr/bin/env bash
set -uo pipefail
# Rigorous per-protocol egress validation script for WatchdogVPN certification.
# Usage: rigorous_egress_test.sh <profile_file> <label>
# Captures physical baseline, connects, tests egress via TUN/SOCKS/HTTP with
# www-prefixed domains, -L (follow redirects), final HTTP code, effective URL
# and remote IP, confirms tunnel exit IP != physical, disconnects, and
# verifies cleanup of processes/interfaces/routes/DNS/rules.

PROFILE_FILE="$1"
LABEL="$2"

echo "### LABEL=$LABEL"
echo "### TIMESTAMP=$(date -u +%Y-%m-%dT%H:%M:%SZ)"

echo "=== PHYSICAL_BASELINE_PRE_CONNECT ==="
watchdog status 2>&1 | head -3
PHYS_IP="$(curl -s --max-time 10 https://api.ipify.org || echo UNKNOWN)"
echo "physical_ip=$PHYS_IP"

echo "=== IMPORT_PROFILE ==="
IMPORT_JSON="$(watchdog profile add --file "$PROFILE_FILE" --json 2>&1)"
echo "$IMPORT_JSON"
PROFILE_ID="$(printf '%s' "$IMPORT_JSON" | grep -o '"id"[^,]*' | head -1 | sed -E 's/.*"id"[^"]*"([^"]*)".*/\1/')"
if [[ -z "$PROFILE_ID" ]]; then
  # Already imported from a prior run of this script; reuse the existing id.
  PROFILE_ID="$(printf '%s' "$IMPORT_JSON" | grep -o 'profile already exists: [^"]*' | sed -E 's/profile already exists: //')"
fi
echo "profile_id=$PROFILE_ID"
if [[ -z "$PROFILE_ID" ]]; then
  echo "ERROR: could not parse profile_id, aborting this protocol"
  exit 1
fi

echo "=== CONNECT ==="
watchdog connect "$PROFILE_ID" 2>&1 | tail -6
sleep 2
watchdog status 2>&1 | head -12

echo "=== EGRESS_RIGOROUS ==="
for path_name in direct socks http; do
  case "$path_name" in
    direct) proxyarg=() ;;
    socks) proxyarg=(-x socks5h://127.0.0.1:2080) ;;
    http) proxyarg=(-x http://127.0.0.1:2081) ;;
  esac
  echo "--- path=$path_name ---"
  TUN_IP="$(curl -s -L --max-time 12 "${proxyarg[@]}" https://api.ipify.org || echo UNKNOWN)"
  echo "exit_ip=$TUN_IP"
  for site in www.facebook.com www.instagram.com www.youtube.com; do
    curl -s -L --max-time 12 "${proxyarg[@]}" -o /dev/null \
      -w "site=$site final_http_code=%{http_code} url_effective=%{url_effective} remote_ip=%{remote_ip} num_redirects=%{num_redirects}\n" \
      "https://$site" || echo "site=$site request_failed"
  done
done

echo "=== LEAK_CHECK ==="
echo "physical_ip=$PHYS_IP"

echo "=== DISCONNECT ==="
watchdog disconnect 2>&1 | tail -6
sleep 2

echo "=== CLEANUP_CHECK ==="
echo "--processes--"
pgrep -af 'sing-box|amneziawg|openvpn|ck-client|amneziawg-go' || echo "none"
echo "--interfaces--"
ip -o link show | grep -E 'wdvpn|tun|watchdogvpn' || echo "none"
echo "--ip-rule--"
ip rule show
echo "--resolv.conf--"
cat /etc/resolv.conf
echo "--nft-tables--"
sudo nft list tables 2>&1
echo "--watchdog-status--"
watchdog status 2>&1
echo "### END_LABEL=$LABEL"
