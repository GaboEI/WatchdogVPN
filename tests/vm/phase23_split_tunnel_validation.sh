#!/usr/bin/env bash
set -uo pipefail
# Real-traffic split-tunnel validation: current/direct/block, each tested
# with an identifiable executable (a renamed copy of curl), capturing the
# active rule, process, command, return code, exit IP, and expected vs
# observed result.

echo "### TIMESTAMP=$(date -u +%Y-%m-%dT%H:%M:%SZ)"

echo "=== PHYSICAL_BASELINE ==="
PHYS_IP="$(curl -s --max-time 10 https://api.ipify.org || echo UNKNOWN)"
echo "physical_ip=$PHYS_IP"

echo "=== SETUP identifiable executable ==="
cp /usr/bin/curl ~/curl-splittunnel-probe
chmod +x ~/curl-splittunnel-probe
echo "probe_path=$HOME/curl-splittunnel-probe"

echo "=== CONNECT (VLESS, resilient) ==="
IMPORT_JSON="$(watchdog profile add --file ~/protocol-fixtures/01_VLESS_ubuntu_gabo.txt --json 2>&1)"
PROFILE_ID="$(printf '%s' "$IMPORT_JSON" | grep -o '"id"[^,]*' | head -1 | sed -E 's/.*"id"[^"]*"([^"]*)".*/\1/')"
if [[ -z "$PROFILE_ID" ]]; then
  PROFILE_ID="$(printf '%s' "$IMPORT_JSON" | grep -o 'profile already exists: [^"]*' | sed -E 's/profile already exists: //')"
fi
echo "profile_id=$PROFILE_ID"
watchdog connect "$PROFILE_ID" 2>&1 | tail -4

echo "=== ENABLE split-tunnel ==="
watchdog split-tunnel enable 2>&1

test_rule() {
  local action="$1" rule_id="$2" expected="$3"
  echo "--- RULE=$action id=$rule_id expected=$expected ---"
  watchdog split-tunnel add --process-path "$HOME/curl-splittunnel-probe" --action "$action" --id "$rule_id" 2>&1
  watchdog disconnect 2>&1 | tail -2
  watchdog connect "$PROFILE_ID" 2>&1 | tail -4
  sleep 2
  echo "watchdog_status_after_reconnect:"
  watchdog status 2>&1 | grep -E "Status:|Active profile"
  echo "probe_command: $HOME/curl-splittunnel-probe -s --max-time 10 https://api.ipify.org"
  PROBE_OUT="$("$HOME/curl-splittunnel-probe" -s --max-time 10 https://api.ipify.org)"
  PROBE_RC=$?
  echo "probe_exit_ip=$PROBE_OUT"
  echo "probe_return_code=$PROBE_RC"
  echo "physical_ip=$PHYS_IP"
  watchdog split-tunnel remove "$rule_id" 2>&1
}

test_rule current cert-current "tunnel exit IP (same as unrestricted connection)"
test_rule direct cert-direct "physical exit IP (bypasses tunnel)"
test_rule block cert-block "request fails / times out (blocked)"

echo "=== CLEANUP ==="
watchdog split-tunnel disable 2>&1
rm -f ~/curl-splittunnel-probe
watchdog disconnect 2>&1 | tail -3
sleep 2
echo "final_status:"
watchdog status 2>&1
echo "### END"
