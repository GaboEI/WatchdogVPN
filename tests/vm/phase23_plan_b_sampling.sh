#!/usr/bin/env bash
set -uo pipefail
# Independent 0.3s-interval sampling of process/interface state during a
# WatchdogVPN connect attempt, to determine with evidence whether the
# backend never comes up (true connection-level failure) or comes up and
# then fails (a different class of problem), rather than trusting the CLI's
# own connect_failed status alone.
#
# Usage: plan_b_sampling.sh <profile_file> <label> <num_samples>
# num_samples * 0.3s = total sampling window.

PROFILE_FILE="$1"
LABEL="$2"
NUM_SAMPLES="${3:-100}"

echo "### LABEL=$LABEL"
echo "### TIMESTAMP=$(date -u +%Y-%m-%dT%H:%M:%SZ)"

echo "=== IMPORT_PROFILE ==="
IMPORT_JSON="$(watchdog profile add --file "$PROFILE_FILE" --json 2>&1)"
echo "$IMPORT_JSON"
PROFILE_ID="$(printf '%s' "$IMPORT_JSON" | grep -o '"id"[^,]*' | head -1 | sed -E 's/.*"id"[^"]*"([^"]*)".*/\1/')"
if [[ -z "$PROFILE_ID" ]]; then
  PROFILE_ID="$(printf '%s' "$IMPORT_JSON" | grep -o 'profile already exists: [^"]*' | sed -E 's/profile already exists: //')"
fi
echo "profile_id=$PROFILE_ID"

echo "=== BASELINE_BEFORE_CONNECT ==="
echo "interfaces: $(ip -o link show | awk '{print $2}' | tr '\n' ' ')"
echo "wg/openvpn processes:"; pgrep -af 'wireguard|openvpn|wg-quick' || echo none

echo "=== ISSUING_CONNECT (async, sampling starts immediately) ==="
watchdog connect "$PROFILE_ID" >/tmp/plan_b_connect_output.log 2>&1 &
CONNECT_PID=$!

for ((sample=1; sample<=NUM_SAMPLES; sample++)); do
  elapsed_ms=$((sample * 300))
  procs="$(pgrep -af 'wireguard|openvpn|wg-quick|sing-box' 2>/dev/null | tr '\n' ';')"
  ifaces="$(ip -o link show 2>/dev/null | awk '{printf "%s(%s);", $2, $9}')"
  echo "sample=$sample elapsed_ms=$elapsed_ms procs=[${procs:-none}] ifaces=[$ifaces]"
  sleep 0.3
done

wait "$CONNECT_PID" 2>/dev/null
echo "=== CONNECT_COMMAND_OUTPUT ==="
cat /tmp/plan_b_connect_output.log

echo "=== FINAL_STATUS (after sampling window) ==="
watchdog status 2>&1

echo "=== FINAL_CLEANUP_CHECK ==="
echo "processes:"; pgrep -af 'wireguard|openvpn|wg-quick' || echo none
echo "interfaces:"; ip -o link show | grep -Ei 'tun|wg|wdvpn' || echo none
echo "### END_LABEL=$LABEL"
