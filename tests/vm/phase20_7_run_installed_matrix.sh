#!/usr/bin/env bash
set -euo pipefail

REPO_DIR="${WATCHDOGVPN_REPO_DIR:-$HOME/WatchdogVPN}"
BRANCH="${WATCHDOGVPN_BRANCH:-phase-20-lan-sharing-gateway}"
LAN_BIND_ADDRESS="${WATCHDOGVPN_LAN_BIND_ADDRESS:-192.168.0.228}"
LAN_INTERFACE="${WATCHDOGVPN_LAN_INTERFACE:-enp0s8}"
CLIENT_CIDR="${WATCHDOGVPN_CLIENT_CIDR:-192.168.0.0/24}"
TUN_INTERFACE="${WATCHDOGVPN_TUN_INTERFACE:-wdvpn-tun0}"
LAN_PROXY_SOCKS_PORT="${WATCHDOGVPN_LAN_PROXY_SOCKS_PORT:-32080}"
LAN_PROXY_HTTP_PORT="${WATCHDOGVPN_LAN_PROXY_HTTP_PORT:-32081}"
INSTALLED_LIB="${WATCHDOGVPN_INSTALLED_LIB:-/usr/local/lib/watchdogvpn}"
INSTALLED_BIN="${WATCHDOGVPN_INSTALLED_BIN:-/usr/local/bin/watchdog}"
GATEWAY_TABLE="watchdogvpn_lan_gateway"

tmp_dir="$(mktemp -d -t watchdogvpn-phase20-7-XXXXXX)"
cleanup() {
  rm -rf "$tmp_dir"
}
trap cleanup EXIT

snapshot_state() {
  local prefix="$1"
  cat /proc/sys/net/ipv4/ip_forward > "$tmp_dir/$prefix.ip_forward"
  ip rule > "$tmp_dir/$prefix.ip_rule"
  ip route > "$tmp_dir/$prefix.ip_route"
  ip -br addr > "$tmp_dir/$prefix.ip_addr"
  if [[ -r /etc/resolv.conf ]]; then
    sha256sum /etc/resolv.conf > "$tmp_dir/$prefix.resolv_conf_sha256"
  else
    : > "$tmp_dir/$prefix.resolv_conf_sha256"
  fi
  ss -H -ltn > "$tmp_dir/$prefix.tcp_listeners"
  sudo nft list table inet "$GATEWAY_TABLE" > "$tmp_dir/$prefix.gateway_table" 2>&1 || true
  sudo nft list ruleset > "$tmp_dir/$prefix.nft_ruleset" 2>&1 || true
}

assert_same() {
  local label="$1"
  local before="$tmp_dir/before.$2"
  local after="$tmp_dir/after.$2"
  if ! cmp -s "$before" "$after"; then
    echo "PHASE20_7_STATE_DRIFT_FAILED: $label changed" >&2
    diff -u "$before" "$after" >&2 || true
    exit 1
  fi
}

assert_no_listener() {
  local port="$1"
  if ss -H -ltn | awk '{print $4}' | grep -Eq "[:.]${port}$"; then
    echo "PHASE20_7_STALE_LISTENER_FAILED: TCP listener remains on port $port" >&2
    ss -H -ltn >&2
    exit 1
  fi
}

cd "$REPO_DIR"

echo "== repo =="
git fetch origin "$BRANCH"
git checkout "$BRANCH"
git pull --ff-only origin "$BRANCH"
git status --short --branch
git rev-parse HEAD "origin/$BRANCH"

echo "== install =="
./update.sh --yes

echo "== installed/source check =="
if ./doctor.sh | tee "$tmp_dir/doctor.txt"; then
  :
else
  cat "$tmp_dir/doctor.txt"
  exit 1
fi
grep -q "FAIL=0" "$tmp_dir/doctor.txt"

echo "== baseline =="
snapshot_state before
cat "$tmp_dir/before.ip_forward"
ip rule
ip route
sudo nft list table inet "$GATEWAY_TABLE" || true

echo "== phase20.4 LAN proxy matrix =="
env WATCHDOGVPN_VM_SMOKE=1 \
  WATCHDOGVPN_REPO_DIR="$INSTALLED_LIB" \
  PYTHONPATH="$INSTALLED_LIB" \
  python3 tests/vm/phase20_4_lan_proxy_validation.py \
  --bind-address "$LAN_BIND_ADDRESS" \
  --socks-port "$LAN_PROXY_SOCKS_PORT" \
  --http-port "$LAN_PROXY_HTTP_PORT" \
  --watchdog-bin "$INSTALLED_BIN"

echo "== phase20.6 LAN gateway matrix =="
sudo env WATCHDOGVPN_VM_SMOKE=1 \
  WATCHDOGVPN_REPO_DIR="$INSTALLED_LIB" \
  PYTHONPATH="$INSTALLED_LIB" \
  python3 tests/vm/phase20_6_lan_gateway_validation.py \
  --lan-interface "$LAN_INTERFACE" \
  --client-cidr "$CLIENT_CIDR" \
  --tun-interface "$TUN_INTERFACE"

echo "== post state =="
snapshot_state after
cat "$tmp_dir/after.ip_forward"
ip rule
ip route
sudo nft list table inet "$GATEWAY_TABLE" || true

assert_same "net.ipv4.ip_forward" ip_forward
assert_same "policy rules" ip_rule
assert_same "routes" ip_route
assert_same "resolver config" resolv_conf_sha256
assert_no_listener "$LAN_PROXY_SOCKS_PORT"
assert_no_listener "$LAN_PROXY_HTTP_PORT"
if sudo nft list table inet "$GATEWAY_TABLE" >/dev/null 2>&1; then
  echo "PHASE20_7_GATEWAY_TABLE_RESIDUE_FAILED: gateway nft table remains" >&2
  sudo nft list table inet "$GATEWAY_TABLE" >&2 || true
  exit 1
fi

echo "PHASE20_7_NO_STALE_PORTS_OK"
echo "PHASE20_7_NO_ROUTE_RULE_DNS_DRIFT_OK"
echo "PHASE20_7_NO_FORWARDING_FIREWALL_RESIDUE_OK"
echo "PHASE20_7_INSTALLED_MATRIX_OK"
