#!/usr/bin/env bash
set -euo pipefail

REPO_DIR="${WATCHDOGVPN_REPO_DIR:-$HOME/WatchdogVPN}"
BRANCH="${WATCHDOGVPN_BRANCH:-phase-20-lan-sharing-gateway}"
LAN_INTERFACE="${WATCHDOGVPN_LAN_INTERFACE:-enp0s8}"
CLIENT_CIDR="${WATCHDOGVPN_CLIENT_CIDR:-192.168.0.0/24}"
TUN_INTERFACE="${WATCHDOGVPN_TUN_INTERFACE:-wdvpn-tun0}"

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
if watchdog doctor --json >/tmp/watchdogvpn-phase20-6-doctor.json; then
  python3 -m json.tool /tmp/watchdogvpn-phase20-6-doctor.json | sed -n '1,160p'
else
  cat /tmp/watchdogvpn-phase20-6-doctor.json
  exit 1
fi

echo "== pre state =="
cat /proc/sys/net/ipv4/ip_forward
sudo nft list table inet watchdogvpn_lan_gateway || true
ip rule
ip route

echo "== phase20.6 gateway validation =="
sudo env WATCHDOGVPN_VM_SMOKE=1 \
  PYTHONPATH=/usr/local/lib/watchdogvpn \
  python3 tests/vm/phase20_6_lan_gateway_validation.py \
  --lan-interface "$LAN_INTERFACE" \
  --client-cidr "$CLIENT_CIDR" \
  --tun-interface "$TUN_INTERFACE"

echo "== post state =="
cat /proc/sys/net/ipv4/ip_forward
sudo nft list table inet watchdogvpn_lan_gateway || true
ip rule
ip route

echo "PHASE20_6_INSTALLED_VALIDATION_SCRIPT_OK"
