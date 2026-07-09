#!/usr/bin/env bash
set -euo pipefail

REPO_DIR="${WATCHDOGVPN_REPO_DIR:-$HOME/WatchdogVPN}"
BRANCH="${WATCHDOGVPN_BRANCH:-phase-21-5-proxy-route-chain-runtime}"
INSTALLED_LIB="${WATCHDOGVPN_INSTALLED_LIB:-/usr/local/lib/watchdogvpn}"
EVIDENCE_DIR="${WATCHDOGVPN_EVIDENCE_DIR:-/tmp/watchdogvpn-phase21-5-chain-evidence}"

tmp_dir="$(mktemp -d -t watchdogvpn-phase21-5-chain-XXXXXX)"
cleanup() {
  rm -rf "$tmp_dir"
}
trap cleanup EXIT

snapshot_state() {
  local prefix="$1"
  ip rule > "$tmp_dir/$prefix.ip_rule"
  ip route > "$tmp_dir/$prefix.ip_route"
  ip -6 route > "$tmp_dir/$prefix.ip6_route" 2>&1 || true
  ip -br addr > "$tmp_dir/$prefix.ip_addr"
  ss -H -ltn > "$tmp_dir/$prefix.tcp_listeners"
  pgrep -a sing-box > "$tmp_dir/$prefix.singbox_processes" 2>&1 || true
  if [[ -r /etc/resolv.conf ]]; then
    sha256sum /etc/resolv.conf > "$tmp_dir/$prefix.resolv_conf_sha256"
  else
    : > "$tmp_dir/$prefix.resolv_conf_sha256"
  fi
  sudo nft list ruleset > "$tmp_dir/$prefix.nft_ruleset" 2>&1 || true
}

assert_same() {
  local label="$1"
  local name="$2"
  if ! cmp -s "$tmp_dir/before.$name" "$tmp_dir/after.$name"; then
    echo "PHASE21_5_STATE_DRIFT_FAILED: $label changed" >&2
    diff -u "$tmp_dir/before.$name" "$tmp_dir/after.$name" >&2 || true
    exit 1
  fi
}

assert_no_watchdog_listener() {
  if ss -H -ltn | awk '{print $4}' | grep -Eq '(^|[:.])(2080|2081)$'; then
    echo "PHASE21_5_STALE_LISTENER_FAILED: local proxy listener remains" >&2
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

mkdir -p "$EVIDENCE_DIR"
evidence_file="$EVIDENCE_DIR/phase21_5_chain_installed_validation.json"

echo "== baseline =="
snapshot_state before
ip rule
ip route
sudo nft list ruleset >/dev/null 2>&1 || true

echo "== phase21.5 chain installed VM validation =="
env WATCHDOGVPN_VM_SMOKE=1 \
  WATCHDOGVPN_REPO_DIR="$INSTALLED_LIB" \
  PYTHONPATH="$INSTALLED_LIB" \
  python3 tests/vm/phase21_5_chain_installed_validation.py \
  --write-evidence "$evidence_file"

echo "== daemon logs =="
journalctl -u watchdogvpn.service -n 80 --no-pager > "$EVIDENCE_DIR/watchdogvpn-daemon-tail.log" 2>&1 || true

echo "== post state =="
snapshot_state after
ip rule
ip route

assert_same "policy rules" ip_rule
assert_same "IPv4 routes" ip_route
assert_same "IPv6 routes" ip6_route
assert_same "resolver config" resolv_conf_sha256
assert_same "nft ruleset" nft_ruleset
assert_no_watchdog_listener

echo "PHASE21_5_NO_ROUTE_RULE_DNS_FIREWALL_DRIFT_OK"
echo "PHASE21_5_NO_STALE_PROXY_LISTENERS_OK"
echo "PHASE21_5_EVIDENCE=$evidence_file"
echo "PHASE21_5_CHAIN_INSTALLED_VALIDATION_SCRIPT_OK"
