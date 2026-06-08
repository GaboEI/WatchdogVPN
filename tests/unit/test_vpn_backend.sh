#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SCRIPT="$ROOT_DIR/bin/vpn_backend"

tmpdir="$(mktemp -d)"
cleanup() { rm -rf "$tmpdir"; }
trap cleanup EXIT

assert_contains() {
  local haystack="$1" needle="$2"
  if [[ "$haystack" != *"$needle"* ]]; then
    printf 'Expected output to contain %q, got:\n%s\n' "$needle" "$haystack" >&2
    exit 1
  fi
}

output="$(WATCHDOGVPN_CONFIG_FILE="$tmpdir/missing.toml" "$SCRIPT" status)"
assert_contains "$output" "BACKEND=adguard"
assert_contains "$output" "IMPLEMENTED=true"
assert_contains "$output" "SUPPORTS_ROTATION=true"
assert_contains "$output" "TRUTH_INTERFACE=tun0"

cat >"$tmpdir/config.toml" <<'EOF'
[backend]
active = "adguard"
EOF

active="$(WATCHDOGVPN_CONFIG_FILE="$tmpdir/config.toml" "$SCRIPT" active)"
[[ "$active" == "adguard" ]]
WATCHDOGVPN_CONFIG_FILE="$tmpdir/config.toml" "$SCRIPT" validate

cat >"$tmpdir/config.toml" <<'EOF'
[backend]
active = "custom-vps"
EOF

set +e
unsupported_output="$(WATCHDOGVPN_CONFIG_FILE="$tmpdir/config.toml" "$SCRIPT" validate 2>&1)"
unsupported_rc=$?
set -e
if ((unsupported_rc != 65)); then
  printf 'expected unsupported backend rc 65, got %s\n%s\n' "$unsupported_rc" "$unsupported_output" >&2
  exit 1
fi
assert_contains "$unsupported_output" "unsupported backend: custom-vps"

status_output="$(WATCHDOGVPN_CONFIG_FILE="$tmpdir/config.toml" "$SCRIPT" status)"
assert_contains "$status_output" "BACKEND=custom-vps"
assert_contains "$status_output" "IMPLEMENTED=false"
assert_contains "$status_output" "SUPPORTS_ROTATION=false"
assert_contains "$status_output" "TRUTH_INTERFACE=unknown"

echo "vpn_backend unit checks passed"
