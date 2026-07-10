#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SYSCTL_FILE="$ROOT_DIR/etc/sysctl.d/99-watchdogvpn.conf"
RUNTIME_LIB="$ROOT_DIR/lib/runtime.sh"
DRIVER="$ROOT_DIR/drivers/amneziawg_driver.py"

fail() {
  printf 'FAIL: %s\n' "$*" >&2
  exit 1
}

assert_contains() {
  local file="$1" pattern="$2" message="$3"
  grep -Fq "$pattern" "$file" || fail "$message"
}

[[ -f "$SYSCTL_FILE" ]] || fail "missing sysctl defaults file: $SYSCTL_FILE"
assert_contains "$SYSCTL_FILE" "net.ipv4.conf.all.src_valid_mark = 1" \
  "sysctl defaults must enable src_valid_mark for fwmark policy routing"
assert_contains "$SYSCTL_FILE" "net.ipv4.conf.default.src_valid_mark = 1" \
  "sysctl defaults must also set conf.default so newly created interfaces inherit it (all alone is not reliable)"

assert_contains "$RUNTIME_LIB" "install_sysctl_defaults" \
  "install_runtime_files must call install_sysctl_defaults"
assert_contains "$RUNTIME_LIB" "install_root_file \"\$ROOT_DIR/etc/sysctl.d/99-watchdogvpn.conf\" /etc/sysctl.d/99-watchdogvpn.conf" \
  "install_sysctl_defaults must install the tracked sysctl.d file"
assert_contains "$RUNTIME_LIB" "sudo sysctl -q -p /etc/sysctl.d/99-watchdogvpn.conf" \
  "install_sysctl_defaults must apply the sysctl file at install/update time"

# The daemon runs under ProtectKernelTunables=true and cannot write kernel
# tunables itself (see systemd/watchdogvpn.service); the driver must only
# ever read this value at connect time, never try to set it live.
if grep -Fq '"sysctl"' "$DRIVER"; then
  fail "AmneziaWGDriver must not shell out to sysctl; ProtectKernelTunables=true blocks it at runtime"
fi
assert_contains "$DRIVER" "_src_valid_mark_path" \
  "AmneziaWGDriver must read the interface's own src_valid_mark tunable instead of writing it"

printf 'amneziawg sysctl defaults checks passed\n'
