#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

# shellcheck source=../../lib/common.sh
. "$ROOT_DIR/lib/common.sh"
# shellcheck source=../../lib/install_files.sh
. "$ROOT_DIR/lib/install_files.sh"
# shellcheck source=../../lib/systemd.sh
. "$ROOT_DIR/lib/systemd.sh"
# shellcheck source=../../lib/uninstall_safety.sh
. "$ROOT_DIR/lib/uninstall_safety.sh"

sudo() { "$@"; }
INSTALL_DRY_RUN=0

SYSTEMCTL_MODE="stop-fails"
systemctl() {
  case "$1" in
    show)
      printf 'loaded\n'
      ;;
    is-active)
      return 1
      ;;
    disable)
      [[ "$SYSTEMCTL_MODE" != "stop-fails" ]]
      ;;
    daemon-reload|restart|stop)
      return 0
      ;;
    *)
      return 0
      ;;
  esac
}

# A failed service stop is a hard barrier: callers must not continue into
# destructive file removal and therefore retain all rescue commands.
if stop_watchdogvpn_for_uninstall >/dev/null 2>&1; then
  printf 'FAIL: failed watchdogvpn stop was accepted\n' >&2
  exit 1
fi

# A present nftables table that cannot be removed is also a hard barrier.
nft() {
  case "$1 $2 $3" in
    'list tables inet')
      printf 'table inet watchdogvpn\n'
      return 0
      ;;
    'delete table inet')
      return 1
      ;;
    *)
      return 1
      ;;
  esac
}
iptables() { return 0; }
ip6tables() { return 0; }
if remove_kill_switch_rules_strict >/dev/null 2>&1; then
  printf 'FAIL: failed kill-switch cleanup was accepted\n' >&2
  exit 1
fi
unset -f nft iptables ip6tables

assert_contains() {
  local file="$1" pattern="$2" message="$3"
  if ! grep -Fq -- "$pattern" "$file"; then
    printf 'FAIL: %s\n' "$message" >&2
    exit 1
  fi
}

assert_order() {
  local first="$1" second="$2" message="$3" first_line second_line
  first_line="$(grep -nF -- "$first" "$ROOT_DIR/uninstall.sh" | head -n1 | cut -d: -f1)"
  second_line="$(grep -nF -- "$second" "$ROOT_DIR/uninstall.sh" | head -n1 | cut -d: -f1)"
  if [[ -z "$first_line" || -z "$second_line" || "$first_line" -ge "$second_line" ]]; then
    printf 'FAIL: %s\n' "$message" >&2
    exit 1
  fi
}

# The destructive script must route every critical precondition through the
# abort helper before it reaches any runtime/removal function. Rescue helpers
# receive --strict and no longer have an unsafe DNS-skip escape hatch.
assert_contains "$ROOT_DIR/uninstall.sh" 'stop_watchdogvpn_for_uninstall' "uninstall must verify daemon inactivity before deletion"
assert_contains "$ROOT_DIR/uninstall.sh" 'remove_kill_switch_rules_strict' "uninstall must strictly verify kill-switch cleanup"
assert_contains "$ROOT_DIR/uninstall.sh" 'uninstall_abort_with_recovery' "uninstall failures must retain recovery evidence"
assert_contains "$ROOT_DIR/uninstall.sh" 'auto --strict' "uninstall must invoke strict rescue helpers"
assert_contains "$ROOT_DIR/uninstall.sh" '--skip-dns-rescue is unsafe and no longer supported' "uninstall must reject DNS cleanup bypass"
assert_contains "$ROOT_DIR/bin/vpn_dns_rescue" '--strict' "DNS rescue must expose strict failure propagation"
assert_contains "$ROOT_DIR/bin/vpn_domain_bypass_rescue" '--strict' "route rescue must expose strict failure propagation"
assert_order 'if ! stop_watchdogvpn_for_uninstall; then' 'print_section "Remove product files"' "daemon verification must precede product removal"
assert_order 'if ! remove_kill_switch_rules_strict; then' 'print_section "Remove product files"' "firewall verification must precede product removal"
assert_order 'if ! rescue_system_dns; then' 'print_section "Remove product files"' "DNS verification must precede product removal"

set +e
"$ROOT_DIR/uninstall.sh" --skip-dns-rescue >/dev/null 2>&1
skip_status=$?
set -e
if [[ "$skip_status" -ne 64 ]]; then
  printf 'FAIL: unsafe DNS cleanup bypass did not return usage error 64\n' >&2
  exit 1
fi

for script in uninstall.sh bin/vpn_dns_rescue bin/vpn_domain_bypass_rescue; do
  bash -n "$ROOT_DIR/$script"
done

printf 'uninstall fail-closed checks passed\n'
