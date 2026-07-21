#!/usr/bin/env bash
set -euo pipefail

# Destructive removal is allowed only after the network state which can strand
# an operator has been proved absent. These checks deliberately live outside
# uninstall.sh so they can be failure-injected without touching a host install.
uninstall_abort_with_recovery() {
  local stage="$1"
  fail "uninstall stopped: $stage was not verified"
  cat >&2 <<'EOF'
No product runtime file, rescue command, unit, configuration, log, or state was removed.
Recovery tools are intentionally still installed:
  /usr/local/bin/watchdog_panic
  /usr/local/bin/vpn_dns_rescue
  /usr/local/bin/vpn_domain_bypass_rescue
Next steps:
  1. Inspect: sudo systemctl status watchdogvpn.service --no-pager
  2. Recover DNS: sudo vpn_dns_rescue auto --no-reconnect --strict
  3. Recover routes: sudo vpn_domain_bypass_rescue auto --strict
  4. Fix the reported cleanup failure, then rerun uninstall.
EOF
}

_uninstall_watchdogvpn_unit_known() {
  local load_state
  load_state="$(systemctl show watchdogvpn.service --property LoadState --value 2>/dev/null || true)"
  [[ "$load_state" != "not-found" && -n "$load_state" ]]
}

_uninstall_have_cmd() {
  if declare -F have_cmd >/dev/null 2>&1; then
    have_cmd "$1"
    return $?
  fi
  command -v "$1" >/dev/null 2>&1
}

stop_watchdogvpn_for_uninstall() {
  local main_pid socket_path="${WATCHDOGVPN_SOCKET_PATH:-/run/watchdogvpn/control.sock}"
  if [[ "${INSTALL_DRY_RUN:-0}" == "1" ]]; then
    printf '[DRY-RUN] stop and verify watchdogvpn.service inactivity\n'
    return 0
  fi

  if _uninstall_watchdogvpn_unit_known; then
    sudo systemctl disable --now watchdogvpn.service || return 1
  fi
  if systemctl is-active --quiet watchdogvpn.service 2>/dev/null; then
    return 1
  fi
  main_pid="$(systemctl show watchdogvpn.service --property MainPID --value 2>/dev/null || true)"
  [[ -z "$main_pid" || "$main_pid" == "0" ]] || return 1
  [[ ! -S "$socket_path" ]] || return 1
}

_uninstall_remove_iptables_chain() {
  local command="$1" chain="$2"
  _uninstall_have_cmd "$command" || return 0
  sudo "$command" -S >/dev/null || return 1
  while sudo "$command" -C OUTPUT -j "$chain" >/dev/null 2>&1; do
    sudo "$command" -D OUTPUT -j "$chain" || return 1
  done
  if sudo "$command" -S "$chain" >/dev/null 2>&1; then
    sudo "$command" -F "$chain" || return 1
    sudo "$command" -X "$chain" || return 1
  fi
  ! sudo "$command" -S 2>/dev/null | grep -Fq "$chain"
}

remove_kill_switch_rules_strict() {
  if [[ "${INSTALL_DRY_RUN:-0}" == "1" ]]; then
    printf '[DRY-RUN] strictly remove and verify WatchdogVPN kill-switch rules\n'
    return 0
  fi
  if _uninstall_have_cmd nft; then
    sudo nft list tables inet >/dev/null || return 1
    if sudo nft list tables inet | grep -Fqx "table inet $KILL_SWITCH_NFT_TABLE"; then
      sudo nft delete table inet "$KILL_SWITCH_NFT_TABLE" || return 1
    fi
    ! sudo nft list tables inet | grep -Fqx "table inet $KILL_SWITCH_NFT_TABLE" || return 1
  fi
  _uninstall_remove_iptables_chain iptables "$KILL_SWITCH_IPTABLES_CHAIN" || return 1
  _uninstall_remove_iptables_chain ip6tables "$KILL_SWITCH_IPTABLES_CHAIN" || return 1
}
