#!/usr/bin/env bash
set -euo pipefail

SYSTEMD_UNITS=(
  watchdogvpn.service
  watchdogvpn-nm-dns-restore.service
  watchdogvpn-nm-tun-cleanup.service
  vpn-domain-bypass.service
  vpn-domain-bypass.timer
  myvpn-logrotate.service
  myvpn-logrotate.timer
  watchdogvpn-rp-filter.service
)

# vpn-domain-bypass.timer is deliberately NOT in this list. It modifies live
# kernel routing state (ip rule entries and a custom routing table) and must
# never be force-restarted just because install.sh/update.sh ran - a real
# incident (2026-07-07) showed that unconditionally re-running
# `systemctl enable --now vpn-domain-bypass.timer` on every update resets its
# OnActiveSec=30s schedule, causing it to re-apply routing rules ~30s after
# a routine update finishes and collide with another VPN client (Karing)
# managing its own routes at that moment. It is handled by
# enable_vpn_domain_bypass_timer_if_safe() instead, which only enables it
# when real bypass domains are configured and never touches it if it is
# already running. See docs/security.md's "Domain bypass network safety".
#
# watchdogvpn.service is also NOT in this list, for a related reason: if the
# user put WatchdogVPN to sleep with `watchdog_panic sleep`
# (docs/security.md "WatchdogVPN Panic Button"), a later install/update must
# not silently wake it back up. It is handled by
# enable_watchdogvpn_service_unless_hibernating() instead.
SYSTEMD_ENABLE_UNITS=(
  myvpn-logrotate.timer
  watchdogvpn-rp-filter.service
)

SYSTEMD_COMMON_ENABLE_UNITS=(
  myvpn-logrotate.timer
  watchdogvpn-rp-filter.service
)

vpn_domain_bypass_configured() {
  local conf="${WATCHDOGVPN_DOMAIN_BYPASS_CONF:-/etc/vpn-domain-bypass.conf}"
  [[ -f "$conf" ]] || return 1
  grep -Eq '^[[:space:]]*[^#[:space:]]' "$conf"
}

# systemd cannot distinguish "never enabled" from "the user explicitly
# disabled this after a routing conflict" - both look identical
# (disabled/inactive). This marker is WatchdogVPN's own record of the
# latter, so a later install/update does not silently undo a safety
# decision the user already made. Written by vpn_domain_bypass_rescue.
VPN_DOMAIN_BYPASS_DISABLED_MARKER="${VPN_DOMAIN_BYPASS_DISABLED_MARKER:-/etc/watchdogvpn/.domain-bypass-disabled}"

enable_vpn_domain_bypass_timer_if_safe() {
  local unit="vpn-domain-bypass.timer" conf="${WATCHDOGVPN_DOMAIN_BYPASS_CONF:-/etc/vpn-domain-bypass.conf}"

  if systemctl is-active --quiet "$unit" 2>/dev/null; then
    if [[ "${INSTALL_DRY_RUN:-0}" == "1" ]]; then
      printf '[DRY-RUN] %s already active; would not restart it\n' "$unit"
      [[ -e "$VPN_DOMAIN_BYPASS_DISABLED_MARKER" ]] && printf '[DRY-RUN] clear stale manual-disable marker: %s\n' "$VPN_DOMAIN_BYPASS_DISABLED_MARKER"
      return 0
    fi
    printf '[KEEP] %s already active; not restarting it (would re-apply routing rules)\n' "$unit"
    if [[ -e "$VPN_DOMAIN_BYPASS_DISABLED_MARKER" ]]; then
      run_step sudo rm -f "$VPN_DOMAIN_BYPASS_DISABLED_MARKER"
      printf '[INFO] cleared previous manual-disable marker; %s is running again\n' "$unit"
    fi
    return 0
  fi

  if [[ -e "$VPN_DOMAIN_BYPASS_DISABLED_MARKER" ]]; then
    printf '[SKIP] %s was manually disabled after a routing conflict; not re-enabling automatically\n' "$unit"
    printf '       to re-enable it yourself: sudo systemctl enable --now %s\n' "$unit"
    return 0
  fi

  if [[ "${INSTALL_DRY_RUN:-0}" == "1" ]]; then
    if vpn_domain_bypass_configured; then
      printf '[DRY-RUN] sudo systemctl enable --now %s (domains configured in %s)\n' "$unit" "$conf"
    else
      printf '[DRY-RUN] skip enabling %s; no domains configured in %s\n' "$unit" "$conf"
    fi
    return 0
  fi

  if ! vpn_domain_bypass_configured; then
    printf '[SKIP] %s not enabled; no domains configured in %s\n' "$unit" "$conf"
    return 0
  fi
  run_step sudo systemctl enable --now "$unit"
}

# Written by `watchdog_panic sleep` (bin/watchdog_panic). While present,
# install.sh/update.sh must not re-enable the daemon - the whole point of
# the panic button is that it stays off until the user explicitly runs
# `watchdog_panic wake`, including across a reboot and across running the
# installer again. See docs/security.md "WatchdogVPN Panic Button".
WATCHDOGVPN_HIBERNATE_MARKER="${WATCHDOGVPN_HIBERNATE_MARKER:-/etc/watchdogvpn/.hibernating}"

# update.sh replaces imported Python modules while the daemon may still have
# their previous generation resident in memory. The installed-version marker
# only describes files on disk, so it cannot prove the active process loaded
# them. Capture the pre-update service generation before replacement, then
# require an actual PID change after the hibernate-aware enable phase.
WATCHDOGVPN_DAEMON_WAS_ACTIVE=0
WATCHDOGVPN_DAEMON_PID_BEFORE_UPDATE=""
WATCHDOGVPN_DAEMON_PID_AFTER_UPDATE=""

capture_watchdogvpn_service_state() {
  WATCHDOGVPN_DAEMON_WAS_ACTIVE=0
  WATCHDOGVPN_DAEMON_PID_BEFORE_UPDATE=""
  WATCHDOGVPN_DAEMON_PID_AFTER_UPDATE=""
  if systemctl is-active --quiet watchdogvpn.service 2>/dev/null; then
    WATCHDOGVPN_DAEMON_WAS_ACTIVE=1
    WATCHDOGVPN_DAEMON_PID_BEFORE_UPDATE="$(
      systemctl show watchdogvpn.service --property MainPID --value 2>/dev/null || true
    )"
    printf '[INFO] active daemon generation before update: pid=%s\n' \
      "${WATCHDOGVPN_DAEMON_PID_BEFORE_UPDATE:-unknown}"
  else
    printf '[INFO] watchdogvpn.service was inactive before update\n'
  fi
}

restart_watchdogvpn_service_after_runtime_update() {
  local current_pid
  if [[ -e "$WATCHDOGVPN_HIBERNATE_MARKER" ]]; then
    printf '[SKIP] watchdogvpn.service restart; WatchdogVPN is asleep (run: watchdog_panic wake)\n'
    return 0
  fi
  if [[ "$WATCHDOGVPN_DAEMON_WAS_ACTIVE" != "1" ]]; then
    printf '[INFO] no pre-update daemon generation to restart\n'
    return 0
  fi
  if [[ -z "$WATCHDOGVPN_DAEMON_PID_BEFORE_UPDATE" \
    || "$WATCHDOGVPN_DAEMON_PID_BEFORE_UPDATE" == "0" ]]; then
    fail "could not identify the active pre-update watchdogvpn.service process"
    return 1
  fi

  if declare -F runtime_transaction_is_active >/dev/null && runtime_transaction_is_active; then
    runtime_transaction_checkpoint restart
  fi
  run_step sudo systemctl restart watchdogvpn.service
  if [[ "${INSTALL_DRY_RUN:-0}" == "1" ]]; then
    info "daemon process-generation change will be verified during a real update"
    return 0
  fi
  current_pid="$(
    systemctl show watchdogvpn.service --property MainPID --value 2>/dev/null || true
  )"
  if [[ -z "$current_pid" || "$current_pid" == "0" ]]; then
    fail "watchdogvpn.service has no running MainPID after update restart"
    return 1
  fi
  if [[ "$current_pid" == "$WATCHDOGVPN_DAEMON_PID_BEFORE_UPDATE" ]]; then
    fail "watchdogvpn.service did not enter a new process generation after update"
    return 1
  fi
  WATCHDOGVPN_DAEMON_PID_AFTER_UPDATE="$current_pid"
  ok "daemon runtime refreshed: pid=$WATCHDOGVPN_DAEMON_PID_BEFORE_UPDATE -> $current_pid"
}

restore_watchdogvpn_service_after_runtime_rollback() {
  if [[ "${INSTALL_DRY_RUN:-0}" == "1" ]]; then
    return 0
  fi
  run_step sudo systemctl daemon-reload || return 1
  if [[ "${WATCHDOGVPN_DAEMON_WAS_ACTIVE:-0}" == "1" ]]; then
    run_step sudo systemctl restart watchdogvpn.service || return 1
    systemctl is-active --quiet watchdogvpn.service || return 1
    return 0
  fi
  if systemctl is-active --quiet watchdogvpn.service 2>/dev/null; then
    run_step sudo systemctl stop watchdogvpn.service || return 1
  fi
}

enable_watchdogvpn_service_unless_hibernating() {
  local unit="watchdogvpn.service"
  if [[ -e "$WATCHDOGVPN_HIBERNATE_MARKER" ]]; then
    printf '[SKIP] %s not enabled; WatchdogVPN is asleep (run: watchdog_panic wake)\n' "$unit"
    return 0
  fi
  run_step sudo systemctl enable --now "$unit"
}

# Kill switch firewall state (core/kill_switch.py) is not tracked by any
# systemd unit - it is nftables/iptables state the daemon applies directly.
# Disabling/removing the daemon does not undo it, so uninstall must clean it
# up explicitly or a user with the kill switch enabled would be left with a
# firewall silently blocking non-tunnel traffic forever with no WatchdogVPN
# left to turn it off. Mirrors bin/watchdog_panic's cleanup (kept separate
# since bin/ scripts run standalone once installed and cannot source lib/).
KILL_SWITCH_NFT_TABLE="${KILL_SWITCH_NFT_TABLE:-watchdogvpn}"
KILL_SWITCH_IPTABLES_CHAIN="${KILL_SWITCH_IPTABLES_CHAIN:-WATCHDOGVPN-OUTPUT}"

_systemd_have_cmd() {
  if declare -F have_cmd >/dev/null 2>&1; then
    have_cmd "$1"
    return $?
  fi
  command -v "$1" >/dev/null 2>&1
}

remove_kill_switch_rules() {
  if [[ "${INSTALL_DRY_RUN:-0}" == "1" ]]; then
    printf '[DRY-RUN] remove kill switch firewall rules (nftables table %s / iptables chain %s)\n' \
      "$KILL_SWITCH_NFT_TABLE" "$KILL_SWITCH_IPTABLES_CHAIN"
    return 0
  fi
  if _systemd_have_cmd nft; then
    sudo nft delete table inet "$KILL_SWITCH_NFT_TABLE" >/dev/null 2>&1 || true
  fi
  if _systemd_have_cmd iptables; then
    sudo iptables -D OUTPUT -j "$KILL_SWITCH_IPTABLES_CHAIN" >/dev/null 2>&1 || true
    sudo iptables -F "$KILL_SWITCH_IPTABLES_CHAIN" >/dev/null 2>&1 || true
    sudo iptables -X "$KILL_SWITCH_IPTABLES_CHAIN" >/dev/null 2>&1 || true
  fi
  if _systemd_have_cmd ip6tables; then
    sudo ip6tables -D OUTPUT -j "$KILL_SWITCH_IPTABLES_CHAIN" >/dev/null 2>&1 || true
    sudo ip6tables -F "$KILL_SWITCH_IPTABLES_CHAIN" >/dev/null 2>&1 || true
    sudo ip6tables -X "$KILL_SWITCH_IPTABLES_CHAIN" >/dev/null 2>&1 || true
  fi
}

# Historical WatchdogVPN-owned units removed from the shipped set before this
# release (AdGuard-era rotation/watchdog automation, Task 2.6). Kept here,
# separate from SYSTEMD_UNITS, purely so uninstall can clean up a machine
# that installed before their removal. See INV-18.1-001 in
# docs/phase-18-task-18-1-legacy-contamination-inventory.md.
SYSTEMD_LEGACY_UNITS=(
  adguardvpn.service
  vpn-watchdog.service
  vpn-watchdog.timer
  vpn-rotate.service
  vpn-rotate.timer
  vpn-rotate-firstboot.timer
  vpn-rotate-onboot.service
)

verify_systemd_units() {
  if [[ "${INSTALL_DRY_RUN:-0}" == "1" ]]; then
    printf '[DRY-RUN] systemd-analyze verify --man=no systemd/*.service systemd/*.timer\n'
    return 0
  fi

  if command -v systemd-analyze >/dev/null 2>&1; then
    # --man=no: unit correctness must not depend on man-db being installed.
    # Documentation= is informational; some distros (e.g. openSUSE Leap
    # minimal) don't ship `man` by default, and it is not a WatchdogVPN
    # runtime dependency.
    if ! sudo systemd-analyze verify --man=no "$ROOT_DIR"/systemd/*.service "$ROOT_DIR"/systemd/*.timer; then
      return 1
    fi
  else
    warn "systemd-analyze not found; skipping unit verification"
  fi
}

install_systemd_units() {
  local unit runtime_root="${WATCHDOGVPN_RUNTIME_CANDIDATE_ROOT:-$ROOT_DIR}"
  if declare -F runtime_transaction_is_active >/dev/null && runtime_transaction_is_active; then
    runtime_transaction_checkpoint unit
  fi
  for unit in "${SYSTEMD_UNITS[@]}"; do
    install_root_file "$runtime_root/systemd/$unit" "/etc/systemd/system/$unit" 0644
  done
}

enable_systemd_units() {
  local unit
  run_step sudo systemctl daemon-reload
  if [[ "${ENABLE_VPN_AUTOMATION:-1}" == "1" ]]; then
    for unit in "${SYSTEMD_ENABLE_UNITS[@]}"; do
      run_step sudo systemctl enable --now "$unit"
    done
    enable_watchdogvpn_service_unless_hibernating
    enable_vpn_domain_bypass_timer_if_safe
    return 0
  fi

  for unit in "${SYSTEMD_COMMON_ENABLE_UNITS[@]}"; do
    run_step sudo systemctl enable --now "$unit"
  done
}

disable_systemd_units() {
  local unit
  for unit in "${SYSTEMD_ENABLE_UNITS[@]}" watchdogvpn.service vpn-domain-bypass.timer; do
    if [[ "${INSTALL_DRY_RUN:-0}" == "1" ]]; then
      run_step sudo systemctl disable --now "$unit"
    else
      sudo systemctl disable --now "$unit" >/dev/null 2>&1 || true
    fi
  done
}

remove_systemd_units() {
  local unit
  for unit in "${SYSTEMD_UNITS[@]}"; do
    remove_root_path "/etc/systemd/system/$unit"
  done
  run_step sudo systemctl daemon-reload
}

remove_legacy_systemd_units() {
  local unit
  for unit in "${SYSTEMD_LEGACY_UNITS[@]}"; do
    if [[ "${INSTALL_DRY_RUN:-0}" == "1" ]]; then
      run_step sudo systemctl disable --now "$unit"
    else
      sudo systemctl disable --now "$unit" >/dev/null 2>&1 || true
    fi
    remove_root_path "/etc/systemd/system/$unit"
  done
  run_step sudo systemctl daemon-reload
}
