#!/usr/bin/env bash
set -euo pipefail

SYSTEMD_UNITS=(
  watchdogvpn.service
  vpn-domain-bypass.service
  vpn-domain-bypass.timer
  myvpn-logrotate.service
  myvpn-logrotate.timer
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
SYSTEMD_ENABLE_UNITS=(
  watchdogvpn.service
  myvpn-logrotate.timer
)

SYSTEMD_COMMON_ENABLE_UNITS=(
  myvpn-logrotate.timer
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
    printf '[DRY-RUN] systemd-analyze verify systemd/*.service systemd/*.timer\n'
    return 0
  fi

  if command -v systemd-analyze >/dev/null 2>&1; then
    if ! sudo systemd-analyze verify "$ROOT_DIR"/systemd/*.service "$ROOT_DIR"/systemd/*.timer; then
      return 1
    fi
  else
    warn "systemd-analyze not found; skipping unit verification"
  fi
}

install_systemd_units() {
  local unit
  for unit in "${SYSTEMD_UNITS[@]}"; do
    install_root_file "$ROOT_DIR/systemd/$unit" "/etc/systemd/system/$unit" 0644
  done
}

enable_systemd_units() {
  local unit
  run_step sudo systemctl daemon-reload
  if [[ "${ENABLE_VPN_AUTOMATION:-1}" == "1" ]]; then
    for unit in "${SYSTEMD_ENABLE_UNITS[@]}"; do
      run_step sudo systemctl enable --now "$unit"
    done
    enable_vpn_domain_bypass_timer_if_safe
    return 0
  fi

  for unit in "${SYSTEMD_COMMON_ENABLE_UNITS[@]}"; do
    run_step sudo systemctl enable --now "$unit"
  done
}

disable_systemd_units() {
  local unit
  for unit in "${SYSTEMD_ENABLE_UNITS[@]}" vpn-domain-bypass.timer; do
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
