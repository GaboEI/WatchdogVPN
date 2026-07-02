#!/usr/bin/env bash
set -euo pipefail

SYSTEMD_UNITS=(
  watchdogvpn.service
  adguardvpn.service
  vpn-rotate.service
  vpn-rotate.timer
  vpn-rotate-firstboot.timer
  vpn-rotate-onboot.service
  vpn-watchdog.service
  vpn-watchdog.timer
  vpn-domain-bypass.service
  vpn-domain-bypass.timer
  myvpn-logrotate.service
  myvpn-logrotate.timer
)

SYSTEMD_ENABLE_UNITS=(
  watchdogvpn.service
  adguardvpn.service
  vpn-rotate.timer
  vpn-watchdog.timer
  vpn-domain-bypass.timer
  myvpn-logrotate.timer
)

SYSTEMD_COMMON_ENABLE_UNITS=(
  myvpn-logrotate.timer
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
    return 0
  fi

  for unit in "${SYSTEMD_COMMON_ENABLE_UNITS[@]}"; do
    run_step sudo systemctl enable --now "$unit"
  done
}

disable_systemd_units() {
  local unit
  for unit in "${SYSTEMD_ENABLE_UNITS[@]}"; do
    if [[ "${INSTALL_DRY_RUN:-0}" == "1" ]]; then
      run_step sudo systemctl disable --now "$unit"
    else
      sudo systemctl disable --now "$unit" >/dev/null 2>&1 || true
    fi
  done
  for unit in vpn-rotate-firstboot.timer vpn-rotate-onboot.service; do
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
