#!/usr/bin/env bash
set -euo pipefail

AGH_INSTALL_URL="https://raw.githubusercontent.com/AdguardTeam/AdGuardHome/master/scripts/install.sh"
AGH_DEFAULT_PROFILE="${AGH_DEFAULT_PROFILE:-quad9-doh}"

print_adguard_home_external_notice() {
  cat <<EOF
Security notice:
  Advanced DNS can download and execute the official AdGuard Home installer.
  Source: $AGH_INSTALL_URL

  This repository does not currently pin that vendor script by checksum or
  signature. You can answer "n" to advanced DNS, install AdGuard Home manually
  later, and then use vpn_dnsctl to apply a DNS profile.
EOF
}

adguard_home_network_ready() {
  local host
  for host in raw.githubusercontent.com static.adtidy.org archive.ubuntu.com; do
    if ! getent hosts "$host" >/dev/null 2>&1; then
      fail "advanced DNS cannot be installed because DNS cannot resolve: $host"
      printf 'Your current network has broken name resolution. Rerun ./install.sh and answer "n" to advanced DNS,\n'
      printf 'or fix DNS first and then enable AdGuard Home later.\n'
      return 1
    fi
  done
}

adguard_home_service_known() {
  systemctl cat AdGuardHome.service >/dev/null 2>&1 \
    || systemctl list-unit-files AdGuardHome.service >/dev/null 2>&1
}

adguard_home_workdir() {
  local work=""
  work="$(systemctl cat AdGuardHome.service 2>/dev/null \
    | awk -F= '$1 == "WorkingDirectory" {print $2; exit}' || true)"
  if [[ -n "$work" ]]; then
    printf '%s\n' "$work"
    return 0
  fi
  if [[ -x /opt/AdGuardHome/AdGuardHome ]]; then
    printf '%s\n' /opt/AdGuardHome
    return 0
  fi
  if [[ -x "$HOME/AdGuardHome/AdGuardHome" ]]; then
    printf '%s\n' "$HOME/AdGuardHome"
    return 0
  fi
  printf '%s\n' /opt/AdGuardHome
}

adguard_home_bin() {
  printf '%s/AdGuardHome\n' "$(adguard_home_workdir)"
}

adguard_home_conf() {
  printf '%s/AdGuardHome.yaml\n' "$(adguard_home_workdir)"
}

install_adguard_home_binary() {
  if adguard_home_service_known || [[ -x "$(adguard_home_bin)" ]]; then
    printf '[KEEP] AdGuard Home detected: %s\n' "$(adguard_home_workdir)"
    return 0
  fi

  print_adguard_home_external_notice
  run_step sh -c "curl -s -S -L '$AGH_INSTALL_URL' -o /tmp/watchdogvpn-adguardhome-install.sh"
  run_step sudo sh /tmp/watchdogvpn-adguardhome-install.sh -v
}

ensure_adguard_home_config() {
  local work conf bin
  work="$(adguard_home_workdir)"
  conf="$(adguard_home_conf)"
  bin="$(adguard_home_bin)"

  if [[ -e "$conf" ]]; then
    printf '[KEEP] AdGuard Home config: %s\n' "$conf"
    return 0
  fi

  create_root_dir "$work" 0755
  install_root_file "$ROOT_DIR/examples/AdGuardHome.yaml.example" "$conf" 0600

  if [[ "${INSTALL_DRY_RUN:-0}" == "1" ]]; then
    printf '[DRY-RUN] %s --check-config -c %s -w %s\n' "$bin" "$conf" "$work"
    return 0
  fi

  if [[ ! -x "$bin" ]]; then
    fail "AdGuard Home binary not executable: $bin"
    return 1
  fi
  sudo "$bin" --check-config -c "$conf" -w "$work"
}

enable_adguard_home_service() {
  local work conf bin
  work="$(adguard_home_workdir)"
  conf="$(adguard_home_conf)"
  bin="$(adguard_home_bin)"

  if ! adguard_home_service_known; then
    if [[ "${INSTALL_DRY_RUN:-0}" == "1" ]]; then
      printf '[DRY-RUN] ensure AdGuardHome.service registered for %s\n' "$work"
      run_step sudo systemctl enable --now AdGuardHome.service
      return 0
    fi
    run_step sudo "$bin" -s install -w "$work" -c "$conf"
  fi

  run_step sudo systemctl enable --now AdGuardHome.service
}

apply_adguard_home_profile() {
  local profile="${1:-$AGH_DEFAULT_PROFILE}"
  if [[ "${INSTALL_DRY_RUN:-0}" == "1" ]]; then
    printf '[DRY-RUN] %s/bin/vpn_dnsctl apply %s\n' "$ROOT_DIR" "$profile"
    return 0
  fi
  "$ROOT_DIR/bin/vpn_dnsctl" apply "$profile"
}

install_adguard_home_integration() {
  adguard_home_network_ready

  if declare -p DISTRO_DNS_PACKAGES >/dev/null 2>&1; then
    install_package_set "${DISTRO_DNS_PACKAGES[@]}"
  fi

  install_adguard_home_binary
  ensure_adguard_home_config
  enable_adguard_home_service
  apply_adguard_home_profile "$AGH_DEFAULT_PROFILE"
}
