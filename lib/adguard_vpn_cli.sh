#!/usr/bin/env bash
set -euo pipefail

ADGUARD_VPN_CLI_INSTALL_URL="${ADGUARD_VPN_CLI_INSTALL_URL:-https://raw.githubusercontent.com/AdguardTeam/AdGuardVPNCLI/master/scripts/release/install.sh}"
ADGUARD_VPN_CLI_DOWNLOAD_TIMEOUT="${ADGUARD_VPN_CLI_DOWNLOAD_TIMEOUT:-60}"

print_adguard_cli_external_notice() {
  cat <<EOF
Security notice:
  WatchdogVPN can download and execute the official AdGuard VPN CLI installer.
  Source: $ADGUARD_VPN_CLI_INSTALL_URL

  This repository does not currently pin that vendor script by checksum or
  signature. The safest path is to install AdGuard VPN CLI manually from the
  official vendor instructions, then rerun ./install.sh.
EOF
}

download_adguard_cli_installer() {
  local target="$1" ip

  if curl --fail --show-error --location \
    --connect-timeout 15 \
    --max-time "$ADGUARD_VPN_CLI_DOWNLOAD_TIMEOUT" \
    "$ADGUARD_VPN_CLI_INSTALL_URL" \
    -o "$target"; then
    return 0
  fi

  warn "standard download failed; trying GitHub raw IPv4 fallbacks"
  for ip in 185.199.108.133 185.199.109.133 185.199.110.133 185.199.111.133; do
    info "trying raw.githubusercontent.com via $ip"
    if curl --fail --show-error --location --ipv4 \
      --resolve "raw.githubusercontent.com:443:$ip" \
      --connect-timeout 15 \
      --max-time "$ADGUARD_VPN_CLI_DOWNLOAD_TIMEOUT" \
      "$ADGUARD_VPN_CLI_INSTALL_URL" \
      -o "$target"; then
      return 0
    fi
  done

  return 1
}

adguard_cli_available() {
  command -v adguardvpn-cli >/dev/null 2>&1 || [[ -x /usr/local/bin/adguardvpn-cli ]]
}

adguard_cli_path() {
  if command -v adguardvpn-cli >/dev/null 2>&1; then
    command -v adguardvpn-cli
  elif [[ -x /usr/local/bin/adguardvpn-cli ]]; then
    printf '%s\n' /usr/local/bin/adguardvpn-cli
  else
    return 1
  fi
}

install_official_adguard_vpn_cli() {
  local tmp cli

  if adguard_cli_available; then
    cli="$(adguard_cli_path)"
    printf '[KEEP] AdGuard VPN CLI detected: %s\n' "$cli"
    return 0
  fi

  warn "AdGuard VPN CLI is not installed"
  printf 'WatchdogVPN is a control layer around the official AdGuard VPN CLI.\n'
  printf 'The official CLI must be installed before WatchdogVPN can manage the VPN.\n'
  print_adguard_cli_external_notice

  if [[ "${INSTALL_DRY_RUN:-0}" == "1" ]]; then
    printf '[DRY-RUN] sh -c curl -fsSL %s -o /tmp/watchdogvpn-adguardvpn-cli-install.sh\n' "$ADGUARD_VPN_CLI_INSTALL_URL"
    printf '[DRY-RUN] sh /tmp/watchdogvpn-adguardvpn-cli-install.sh -v\n'
    return 0
  fi

  if ! prompt_yes_no "Download and run the official AdGuard VPN CLI installer now?" yes; then
    fail "adguardvpn-cli is required before installing WatchdogVPN"
    printf 'Install it manually, then rerun ./install.sh:\n'
    printf '  curl -fsSL %s | sh -s -- -v\n' "$ADGUARD_VPN_CLI_INSTALL_URL"
    exit 1
  fi

  tmp="/tmp/watchdogvpn-adguardvpn-cli-install.sh"
  info "downloading official AdGuard VPN CLI installer"
  if ! download_adguard_cli_installer "$tmp"; then
    fail "could not download the official AdGuard VPN CLI installer"
    printf 'Check DNS/connectivity to raw.githubusercontent.com, then rerun ./install.sh.\n'
    printf 'Manual test:\n'
    printf '  curl -4 -I --resolve raw.githubusercontent.com:443:185.199.108.133 %s\n' "$ADGUARD_VPN_CLI_INSTALL_URL"
    exit 1
  fi

  info "running official AdGuard VPN CLI installer"
  sh "$tmp" -v

  if ! adguard_cli_available; then
    fail "AdGuard VPN CLI installation finished but adguardvpn-cli was not found"
    printf 'Expected command: /usr/local/bin/adguardvpn-cli\n'
    exit 1
  fi

  cli="$(adguard_cli_path)"
  ok "AdGuard VPN CLI installed: $cli"
}
