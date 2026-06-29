#!/usr/bin/env bash
set -euo pipefail

SINGBOX_VERSION="${SINGBOX_VERSION:-1.13.14}"
SINGBOX_RELEASE_BASE_URL="${SINGBOX_RELEASE_BASE_URL:-https://github.com/SagerNet/sing-box/releases/download/v${SINGBOX_VERSION}}"
SINGBOX_DOWNLOAD_TIMEOUT="${SINGBOX_DOWNLOAD_TIMEOUT:-120}"

singbox_available() {
  command -v sing-box >/dev/null 2>&1 || [[ -x /usr/local/bin/sing-box ]] || [[ -x "$HOME/.local/bin/sing-box" ]]
}

singbox_path() {
  if command -v sing-box >/dev/null 2>&1; then
    command -v sing-box
  elif [[ -x /usr/local/bin/sing-box ]]; then
    printf '%s\n' /usr/local/bin/sing-box
  elif [[ -x "$HOME/.local/bin/sing-box" ]]; then
    printf '%s\n' "$HOME/.local/bin/sing-box"
  else
    return 1
  fi
}

singbox_asset_name() {
  case "$(uname -m)" in
    x86_64|amd64)
      printf 'sing-box-%s-linux-amd64-glibc.tar.gz\n' "$SINGBOX_VERSION"
      ;;
    aarch64|arm64)
      printf 'sing-box-%s-linux-arm64.tar.gz\n' "$SINGBOX_VERSION"
      ;;
    *)
      return 1
      ;;
  esac
}

print_singbox_external_notice() {
  local asset
  asset="$(singbox_asset_name || true)"
  cat <<EOF
Security notice:
  WatchdogVPN can download the official sing-box release archive.
  Source: ${SINGBOX_RELEASE_BASE_URL}/${asset:-unsupported-architecture}

  This repository does not currently pin the archive by checksum. Advanced users
  may install sing-box manually before running ./install.sh.
EOF
}

install_official_singbox() {
  local asset url tmpdir bin

  if singbox_available; then
    bin="$(singbox_path)"
    printf '[KEEP] sing-box detected: %s\n' "$bin"
    return 0
  fi

  asset="$(singbox_asset_name)" || {
    fail "sing-box automatic install does not support architecture: $(uname -m)"
    printf 'Install sing-box manually, then rerun ./install.sh.\n'
    exit 1
  }
  url="${SINGBOX_RELEASE_BASE_URL}/${asset}"

  warn "sing-box is not installed"
  printf 'Custom VPS profiles require sing-box before WatchdogVPN can run proxy/VPN protocols.\n'
  print_singbox_external_notice

  if [[ "${INSTALL_DRY_RUN:-0}" == "1" ]]; then
    printf '[DRY-RUN] download %s\n' "$url"
    printf '[DRY-RUN] install sing-box to /usr/local/bin/sing-box\n'
    return 0
  fi

  if ! prompt_yes_no "Download and install the official sing-box binary now?" yes; then
    fail "sing-box is required for Custom VPS backend"
    printf 'Install it manually, then rerun ./install.sh:\n'
    printf '  curl -L -o /tmp/%s %s\n' "$asset" "$url"
    exit 1
  fi

  tmpdir="$(mktemp -d)"
  trap 'rm -rf "$tmpdir"' RETURN
  info "downloading sing-box $SINGBOX_VERSION"
  run_step curl --fail --show-error --location \
    --connect-timeout 15 \
    --max-time "$SINGBOX_DOWNLOAD_TIMEOUT" \
    "$url" \
    -o "$tmpdir/$asset"
  run_step tar -xzf "$tmpdir/$asset" -C "$tmpdir"
  run_step sudo install -m 0755 -o root -g root "$tmpdir/sing-box-${SINGBOX_VERSION}-linux-"*/sing-box /usr/local/bin/sing-box

  if ! singbox_available; then
    fail "sing-box installation finished but sing-box was not found"
    exit 1
  fi

  bin="$(singbox_path)"
  ok "sing-box installed: $bin"
}
