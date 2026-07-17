#!/usr/bin/env bash
set -euo pipefail

SINGBOX_VERSION="${SINGBOX_VERSION:-1.13.14}"
SINGBOX_RELEASE_BASE_URL="${SINGBOX_RELEASE_BASE_URL:-https://github.com/SagerNet/sing-box/releases/download/v${SINGBOX_VERSION}}"
SINGBOX_DOWNLOAD_TIMEOUT="${SINGBOX_DOWNLOAD_TIMEOUT:-120}"

# SagerNet does not publish a checksums/signature file alongside sing-box
# release assets, so these are computed directly from the official release
# archives for the exact pinned SINGBOX_VERSION above. Bumping the version
# requires re-verifying the new archives and updating both hashes together.
SINGBOX_SHA256_LINUX_AMD64="${SINGBOX_SHA256_LINUX_AMD64:-aae9172317c61760aae3dafcde889b2e51b7ea590c40d2b3c7ccdeae14b361b6}"
SINGBOX_SHA256_LINUX_ARM64="${SINGBOX_SHA256_LINUX_ARM64:-4742df6a4314e8ecc41736849fca6d73b8f9e91b6e8b06ee794ff17ba180579e}"

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

singbox_asset_sha256() {
  case "$(uname -m)" in
    x86_64|amd64)
      printf '%s\n' "$SINGBOX_SHA256_LINUX_AMD64"
      ;;
    aarch64|arm64)
      printf '%s\n' "$SINGBOX_SHA256_LINUX_ARM64"
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

  SagerNet does not publish a checksums/signature file for sing-box releases.
  WatchdogVPN verifies the download against a SHA-256 hash computed by the
  WatchdogVPN maintainers directly from the official release archive for the
  exact pinned version ($SINGBOX_VERSION) and refuses to install on mismatch.
EOF
}

install_official_singbox() {
  local asset url tmpdir bin expected_sha256

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
  expected_sha256="$(singbox_asset_sha256)" || {
    fail "sing-box automatic install has no pinned checksum for architecture: $(uname -m)"
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
  download_release_asset "$url" "$tmpdir/$asset" "$SINGBOX_DOWNLOAD_TIMEOUT" "sing-box"
  if ! verify_sha256 "$tmpdir/$asset" "$expected_sha256"; then
    fail "sing-box download checksum mismatch: $asset"
    printf 'expected sha256: %s\n' "$expected_sha256"
    printf 'actual sha256:   %s\n' "$(sha256sum "$tmpdir/$asset" | awk '{print $1}')"
    printf 'The download may be corrupted or tampered with. Aborting without installing.\n'
    exit 1
  fi
  ok "sing-box download checksum verified"
  run_step tar -xzf "$tmpdir/$asset" -C "$tmpdir"
  run_step sudo install -m 0755 -o root -g root "$tmpdir/sing-box-${SINGBOX_VERSION}-linux-"*/sing-box /usr/local/bin/sing-box

  if ! singbox_available; then
    fail "sing-box installation finished but sing-box was not found"
    exit 1
  fi

  bin="$(singbox_path)"
  ok "sing-box installed: $bin"
}
