#!/usr/bin/env bash
set -euo pipefail

CLOAK_VERSION="${CLOAK_VERSION:-2.12.0}"
CLOAK_RELEASE_BASE_URL="${CLOAK_RELEASE_BASE_URL:-https://github.com/cbeuw/Cloak/releases/download/v${CLOAK_VERSION}}"
CLOAK_DOWNLOAD_TIMEOUT="${CLOAK_DOWNLOAD_TIMEOUT:-120}"

# cbeuw/Cloak does not publish a checksums/signature file alongside release
# assets, so these are computed directly from the official release binaries
# for the exact pinned CLOAK_VERSION above. Bumping the version requires
# re-verifying the new binaries and updating both hashes together.
CLOAK_SHA256_LINUX_AMD64="${CLOAK_SHA256_LINUX_AMD64:-ceabde7e13cf0e9dd7f53f811d6f24c1246755911b06aa40fb541041016348e3}"
CLOAK_SHA256_LINUX_ARM64="${CLOAK_SHA256_LINUX_ARM64:-4aa5e9a16864caed73e374fe87a5bc853043aa2c06fbd89e329ff1f623bf5f71}"

cloak_available() {
  command -v ck-client >/dev/null 2>&1 || [[ -x /usr/local/bin/ck-client ]] || [[ -x "$HOME/.local/bin/ck-client" ]]
}

cloak_path() {
  if command -v ck-client >/dev/null 2>&1; then
    command -v ck-client
  elif [[ -x /usr/local/bin/ck-client ]]; then
    printf '%s\n' /usr/local/bin/ck-client
  elif [[ -x "$HOME/.local/bin/ck-client" ]]; then
    printf '%s\n' "$HOME/.local/bin/ck-client"
  else
    return 1
  fi
}

cloak_asset_name() {
  case "$(uname -m)" in
    x86_64|amd64)
      printf 'ck-client-linux-amd64-v%s\n' "$CLOAK_VERSION"
      ;;
    aarch64|arm64)
      printf 'ck-client-linux-arm64-v%s\n' "$CLOAK_VERSION"
      ;;
    *)
      return 1
      ;;
  esac
}

cloak_asset_sha256() {
  case "$(uname -m)" in
    x86_64|amd64)
      printf '%s\n' "$CLOAK_SHA256_LINUX_AMD64"
      ;;
    aarch64|arm64)
      printf '%s\n' "$CLOAK_SHA256_LINUX_ARM64"
      ;;
    *)
      return 1
      ;;
  esac
}

print_cloak_external_notice() {
  local asset
  asset="$(cloak_asset_name || true)"
  cat <<EOF
Security notice:
  WatchdogVPN can download the official Cloak client (ck-client) release
  binary.
  Source: ${CLOAK_RELEASE_BASE_URL}/${asset:-unsupported-architecture}

  cbeuw/Cloak does not publish a checksums/signature file for its releases.
  WatchdogVPN verifies the download against a SHA-256 hash computed by the
  WatchdogVPN maintainers directly from the official release binary for the
  exact pinned version ($CLOAK_VERSION) and refuses to install on mismatch.
EOF
}

# Cloak is only needed for the OpenVPN+Cloak protocol combination, unlike
# sing-box which is required by most Custom VPS protocols. Installation is
# therefore always opt-in, defaulting to no, and is skipped without asking
# under --dry-run so dry-run stays scriptable without extra stdin input.
install_official_cloak() {
  local asset url tmpdir bin expected_sha256

  if cloak_available; then
    bin="$(cloak_path)"
    printf '[KEEP] Cloak client detected: %s\n' "$bin"
    return 0
  fi

  if [[ "${INSTALL_DRY_RUN:-0}" == "1" ]]; then
    printf '[DRY-RUN] skip optional Cloak client install (only needed for OpenVPN+Cloak profiles)\n'
    return 0
  fi

  asset="$(cloak_asset_name)" || {
    warn "Cloak client automatic install does not support architecture: $(uname -m)"
    printf 'Install ck-client manually if you plan to use OpenVPN+Cloak profiles.\n'
    return 0
  }
  expected_sha256="$(cloak_asset_sha256)" || {
    warn "Cloak client automatic install has no pinned checksum for architecture: $(uname -m)"
    printf 'Install ck-client manually if you plan to use OpenVPN+Cloak profiles.\n'
    return 0
  }
  url="${CLOAK_RELEASE_BASE_URL}/${asset}"

  printf '\nThe Cloak client (ck-client) is only needed for OpenVPN+Cloak profiles.\n'
  print_cloak_external_notice

  if ! prompt_yes_no "Download and install the official Cloak client now?" no; then
    printf '[SKIP] Cloak client not installed; OpenVPN+Cloak profiles will fail until it is installed.\n'
    return 0
  fi

  tmpdir="$(mktemp -d)"
  trap 'rm -rf "$tmpdir"' RETURN
  info "downloading Cloak client $CLOAK_VERSION"
  run_step curl --fail --show-error --location \
    --connect-timeout 15 \
    --max-time "$CLOAK_DOWNLOAD_TIMEOUT" \
    "$url" \
    -o "$tmpdir/$asset"
  if ! verify_sha256 "$tmpdir/$asset" "$expected_sha256"; then
    fail "Cloak client download checksum mismatch: $asset"
    printf 'expected sha256: %s\n' "$expected_sha256"
    printf 'actual sha256:   %s\n' "$(sha256sum "$tmpdir/$asset" | awk '{print $1}')"
    printf 'The download may be corrupted or tampered with. Aborting without installing.\n'
    exit 1
  fi
  ok "Cloak client download checksum verified"
  run_step chmod +x "$tmpdir/$asset"
  run_step sudo install -m 0755 -o root -g root "$tmpdir/$asset" /usr/local/bin/ck-client

  if ! cloak_available; then
    fail "Cloak client installation finished but ck-client was not found"
    exit 1
  fi

  bin="$(cloak_path)"
  ok "Cloak client installed: $bin"
}
