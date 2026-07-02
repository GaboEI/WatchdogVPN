#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
INSTALLER="$ROOT_DIR/install.sh"
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

contains() {
  local haystack="$1" needle="$2"
  grep -Fq "$needle" <<<"$haystack"
}

not_contains() {
  local haystack="$1" needle="$2"
  if grep -Fqi "$needle" <<<"$haystack"; then
    printf 'FAIL: unexpected match for %s\n' "$needle" >&2
    exit 1
  fi
}

yes_output="$("$INSTALLER" --dry-run --yes --skip-doctor 2>&1)"
contains "$yes_output" "Backend mode:"
contains "$yes_output" "Active backend:"
contains "$yes_output" "custom-vps"
not_contains "$yes_output" "select vpn backend"
not_contains "$yes_output" "AdGuard VPN CLI installation"
not_contains "$yes_output" "AdGuard VPN login"

mkdir -p "$TMP_DIR/home"
custom_output="$(printf '\n\n\n\n\n\n\n\nn\nn\n' | HOME="$TMP_DIR/home" PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin" "$INSTALLER" --dry-run --skip-doctor 2>&1)"
contains "$custom_output" "WatchdogVPN backend: Custom VPS"
contains "$custom_output" "Custom VPS configuration stores only non-secret local metadata."
if ! contains "$custom_output" "[DRY-RUN] install sing-box to /usr/local/bin/sing-box" \
  && ! contains "$custom_output" "[KEEP] sing-box detected:"; then
  printf 'FAIL: custom-vps dry-run must validate sing-box availability or install plan\n' >&2
  exit 1
fi
contains "$custom_output" "Backend mode:"
contains "$custom_output" "Active backend:"
contains "$custom_output" "custom-vps"
contains "$custom_output" "[DRY-RUN] set backend.mode = \"custom-vps\""
contains "$custom_output" "[DRY-RUN] set custom_vps.enabled = true"
contains "$custom_output" "[DRY-RUN] set custom_vps.ssh_port = 22"
contains "$custom_output" "[DRY-RUN] set custom_vps.interface = \"\""
contains "$custom_output" "[SKIP] automatic VPN settle check; selected backend is custom-vps"
contains "$custom_output" "[SKIP] automatic runtime validation; selected backend is custom-vps"
not_contains "$custom_output" "select vpn backend"
not_contains "$custom_output" "AdGuard VPN CLI installation"
not_contains "$custom_output" "AdGuard VPN login"

echo "install backend selection checks passed"
