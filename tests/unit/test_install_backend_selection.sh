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

yes_output="$("$INSTALLER" --dry-run --yes --skip-doctor 2>&1)"
contains "$yes_output" "Backend mode:"
contains "$yes_output" "Active backend:"
contains "$yes_output" "adguard"
contains "$yes_output" "[DRY-RUN] validate VPN tunnel after install"

mkdir -p "$TMP_DIR/home"
custom_output="$(printf '2\n\n\n\n\n\n\n\n\nn\nn\nn\n' | HOME="$TMP_DIR/home" PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin" "$INSTALLER" --dry-run --skip-doctor 2>&1)"
contains "$custom_output" "Select VPN backend:"
contains "$custom_output" "Custom VPS backend setup is experimental and uses a user-configured local service."
contains "$custom_output" "Custom VPS configuration stores only non-secret local metadata."
contains "$custom_output" "[SKIP] AdGuard VPN CLI installation; selected backend is custom-vps"
contains "$custom_output" "[DRY-RUN] install sing-box to /usr/local/bin/sing-box"
contains "$custom_output" "Backend mode:"
contains "$custom_output" "Active backend:"
contains "$custom_output" "custom-vps"
contains "$custom_output" "[DRY-RUN] set backend.mode = \"custom-vps\""
contains "$custom_output" "[DRY-RUN] set custom_vps.enabled = true"
contains "$custom_output" "[DRY-RUN] set custom_vps.ssh_port = 22"
contains "$custom_output" "[DRY-RUN] set custom_vps.interface = \"\""
contains "$custom_output" "[SKIP] AdGuard VPN login; selected backend is custom-vps"
contains "$custom_output" "[SKIP] AdGuard VPN settle check; selected backend is custom-vps"
contains "$custom_output" "[SKIP] AdGuard runtime validation; selected backend is custom-vps"

if contains "$custom_output" "Download and run the official AdGuard VPN CLI installer now?"; then
  printf 'FAIL: custom-vps dry-run must not prompt for AdGuard CLI installer\n' >&2
  exit 1
fi

echo "install backend selection checks passed"
