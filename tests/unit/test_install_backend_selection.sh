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

grep -Fq 'sudo awk -v section="$section" -v name="$name" -v value="$formatted"' "$ROOT_DIR/install.sh" || {
  printf 'FAIL: installer must read a private root-owned config through sudo before updating it\n' >&2
  exit 1
}
grep -Fq 'sudo install -m 0640 -o root -g watchdogvpn "$tmp" "$WATCHDOGVPN_CONFIG_FILE"' "$ROOT_DIR/install.sh" || {
  printf 'FAIL: backend selection must preserve the private root:watchdogvpn config policy\n' >&2
  exit 1
}

# Every invocation below points WATCHDOGVPN_ETC_CONFIG_DIR/FILE at an isolated
# temp path so this test never reads or depends on the real
# /etc/watchdogvpn/config.toml on the machine running it.
fresh_yes_dir="$TMP_DIR/fresh-yes/etc/watchdogvpn"
mkdir -p "$fresh_yes_dir"
yes_output="$(WATCHDOGVPN_ETC_CONFIG_DIR="$fresh_yes_dir" WATCHDOGVPN_CONFIG_FILE="$fresh_yes_dir/config.toml" "$INSTALLER" --dry-run --yes --skip-doctor 2>&1)"
contains "$yes_output" "Backend mode:"
contains "$yes_output" "Active backend:"
contains "$yes_output" "custom-vps"
contains "$yes_output" "[DRY-RUN] smoke test watchdogvpn.service and daemon IPC status"
not_contains "$yes_output" "select vpn backend"
# Regression test for a real fresh-install finding: install.sh used to hardcode
# ENABLE_VPN_AUTOMATION=0 for every custom-vps install with no code path ever
# setting it back to 1, so watchdogvpn.service was never enabled/started (and
# its own smoke test silently skipped itself, masked here by --dry-run's
# earlier own short-circuit). A fresh install must enable and start the
# daemon without asking - an installed app that never starts is not usable
# software.
contains "$yes_output" "[DRY-RUN] sudo systemctl enable --now watchdogvpn.service"

mkdir -p "$TMP_DIR/home"
fresh_custom_dir="$TMP_DIR/fresh-custom/etc/watchdogvpn"
mkdir -p "$fresh_custom_dir"
custom_output="$(printf '\n\n\n\n\n\n\n\nn\nn\n' | HOME="$TMP_DIR/home" WATCHDOGVPN_ETC_CONFIG_DIR="$fresh_custom_dir" WATCHDOGVPN_CONFIG_FILE="$fresh_custom_dir/config.toml" PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin" "$INSTALLER" --dry-run --skip-doctor 2>&1)"
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
contains "$custom_output" "[DRY-RUN] smoke test watchdogvpn.service and daemon IPC status"
contains "$custom_output" "[SKIP] automatic VPN settle check; selected backend is custom-vps"
contains "$custom_output" "[SKIP] automatic runtime validation; selected backend is custom-vps"
not_contains "$custom_output" "select vpn backend"

# Re-run scenario: an already-configured backend must be detected and left
# alone, not silently overwritten with the fresh-install default.
existing_dir="$TMP_DIR/existing/etc/watchdogvpn"
mkdir -p "$existing_dir"
cat >"$existing_dir/config.toml" <<'CFG'
[backend]
mode = "custom-vps"
active = "custom-vps"

[custom_vps]
enabled = true
name = "existing-vps"
host = "vpn.example.test"
ssh_user = "watchdog"
ssh_port = 22
protocol = ""
profile_path = ""
service_name = "wg-quick@existing.service"
interface = "wg-existing"
CFG
existing_hash_before="$(md5sum "$existing_dir/config.toml" | awk '{print $1}')"
preserve_output="$(WATCHDOGVPN_ETC_CONFIG_DIR="$existing_dir" WATCHDOGVPN_CONFIG_FILE="$existing_dir/config.toml" "$INSTALLER" --dry-run --yes --skip-doctor 2>&1)"
existing_hash_after="$(md5sum "$existing_dir/config.toml" | awk '{print $1}')"

contains "$preserve_output" "Existing backend configuration detected: custom-vps"
contains "$preserve_output" "Preserving existing backend configuration (active = \"custom-vps\")"
contains "$preserve_output" "[DRY-RUN] smoke test watchdogvpn.service and daemon IPC status"
not_contains "$preserve_output" "[DRY-RUN] set backend.mode"
not_contains "$preserve_output" "[DRY-RUN] set backend.active"
not_contains "$preserve_output" "[DRY-RUN] set custom_vps."
if [[ "$existing_hash_before" != "$existing_hash_after" ]]; then
  printf 'FAIL: existing config.toml must not be modified when a backend is already configured\n' >&2
  exit 1
fi

echo "install backend selection checks passed"
