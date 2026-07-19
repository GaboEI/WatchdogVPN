#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
INSTALLER="$ROOT_DIR/install.sh"
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

FAKE_BIN="$TMP_DIR/fake-bin"
mkdir -p "$FAKE_BIN"
cat >"$FAKE_BIN/sudo" <<'SUDO'
#!/usr/bin/env bash
set -euo pipefail

non_interactive=0
validate=0
while (($#)); do
  case "$1" in
    -n) non_interactive=1; shift ;;
    -v) validate=1; shift ;;
    --) shift; break ;;
    *) break ;;
  esac
done

if [[ "${FAKE_SUDO_DENY:-0}" == "1" ]]; then
  if ((non_interactive == 0)); then
    printf 'interactive-sudo-invoked\n' >&2
  fi
  exit 1
fi
if ((non_interactive == 0)); then
  printf 'interactive-sudo-invoked\n' >&2
  exit 97
fi
((validate == 0)) || exit 0
"$@"
SUDO
chmod 0755 "$FAKE_BIN/sudo"

export PATH="$FAKE_BIN:$PATH"
export WATCHDOGVPN_PREFLIGHT_ROOT="$TMP_DIR/preflight-root"
export WATCHDOGVPN_SHARED_STATE_DIR="$TMP_DIR/shared-state"
export WATCHDOGVPN_LEGACY_CONFIG_DIR="$TMP_DIR/legacy-state"
mkdir -p "$WATCHDOGVPN_PREFLIGHT_ROOT"

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

grep -Fq 'sudo awk -v section="$section" -v name="$name" -v value="$formatted"' "$ROOT_DIR/lib/config.sh" || {
  printf 'FAIL: shared config writer must read a private root-owned config through sudo before updating it\n' >&2
  exit 1
}
grep -Fq 'sudo install -m 0640 -o root -g watchdogvpn "$tmp" "$WATCHDOGVPN_CONFIG_FILE"' "$ROOT_DIR/lib/config.sh" || {
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
contains "$yes_output" '[DRY-RUN] set custom_vps.enabled = false'
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
custom_output="$(printf '\n\n\n\n\n\n\n\nn\nn\n' | HOME="$TMP_DIR/home" WATCHDOGVPN_ETC_CONFIG_DIR="$fresh_custom_dir" WATCHDOGVPN_CONFIG_FILE="$fresh_custom_dir/config.toml" PATH="$FAKE_BIN:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin" "$INSTALLER" --dry-run --skip-doctor 2>&1)"
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
contains "$custom_output" "Custom VPS remains disabled until a valid local systemd service name is configured"
contains "$custom_output" "[DRY-RUN] set custom_vps.enabled = false"
contains "$custom_output" "[DRY-RUN] set custom_vps.ssh_port = 22"
contains "$custom_output" "[DRY-RUN] set custom_vps.interface = \"\""
contains "$custom_output" "[DRY-RUN] smoke test watchdogvpn.service and daemon IPC status"
contains "$custom_output" "[SKIP] automatic VPN settle check; selected backend is custom-vps"
contains "$custom_output" "[SKIP] automatic runtime validation; selected backend is custom-vps"
not_contains "$custom_output" "select vpn backend"

# A real, syntactically valid local service is the only path that enables the
# compatibility backend during an interactive fresh install.
fresh_configured_dir="$TMP_DIR/fresh-configured/etc/watchdogvpn"
mkdir -p "$fresh_configured_dir"
configured_output="$(printf '\n\n\n\n\n\nwg-quick@wg0.service\nwg0\n' | HOME="$TMP_DIR/home" WATCHDOGVPN_ETC_CONFIG_DIR="$fresh_configured_dir" WATCHDOGVPN_CONFIG_FILE="$fresh_configured_dir/config.toml" PATH="$FAKE_BIN:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin" "$INSTALLER" --dry-run --skip-doctor 2>&1)"
contains "$configured_output" '[DRY-RUN] set custom_vps.enabled = true'
contains "$configured_output" '[DRY-RUN] set custom_vps.service_name = "wg-quick@wg0.service"'
not_contains "$configured_output" "Custom VPS remains disabled"

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

# A non-interactive dry-run with no cached sudo ticket must stop before it can
# classify protected paths. It must not print sudo's password/TTY noise and it
# must never claim that the mixed-install preflight passed.
set +e
denied_output="$(FAKE_SUDO_DENY=1 WATCHDOGVPN_ETC_CONFIG_DIR="$fresh_yes_dir" WATCHDOGVPN_CONFIG_FILE="$fresh_yes_dir/config.toml" "$INSTALLER" --dry-run --yes --skip-doctor </dev/null 2>&1)"
denied_rc=$?
set -e
if ((denied_rc == 0)); then
  printf 'FAIL: non-interactive dry-run without privileged read access must fail closed\n' >&2
  exit 1
fi
contains "$denied_output" "dry-run cannot inspect protected paths without cached sudo credentials"
not_contains "$denied_output" "mixed-install preflight passed"
not_contains "$denied_output" "a terminal is required"
not_contains "$denied_output" "a password is required"
not_contains "$denied_output" "interactive-sudo-invoked"

echo "install backend selection checks passed"
