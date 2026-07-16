#!/usr/bin/env bash
set -euo pipefail

# Records which source commit was actually installed, so doctor.sh (and
# later Task 18.7 work) can detect drift between the installed runtime and
# the current source checkout instead of only trusting the hand-edited
# VERSION string in the bin/watchdogvpn compatibility alias, which does not change when the
# installed copy falls behind. Written by install.sh and update.sh every
# time install_python_package_tree() runs; read by doctor.sh.
WATCHDOGVPN_VERSION_MARKER="${WATCHDOGVPN_VERSION_MARKER:-${WATCHDOGVPN_ETC_CONFIG_DIR:-/etc/watchdogvpn}/installed-version}"

record_installed_version() {
  local commit timestamp tmp

  if [[ "${INSTALL_DRY_RUN:-0}" == "1" ]]; then
    printf '[DRY-RUN] record installed version marker at %s\n' "$WATCHDOGVPN_VERSION_MARKER"
    return 0
  fi

  if git -C "$ROOT_DIR" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
    commit="$(git -C "$ROOT_DIR" rev-parse HEAD)"
  else
    commit="unknown"
  fi
  timestamp="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

  tmp="$(mktemp)"
  {
    printf 'commit=%s\n' "$commit"
    printf 'installed_at=%s\n' "$timestamp"
  } >"$tmp"
  # 0750, not 0755: WATCHDOGVPN_VERSION_MARKER defaults to a file directly
  # inside /etc/watchdogvpn (lib/config.sh's WATCHDOGVPN_ETC_CONFIG_DIR),
  # which install_config_defaults() already creates at 0750 to match
  # systemd/watchdogvpn.service's ConfigurationDirectoryMode=0750. This
  # defensive parent-dir creation ran later in every install and silently
  # clobbered that back to 0755 every time (install -d re-applies the mode
  # on an already-existing directory), reproducing the exact mode-mismatch
  # warning that fix was supposed to close for good.
  run_step sudo install -d -m 0750 -o root -g root "$(dirname "$WATCHDOGVPN_VERSION_MARKER")"
  run_step sudo install -m 0644 -o root -g root "$tmp" "$WATCHDOGVPN_VERSION_MARKER"
  rm -f "$tmp"
}

installed_version_commit() {
  [[ -r "$WATCHDOGVPN_VERSION_MARKER" ]] || return 1
  awk -F= '$1 == "commit" {print $2; exit}' "$WATCHDOGVPN_VERSION_MARKER"
}

installed_version_timestamp() {
  [[ -r "$WATCHDOGVPN_VERSION_MARKER" ]] || return 1
  awk -F= '$1 == "installed_at" {print $2; exit}' "$WATCHDOGVPN_VERSION_MARKER"
}

source_checkout_commit() {
  git -C "$ROOT_DIR" rev-parse HEAD 2>/dev/null
}
