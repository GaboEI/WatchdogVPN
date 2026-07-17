#!/usr/bin/env bash
set -euo pipefail

# Records which source commit was actually installed, so doctor.sh (and
# later Task 18.7 work) can detect drift between the installed runtime and
# the current source checkout instead of only trusting the hand-edited
# VERSION string in the bin/watchdogvpn compatibility alias, which does not change when the
# installed copy falls behind. Written by install.sh and update.sh every
# time install_python_package_tree() runs; read by doctor.sh. It intentionally
# lives in the public runtime tree: the marker contains only a commit and an
# install timestamp, while the 0750 configuration directory must remain
# unreadable to normal users. A normal `./doctor.sh` must still be able to
# report installed/source skew without sudo.
WATCHDOGVPN_VERSION_MARKER="${WATCHDOGVPN_VERSION_MARKER:-/usr/local/lib/watchdogvpn/installed-version}"
WATCHDOGVPN_LEGACY_VERSION_MARKER="${WATCHDOGVPN_LEGACY_VERSION_MARKER:-${WATCHDOGVPN_ETC_CONFIG_DIR:-/etc/watchdogvpn}/installed-version}"

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
  run_step sudo install -d -m 0755 -o root -g root "$(dirname "$WATCHDOGVPN_VERSION_MARKER")"
  run_step sudo install -m 0644 -o root -g root "$tmp" "$WATCHDOGVPN_VERSION_MARKER"
  rm -f "$tmp"
}

installed_version_marker_path() {
  if [[ -r "$WATCHDOGVPN_VERSION_MARKER" ]]; then
    printf '%s\n' "$WATCHDOGVPN_VERSION_MARKER"
  elif [[ -r "$WATCHDOGVPN_LEGACY_VERSION_MARKER" ]]; then
    printf '%s\n' "$WATCHDOGVPN_LEGACY_VERSION_MARKER"
  else
    return 1
  fi
}

installed_version_commit() {
  local marker
  marker="$(installed_version_marker_path)" || return 1
  awk -F= '$1 == "commit" {print $2; exit}' "$marker"
}

installed_version_timestamp() {
  local marker
  marker="$(installed_version_marker_path)" || return 1
  awk -F= '$1 == "installed_at" {print $2; exit}' "$marker"
}

source_checkout_commit() {
  git -C "$ROOT_DIR" rev-parse HEAD 2>/dev/null
}
