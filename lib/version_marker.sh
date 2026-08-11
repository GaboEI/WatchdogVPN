#!/usr/bin/env bash
set -euo pipefail

# Publishes a hashed inventory for the installed daemon generation. The public
# marker contains only non-secret provenance metadata so a normal doctor run can
# verify it without access to the private configuration directory.
WATCHDOGVPN_VERSION_MARKER="${WATCHDOGVPN_VERSION_MARKER:-/usr/local/lib/watchdogvpn/installed-version}"
WATCHDOGVPN_LEGACY_VERSION_MARKER="${WATCHDOGVPN_LEGACY_VERSION_MARKER:-${WATCHDOGVPN_ETC_CONFIG_DIR:-/etc/watchdogvpn}/installed-version}"
WATCHDOGVPN_PROVENANCE_MANIFEST="${WATCHDOGVPN_PROVENANCE_MANIFEST:-/usr/local/lib/watchdogvpn/installed-provenance.json}"
WATCHDOGVPN_DAEMON_WRAPPER_PATH="/usr/local/bin/watchdogvpn-daemon"
WATCHDOGVPN_DAEMON_UNIT_PATH="/etc/systemd/system/watchdogvpn.service"

record_installed_version() {
  local timestamp marker_tmp manifest_tmp python_bin unit_sha256 wrapper_sha256
  local -a provenance_args

  if [[ "${INSTALL_DRY_RUN:-0}" == "1" ]]; then
    printf '[DRY-RUN] record installed version marker at %s\n' "$WATCHDOGVPN_VERSION_MARKER"
    return 0
  fi

  timestamp="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  marker_tmp="$(mktemp)"
  manifest_tmp="$(mktemp)"
  python_bin="$(watchdogvpn_python)" || {
    rm -f "$marker_tmp" "$manifest_tmp"
    return 1
  }
  wrapper_sha256="${WATCHDOGVPN_EXPECTED_DAEMON_WRAPPER_SHA256:-}"
  unit_sha256="$(sha256sum "${PYTHON_PACKAGE_DIR:-/usr/local/lib/watchdogvpn}/systemd/watchdogvpn.service" | awk 'NR == 1 {print $1}')" || {
    rm -f "$marker_tmp" "$manifest_tmp"
    return 1
  }
  if [[ ! "$wrapper_sha256" =~ ^[0-9a-f]{64}$ || ! "$unit_sha256" =~ ^[0-9a-f]{64}$ ]]; then
    rm -f "$marker_tmp" "$manifest_tmp"
    printf 'ERROR: cannot establish expected daemon deployment hashes\n' >&2
    return 1
  fi
  case "${WATCHDOGVPN_VERIFIED_GENERATION_SHA256:-pending}" in
    inactive)
      ;;
    [0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f]*)
      if [[ ! "$WATCHDOGVPN_VERIFIED_GENERATION_SHA256" =~ ^[0-9a-f]{64}$ ]]; then
        printf 'ERROR: daemon-approved generation digest is invalid\n' >&2
        rm -f "$marker_tmp" "$manifest_tmp"
        return 1
      fi
      ;;
    *)
      printf 'ERROR: installed provenance publication requires a completed daemon generation smoke\n' >&2
      rm -f "$marker_tmp" "$manifest_tmp"
      return 1
      ;;
  esac
  provenance_args=(
    "$python_bin"
    "$ROOT_DIR/tools/installed_provenance.py"
    build
    --source-root "$ROOT_DIR"
    --installed-root "${PYTHON_PACKAGE_DIR:-/usr/local/lib/watchdogvpn}"
    --installed-at "$timestamp"
    --output "$manifest_tmp"
    --marker-output "$marker_tmp"
    --deployment "$WATCHDOGVPN_DAEMON_WRAPPER_PATH"
    --deployment "$WATCHDOGVPN_DAEMON_UNIT_PATH"
    --expected-deployment-sha256 "$WATCHDOGVPN_DAEMON_WRAPPER_PATH=$wrapper_sha256"
    --expected-deployment-sha256 "$WATCHDOGVPN_DAEMON_UNIT_PATH=$unit_sha256"
    --expected-uid 0
    --expected-gid 0
  )
  if [[ "$WATCHDOGVPN_VERIFIED_GENERATION_SHA256" != "inactive" ]]; then
    provenance_args+=(--expected-generation-sha256 "$WATCHDOGVPN_VERIFIED_GENERATION_SHA256")
  fi
  local item
  for item in \
    "${PYTHON_RUNTIME_PACKAGES[@]}" \
    "${PYTHON_RUNTIME_SUPPORT_FILES[@]}" \
    "${PYTHON_RUNTIME_SUPPORT_DIRS[@]}"
  do
    provenance_args+=(--include "$item")
  done
  if ! "${provenance_args[@]}"; then
    rm -f "$marker_tmp" "$manifest_tmp"
    return 1
  fi
  run_step sudo install -d -m 0755 -o root -g root "$(dirname "$WATCHDOGVPN_VERSION_MARKER")"
  if ! run_step sudo install -m 0644 -o root -g root "$manifest_tmp" "$WATCHDOGVPN_PROVENANCE_MANIFEST" \
    || ! run_step sudo install -m 0644 -o root -g root "$marker_tmp" "$WATCHDOGVPN_VERSION_MARKER"; then
    rm -f "$marker_tmp" "$manifest_tmp"
    return 1
  fi
  rm -f "$marker_tmp" "$manifest_tmp"
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

installed_provenance_layout_state() {
  local marker_h1=0 marker_present=0 manifest_present=0
  [[ -e "$WATCHDOGVPN_VERSION_MARKER" ]] && marker_present=1
  [[ -e "$WATCHDOGVPN_PROVENANCE_MANIFEST" ]] && manifest_present=1
  if ((marker_present == 1)) \
    && grep -Fxq 'schema_version=2' "$WATCHDOGVPN_VERSION_MARKER" 2>/dev/null; then
    marker_h1=1
  fi
  if ((marker_h1 == 1 && manifest_present == 1)); then
    printf 'h1\n'
  elif ((marker_h1 == 1 || manifest_present == 1)); then
    printf 'incomplete\n'
  else
    printf 'legacy\n'
  fi
}

source_checkout_commit() {
  git -C "$ROOT_DIR" rev-parse HEAD 2>/dev/null
}
