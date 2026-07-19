#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SYSCTL_FILE="$ROOT_DIR/etc/sysctl.d/99-watchdogvpn.conf"
RUNTIME_LIB="$ROOT_DIR/lib/runtime.sh"
DRIVER="$ROOT_DIR/drivers/amneziawg_driver.py"

fail() {
  printf 'FAIL: %s\n' "$*" >&2
  exit 1
}

assert_contains() {
  local file="$1" pattern="$2" message="$3"
  grep -Fq "$pattern" "$file" || fail "$message"
}

[[ -f "$SYSCTL_FILE" ]] || fail "missing sysctl defaults file: $SYSCTL_FILE"
assert_contains "$SYSCTL_FILE" "net.ipv4.conf.all.src_valid_mark = 1" \
  "sysctl defaults must enable src_valid_mark for fwmark policy routing"
assert_contains "$SYSCTL_FILE" "net.ipv4.conf.default.src_valid_mark = 1" \
  "sysctl defaults must also set conf.default so newly created interfaces inherit it (all alone is not reliable)"

assert_contains "$RUNTIME_LIB" "install_sysctl_defaults" \
  "install_runtime_files must call install_sysctl_defaults"
assert_contains "$RUNTIME_LIB" "capture_sysctl_defaults_baseline" \
  "install must capture the preexisting sysctl file and live values"
assert_contains "$RUNTIME_LIB" "restore_sysctl_defaults_baseline" \
  "uninstall must have an exact sysctl baseline restoration path"
assert_contains "$RUNTIME_LIB" "install_root_file \"\$runtime_root/etc/sysctl.d/99-watchdogvpn.conf\" \"\$SYSCTL_DEFAULTS_PATH\"" \
  "install_sysctl_defaults must install the tracked sysctl.d file"
assert_contains "$RUNTIME_LIB" "sudo sysctl -q -p \"\$SYSCTL_DEFAULTS_PATH\"" \
  "install_sysctl_defaults must apply the sysctl file at install/update time"
assert_contains "$ROOT_DIR/uninstall.sh" "restore_sysctl_defaults_baseline" \
  "uninstall must restore the captured sysctl baseline before deleting runtime files"

(
  TMP_DIR="$(mktemp -d)"
  trap 'rm -rf "$TMP_DIR"' EXIT
  # shellcheck disable=SC1090
  source "$ROOT_DIR/lib/install_files.sh"
  # shellcheck disable=SC1090
  source "$ROOT_DIR/lib/runtime.sh"
  SYSCTL_DEFAULTS_PATH="$TMP_DIR/99-watchdogvpn.conf"
  SYSCTL_BASELINE_DIR="$TMP_DIR/baseline"
  SYSCTL_BASELINE_MANIFEST="$SYSCTL_BASELINE_DIR/manifest"
  SYSCTL_BASELINE_FILE="$SYSCTL_BASELINE_DIR/defaults.before"
  SRC_VALID_MARK_ALL_PATH="$TMP_DIR/all"
  SRC_VALID_MARK_DEFAULT_PATH="$TMP_DIR/default"
  SYSCTL_INSTALLED_MARKER_PATH="$TMP_DIR/installed-version"
  printf '0\n' >"$SRC_VALID_MARK_ALL_PATH"
  printf '1\n' >"$SRC_VALID_MARK_DEFAULT_PATH"
  printf 'preexisting = true\n' >"$SYSCTL_DEFAULTS_PATH"
  sudo() {
    if [[ "$1" == "install" ]]; then
      shift
      local -a filtered=()
      while (($#)); do
        case "$1" in
          -o|-g) shift 2 ;;
          *) filtered+=("$1"); shift ;;
        esac
      done
      command install "${filtered[@]}"
      return
    fi
    "$@"
  }
  run_privileged_readonly() { "$@"; }
  root_path_exists() { [[ -e "$1" || -L "$1" ]]; }
  root_path_is_file() { [[ -f "$1" ]]; }
  remove_root_path_no_backup() { rm -rf -- "$1"; }

  capture_sysctl_defaults_baseline
  printf '1\n' >"$SRC_VALID_MARK_ALL_PATH"
  printf '0\n' >"$SRC_VALID_MARK_DEFAULT_PATH"
  printf 'product = true\n' >"$SYSCTL_DEFAULTS_PATH"
  restore_sysctl_defaults_baseline
  [[ "$(cat "$SRC_VALID_MARK_ALL_PATH")" == "0" ]] || fail "all.src_valid_mark baseline was not restored"
  [[ "$(cat "$SRC_VALID_MARK_DEFAULT_PATH")" == "1" ]] || fail "default.src_valid_mark baseline was not restored"
  grep -Fxq 'preexisting = true' "$SYSCTL_DEFAULTS_PATH" || fail "preexisting sysctl file was not restored"
  [[ -f "$SYSCTL_BASELINE_MANIFEST" ]] || fail "sysctl baseline must survive for idempotent uninstall retry"

  rm -rf -- "$SYSCTL_BASELINE_DIR"
  rm -f -- "$SYSCTL_DEFAULTS_PATH"
  printf '0\n' >"$SRC_VALID_MARK_ALL_PATH"
  printf '0\n' >"$SRC_VALID_MARK_DEFAULT_PATH"
  capture_sysctl_defaults_baseline
  printf 'product = true\n' >"$SYSCTL_DEFAULTS_PATH"
  printf '1\n' >"$SRC_VALID_MARK_ALL_PATH"
  printf '1\n' >"$SRC_VALID_MARK_DEFAULT_PATH"
  restore_sysctl_defaults_baseline
  [[ ! -e "$SYSCTL_DEFAULTS_PATH" ]] || fail "product sysctl file survived an absent-file baseline restore"
  [[ "$(cat "$SRC_VALID_MARK_ALL_PATH")" == "0" && "$(cat "$SRC_VALID_MARK_DEFAULT_PATH")" == "0" ]] \
    || fail "absent-file live sysctl baseline was not restored"

  rm -rf -- "$SYSCTL_BASELINE_DIR"
  printf 'legacy product marker\n' >"$SYSCTL_INSTALLED_MARKER_PATH"
  printf 'product = true\n' >"$SYSCTL_DEFAULTS_PATH"
  printf '1\n' >"$SRC_VALID_MARK_ALL_PATH"
  printf '1\n' >"$SRC_VALID_MARK_DEFAULT_PATH"
  restore_sysctl_defaults_baseline
  grep -Fxq 'origin=legacy-inferred' "$SYSCTL_BASELINE_MANIFEST" \
    || fail "direct uninstall did not classify the pre-journal installation as a legacy migration"
  grep -Fxq 'file_present=0' "$SYSCTL_BASELINE_MANIFEST" \
    || fail "legacy product sysctl file was misclassified as user-owned"
  [[ ! -e "$SYSCTL_DEFAULTS_PATH" ]] || fail "legacy product sysctl file survived migration restore"
  [[ "$(cat "$SRC_VALID_MARK_ALL_PATH")" == "0" && "$(cat "$SRC_VALID_MARK_DEFAULT_PATH")" == "0" ]] \
    || fail "legacy live sysctl values were not restored to the kernel defaults"
)

# The daemon runs under ProtectKernelTunables=true and cannot write kernel
# tunables itself (see systemd/watchdogvpn.service); the driver must only
# ever read this value at connect time, never try to set it live.
if grep -Fq '"sysctl"' "$DRIVER"; then
  fail "AmneziaWGDriver must not shell out to sysctl; ProtectKernelTunables=true blocks it at runtime"
fi
assert_contains "$DRIVER" "_src_valid_mark_path" \
  "AmneziaWGDriver must read the interface's own src_valid_mark tunable instead of writing it"

printf 'amneziawg sysctl defaults checks passed\n'
