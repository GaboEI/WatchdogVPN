#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

# shellcheck source=../../lib/common.sh
. "$ROOT_DIR/lib/common.sh"
# shellcheck source=../../lib/systemd.sh
. "$ROOT_DIR/lib/systemd.sh"
# shellcheck source=../../lib/config.sh
. "$ROOT_DIR/lib/config.sh"
# shellcheck source=../../lib/runtime.sh
. "$ROOT_DIR/lib/runtime.sh"
# shellcheck source=../../lib/install_preflight.sh
. "$ROOT_DIR/lib/install_preflight.sh"

assert_contains() {
  local haystack="$1" needle="$2" message="$3"
  if ! grep -Fq "$needle" <<<"$haystack"; then
    printf 'FAIL: %s\n' "$message" >&2
    printf 'missing: %s\n' "$needle" >&2
    printf '%s\n' "$haystack" >&2
    exit 1
  fi
}

assert_rc() {
  local expected="$1" actual="$2" message="$3"
  if [[ "$expected" != "$actual" ]]; then
    printf 'FAIL: %s (expected rc %s, got %s)\n' "$message" "$expected" "$actual" >&2
    exit 1
  fi
}

run_preflight_case() {
  local root="$1" home="$2" rc
  set +e
  output="$(HOME="$home" WATCHDOGVPN_PREFLIGHT_ROOT="$root" run_mixed_install_preflight install 2>&1)"
  rc=$?
  set -e
  printf '%s\n%s\n' "$rc" "$output"
}

make_core_install() {
  local root="$1" home="$2"
  install -d -m 0755 "$root/usr/local/bin" "$root/usr/local/lib/watchdogvpn" "$root/etc/systemd/system" "$root/var/lib/watchdogvpn" "$home/.local/bin"
  : >"$root/usr/local/bin/watchdog"
  : >"$root/usr/local/bin/watchdogvpn"
  : >"$root/usr/local/bin/watchdogvpn-daemon"
  : >"$root/etc/systemd/system/watchdogvpn.service"
}

# Fresh install: no current or legacy artifacts.
fresh_root="$TMP_DIR/fresh-root"
fresh_home="$TMP_DIR/fresh-home"
install -d -m 0755 "$fresh_root" "$fresh_home"
fresh_result="$(run_preflight_case "$fresh_root" "$fresh_home")"
fresh_rc="$(printf '%s\n' "$fresh_result" | sed -n '1p')"
fresh_output="$(printf '%s\n' "$fresh_result" | sed '1d')"
assert_rc 0 "$fresh_rc" "fresh preflight must pass"
assert_contains "$fresh_output" "Machine state:         fresh install" "fresh install must be classified"
assert_contains "$fresh_output" "[ABSENT] /usr/local/bin/watchdogvpn" "fresh output must list absent runtime wrappers"
assert_contains "$fresh_output" "[ABSENT] /var/lib/watchdogvpn" "fresh output must list preserved state paths"

# Clean update: all current core paths exist.
clean_root="$TMP_DIR/clean-root"
clean_home="$TMP_DIR/clean-home"
make_core_install "$clean_root" "$clean_home"
clean_result="$(run_preflight_case "$clean_root" "$clean_home")"
clean_rc="$(printf '%s\n' "$clean_result" | sed -n '1p')"
clean_output="$(printf '%s\n' "$clean_result" | sed '1d')"
assert_rc 0 "$clean_rc" "clean update preflight must pass"
assert_contains "$clean_output" "Machine state:         clean update" "clean update must be classified"
assert_contains "$clean_output" "[REPLACE] /usr/local/bin/watchdogvpn" "clean output must print replaced wrapper"
assert_contains "$clean_output" "[PRESERVE] /var/lib/watchdogvpn" "clean output must print preserved state when present"

# Legacy migration: known-dead legacy artifacts and per-user state are safe
# because product-managed legacy files are removed, while user data is
# preserved/migrated without source deletion.
legacy_root="$TMP_DIR/legacy-root"
legacy_home="$TMP_DIR/legacy-home"
install -d -m 0755 "$legacy_root/usr/local/bin" "$legacy_root/etc/systemd/system" "$legacy_home/.config/watchdogvpn"
: >"$legacy_root/usr/local/bin/vpn_auth_check"
: >"$legacy_root/etc/systemd/system/adguardvpn.service"
printf 'legacy\n' >"$legacy_home/.config/watchdogvpn/profiles.json"
legacy_result="$(run_preflight_case "$legacy_root" "$legacy_home")"
legacy_rc="$(printf '%s\n' "$legacy_result" | sed -n '1p')"
legacy_output="$(printf '%s\n' "$legacy_result" | sed '1d')"
assert_rc 0 "$legacy_rc" "legacy migration preflight must pass"
assert_contains "$legacy_output" "Machine state:         legacy migration" "legacy migration must be classified"
assert_contains "$legacy_output" "[REMOVE] /usr/local/bin/vpn_auth_check" "legacy product artifact must be reported for removal"
assert_contains "$legacy_output" "shared-state migration copies with no overwrite and keeps the source" "legacy repair path must be documented"

# Mixed/inconsistent: only part of the current core install exists.
mixed_root="$TMP_DIR/mixed-root"
mixed_home="$TMP_DIR/mixed-home"
install -d -m 0755 "$mixed_root/usr/local/bin" "$mixed_home"
: >"$mixed_root/usr/local/bin/watchdogvpn"
mixed_result="$(run_preflight_case "$mixed_root" "$mixed_home")"
mixed_rc="$(printf '%s\n' "$mixed_result" | sed -n '1p')"
mixed_output="$(printf '%s\n' "$mixed_result" | sed '1d')"
assert_rc 1 "$mixed_rc" "mixed preflight must block"
assert_contains "$mixed_output" "Machine state:         mixed-inconsistent" "mixed install must be classified"
assert_contains "$mixed_output" "[BLOCK] partial current install detected" "mixed install must print block reason"

# Unsupported: a file destination is occupied by a directory.
unsupported_root="$TMP_DIR/unsupported-root"
unsupported_home="$TMP_DIR/unsupported-home"
install -d -m 0755 "$unsupported_root/usr/local/bin/watchdogvpn" "$unsupported_home"
unsupported_result="$(run_preflight_case "$unsupported_root" "$unsupported_home")"
unsupported_rc="$(printf '%s\n' "$unsupported_result" | sed -n '1p')"
unsupported_output="$(printf '%s\n' "$unsupported_result" | sed '1d')"
assert_rc 1 "$unsupported_rc" "unsupported preflight must block"
assert_contains "$unsupported_output" "Machine state:         unsupported" "unsupported state must be classified"
assert_contains "$unsupported_output" "expected file path is a directory: /usr/local/bin/watchdogvpn" "unsupported path shape must be reported"

# Unsupported backend config: preserving it would leave the installed runtime
# with a backend name that the shipped backend helper already rejects.
unsupported_backend_root="$TMP_DIR/unsupported-backend-root"
unsupported_backend_home="$TMP_DIR/unsupported-backend-home"
install -d -m 0755 "$unsupported_backend_root/etc/watchdogvpn" "$unsupported_backend_home"
cat >"$unsupported_backend_root/etc/watchdogvpn/config.toml" <<'CFG'
[backend]
mode = "legacy-vpn"
active = "legacy-vpn"
CFG
unsupported_backend_result="$(run_preflight_case "$unsupported_backend_root" "$unsupported_backend_home")"
unsupported_backend_rc="$(printf '%s\n' "$unsupported_backend_result" | sed -n '1p')"
unsupported_backend_output="$(printf '%s\n' "$unsupported_backend_result" | sed '1d')"
assert_rc 1 "$unsupported_backend_rc" "unsupported backend preflight must block"
assert_contains "$unsupported_backend_output" "Machine state:         unsupported" "unsupported backend state must be classified"
assert_contains "$unsupported_backend_output" "unsupported configured backend in /etc/watchdogvpn/config.toml" "unsupported backend must be reported"

printf 'mixed install preflight checks passed\n'
