#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

assert_contains() {
  local file="$1" pattern="$2" message="$3"
  if ! grep -Fq -- "$pattern" "$file"; then
    printf 'FAIL: %s\n' "$message" >&2
    printf 'missing pattern in %s: %s\n' "$file" "$pattern" >&2
    exit 1
  fi
}

# --- static wiring: install.sh/update.sh record it, doctor.sh reads it ---

assert_contains "$ROOT_DIR/lib/version_marker.sh" 'record_installed_version' "version marker lib must define a recorder"
assert_contains "$ROOT_DIR/lib/version_marker.sh" 'installed_version_commit' "version marker lib must define an installed-commit reader"
assert_contains "$ROOT_DIR/lib/version_marker.sh" 'source_checkout_commit' "version marker lib must define a source-checkout-commit reader"
assert_contains "$ROOT_DIR/lib/version_marker.sh" 'installed-provenance.json' "version marker publication must include a hashed runtime inventory"
assert_contains "$ROOT_DIR/lib/version_marker.sh" 'tools/installed_provenance.py' "version marker recorder must build provenance through the dedicated verifier"
assert_contains "$ROOT_DIR/lib/version_marker.sh" '--deployment "$WATCHDOGVPN_DAEMON_WRAPPER_PATH"' "provenance must include the active daemon wrapper"
assert_contains "$ROOT_DIR/lib/version_marker.sh" '--deployment "$WATCHDOGVPN_DAEMON_UNIT_PATH"' "provenance must include the active daemon unit"
assert_contains "$ROOT_DIR/lib/version_marker.sh" '--expected-uid 0' "provenance publication must require root ownership"
assert_contains "$ROOT_DIR/lib/version_marker.sh" '--expected-deployment-sha256 "$WATCHDOGVPN_DAEMON_WRAPPER_PATH=$wrapper_sha256"' "publication must compare the wrapper with its pre-install hash"
assert_contains "$ROOT_DIR/lib/version_marker.sh" '--expected-deployment-sha256 "$WATCHDOGVPN_DAEMON_UNIT_PATH=$unit_sha256"' "publication must compare the unit with its committed runtime copy"
assert_contains "$ROOT_DIR/tools/installed_provenance.py" 'manifest_sha256=' "version marker must bind the provenance manifest digest"
assert_contains "$ROOT_DIR/lib/runtime_transaction.sh" 'runtime_transaction_publish_installed_version' "runtime transaction must defer installed-version publication"
assert_contains "$ROOT_DIR/lib/runtime_transaction.sh" 'WATCHDOGVPN_PROVENANCE_MANIFEST' "runtime transaction must snapshot the provenance manifest"
assert_contains "$ROOT_DIR/install.sh" 'runtime_transaction_publish_installed_version' "installer must publish the marker only after runtime validation"
assert_contains "$ROOT_DIR/update.sh" 'runtime_transaction_publish_installed_version' "updater must publish the marker only after runtime validation"
assert_contains "$ROOT_DIR/install.sh" '. "$ROOT_DIR/lib/version_marker.sh"' "installer must source lib/version_marker.sh"
assert_contains "$ROOT_DIR/update.sh" '. "$ROOT_DIR/lib/version_marker.sh"' "updater must source lib/version_marker.sh"
assert_contains "$ROOT_DIR/doctor.sh" '. "$ROOT_DIR/lib/version_marker.sh"' "doctor must source lib/version_marker.sh"
assert_contains "$ROOT_DIR/doctor.sh" 'Installed/Source Version Skew' "doctor must report installed/source version skew"
assert_contains "$ROOT_DIR/doctor.sh" 'installed_version_commit' "doctor must read the installed version marker"
assert_contains "$ROOT_DIR/doctor.sh" 'source_checkout_commit' "doctor must compare against the source checkout commit"

# The marker is deliberately public metadata in the installed runtime tree so
# a normal user can run doctor without gaining access to the private 0750
# configuration directory.
assert_contains "$ROOT_DIR/lib/version_marker.sh" '/usr/local/lib/watchdogvpn/installed-version' "version marker must live in the readable installed runtime tree"
assert_contains "$ROOT_DIR/lib/version_marker.sh" 'WATCHDOGVPN_LEGACY_VERSION_MARKER' "version marker reader must retain legacy-path compatibility"
assert_contains "$ROOT_DIR/lib/version_marker.sh" 'install -d -m 0755' "version marker parent must remain readable to normal doctor runs"
assert_contains "$ROOT_DIR/doctor.sh" 'verify-daemon' "doctor must compare the active daemon generation with installed provenance"
assert_contains "$ROOT_DIR/doctor.sh" 'daemon process generation did not prove the installed runtime provenance' "doctor must fail closed when an H1 daemon omits its generation digest"
assert_contains "$ROOT_DIR/doctor.sh" 'provenance_layout_state="$(installed_provenance_layout_state)"' "doctor must classify incomplete H1 publication"

# --- behavioral: record/read/compare actually works, isolated from the real
#     system (no sudo, a throwaway marker path) ---

tmp_marker="$(mktemp -u)"
trap 'rm -f "$tmp_marker"' EXIT

dry_run_output="$(cd "$ROOT_DIR" && bash -c '
set -euo pipefail
ROOT_DIR="'"$ROOT_DIR"'"
source lib/common.sh
WATCHDOGVPN_VERSION_MARKER="'"$tmp_marker"'"
source lib/version_marker.sh
INSTALL_DRY_RUN=1 record_installed_version
' 2>&1)"
grep -Fq "[DRY-RUN] record installed version marker" <<<"$dry_run_output" || {
  printf 'FAIL: record_installed_version must skip writing under --dry-run\n' >&2
  exit 1
}
[[ ! -e "$tmp_marker" ]] || {
  printf 'FAIL: record_installed_version must not create a marker file under --dry-run\n' >&2
  exit 1
}

real_commit="$(git -C "$ROOT_DIR" rev-parse HEAD)"
printf 'commit=%s\ninstalled_at=2026-07-07T00:00:00Z\n' "$real_commit" >"$tmp_marker"

read_output="$(cd "$ROOT_DIR" && bash -c '
set -euo pipefail
ROOT_DIR="'"$ROOT_DIR"'"
source lib/common.sh
WATCHDOGVPN_VERSION_MARKER="'"$tmp_marker"'"
source lib/version_marker.sh
installed="$(installed_version_commit)"
source_commit="$(source_checkout_commit)"
if [[ "$installed" == "$source_commit" ]]; then
  echo "MATCH"
else
  echo "MISMATCH installed=$installed source=$source_commit"
fi
' 2>&1)"
grep -Fq "MATCH" <<<"$read_output" || {
  printf 'FAIL: installed_version_commit must match source_checkout_commit for a marker written from this exact checkout HEAD\n' >&2
  printf '%s\n' "$read_output" >&2
  exit 1
}

printf 'commit=0000000000000000000000000000000000000000\ninstalled_at=2020-01-01T00:00:00Z\n' >"$tmp_marker"
mismatch_output="$(cd "$ROOT_DIR" && bash -c '
set -euo pipefail
ROOT_DIR="'"$ROOT_DIR"'"
source lib/common.sh
WATCHDOGVPN_VERSION_MARKER="'"$tmp_marker"'"
source lib/version_marker.sh
installed="$(installed_version_commit)"
source_commit="$(source_checkout_commit)"
[[ "$installed" != "$source_commit" ]] && echo "MISMATCH_DETECTED" || echo "BUG_MATCHED"
' 2>&1)"
grep -Fq "MISMATCH_DETECTED" <<<"$mismatch_output" || {
  printf 'FAIL: a stale marker commit must be detected as different from the source checkout HEAD\n' >&2
  exit 1
}

rm -f "$tmp_marker"

# A pre-migration install kept its marker in /etc/watchdogvpn. Readers must
# continue to report it until a later update publishes the new runtime marker.
primary_marker="$(mktemp -u)"
legacy_marker="$(mktemp)"
trap 'rm -f "$primary_marker" "$legacy_marker"' EXIT
printf 'commit=legacy-marker\ninstalled_at=2026-07-07T00:00:00Z\n' >"$legacy_marker"
legacy_output="$(cd "$ROOT_DIR" && bash -c '
set -euo pipefail
ROOT_DIR="'"$ROOT_DIR"'"
source lib/common.sh
WATCHDOGVPN_VERSION_MARKER="'"$primary_marker"'"
WATCHDOGVPN_LEGACY_VERSION_MARKER="'"$legacy_marker"'"
source lib/version_marker.sh
printf "%s %s\n" "$(installed_version_commit)" "$(installed_version_timestamp)"
' 2>&1)"
grep -Fq 'legacy-marker 2026-07-07T00:00:00Z' <<<"$legacy_output" || {
  printf 'FAIL: version marker reader must fall back to the legacy private location\n' >&2
  exit 1
}

# Once an update has published the public marker, it is authoritative even
# when the legacy marker remains from an older install.
printf 'commit=public-marker\ninstalled_at=2026-07-17T00:00:00Z\n' >"$primary_marker"
primary_output="$(cd "$ROOT_DIR" && bash -c '
set -euo pipefail
ROOT_DIR="'"$ROOT_DIR"'"
source lib/common.sh
WATCHDOGVPN_VERSION_MARKER="'"$primary_marker"'"
WATCHDOGVPN_LEGACY_VERSION_MARKER="'"$legacy_marker"'"
source lib/version_marker.sh
printf "%s %s\n" "$(installed_version_commit)" "$(installed_version_timestamp)"
' 2>&1)"
grep -Fq 'public-marker 2026-07-17T00:00:00Z' <<<"$primary_output" || {
  printf 'FAIL: public version marker must take precedence over a legacy marker\n' >&2
  exit 1
}

layout_dir="$(mktemp -d)"
layout_marker="$layout_dir/installed-version"
layout_manifest="$layout_dir/installed-provenance.json"
# shellcheck source=../../lib/version_marker.sh
. "$ROOT_DIR/lib/version_marker.sh"
WATCHDOGVPN_VERSION_MARKER="$layout_marker"
WATCHDOGVPN_PROVENANCE_MANIFEST="$layout_manifest"
[[ "$(installed_provenance_layout_state)" == "legacy" ]] || {
  printf 'FAIL: absent H1 files must retain legacy classification\n' >&2
  exit 1
}
printf 'schema_version=2\n' >"$layout_marker"
[[ "$(installed_provenance_layout_state)" == "incomplete" ]] || {
  printf 'FAIL: schema-2 marker without manifest must be incomplete\n' >&2
  exit 1
}
rm -f "$layout_marker"
printf '{}\n' >"$layout_manifest"
[[ "$(installed_provenance_layout_state)" == "incomplete" ]] || {
  printf 'FAIL: manifest without schema-2 marker must be incomplete\n' >&2
  exit 1
}
printf 'schema_version=2\n' >"$layout_marker"
[[ "$(installed_provenance_layout_state)" == "h1" ]] || {
  printf 'FAIL: schema-2 marker and manifest must enter H1 verification\n' >&2
  exit 1
}
rm -rf "$layout_dir"

echo "version marker checks passed"
