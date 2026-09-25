#!/usr/bin/env bash
set -euo pipefail

# T-PR23-09: a recognised legacy installation with absent schema-2/H1
# provenance must be diagnosable (WARN) and migratable, while incomplete or
# malformed provenance must stay fail-closed (FAIL). These are behavioral
# checks: the real doctor.sh is run with marker/manifest paths redirected into
# a throwaway directory, so no system state is touched and no root is needed.

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

assert_contains() {
  local file="$1" pattern="$2" message="$3"
  if ! grep -Fq -- "$pattern" "$file"; then
    printf 'FAIL: %s\n' "$message" >&2
    printf 'missing pattern in %s: %s\n' "$file" "$pattern" >&2
    exit 1
  fi
}

assert_contains "$ROOT_DIR/doctor.sh" 'mark_warn "installed runtime uses a legacy layout without schema-2 hashed provenance"' "doctor must warn, not fail, for a migratable legacy layout"
assert_contains "$ROOT_DIR/doctor.sh" 'mark_fail "installed runtime has incomplete hashed provenance"' "doctor must still fail closed for incomplete provenance"
assert_contains "$ROOT_DIR/update.sh" 'if (( doctor_preflight_rc != 0 )); then' "updater must abort on any non-zero doctor exit"

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

run_doctor() {
  local rc out
  set +e
  out="$(cd "$ROOT_DIR" && WATCHDOGVPN_VERSION_MARKER="$tmp/installed-version" \
    WATCHDOGVPN_PROVENANCE_MANIFEST="$tmp/installed-provenance.json" \
    WATCHDOGVPN_LEGACY_VERSION_MARKER="$tmp/legacy-installed-version" \
    bash doctor.sh 2>&1)"
  rc=$?
  set -e
  printf '%s' "$rc"
  printf '\n---\n%s' "$out"
}

# Recognised legacy install: a legacy marker exists, no schema-2/H1 provenance.
printf 'commit=cafebabecafebabecafebabecafebabecafebabe\ninstalled_at=2026-01-01T00:00:00Z\n' >"$tmp/legacy-installed-version"
legacy_result="$(run_doctor)"
legacy_rc="${legacy_result%%$'\n---'*}"
legacy_out="${legacy_result#*$'\n---'$'\n'}"
if [[ "$legacy_rc" != "0" ]]; then
  printf 'FAIL: recognised legacy layout must not fail doctor (rc=%s)\n' "$legacy_rc" >&2
  printf '%s\n' "$legacy_out" >&2
  exit 1
fi
grep -Fq '[WARN] installed runtime uses a legacy layout without schema-2 hashed provenance' <<<"$legacy_out" || {
  printf 'FAIL: recognised legacy layout must be reported as a migratable warning\n' >&2
  printf '%s\n' "$legacy_out" >&2
  exit 1
}
grep -Fq 'no attributable hashed provenance' <<<"$legacy_out" && {
  printf 'FAIL: recognised legacy layout must not be reported as a missing-provenance failure\n' >&2
  printf '%s\n' "$legacy_out" >&2
  exit 1
} || true

# Incomplete: schema-2 marker present but manifest absent.
printf 'schema_version=2\n' >"$tmp/installed-version"
rm -f "$tmp/installed-provenance.json"
incomplete_result="$(run_doctor)"
incomplete_rc="${incomplete_result%%$'\n---'*}"
incomplete_out="${incomplete_result#*$'\n---'$'\n'}"
if [[ "$incomplete_rc" == "0" ]]; then
  printf 'FAIL: incomplete provenance must stay fail-closed\n' >&2
  printf '%s\n' "$incomplete_out" >&2
  exit 1
fi
grep -Fq 'incomplete hashed provenance' <<<"$incomplete_out" || {
  printf 'FAIL: incomplete provenance must be diagnosed as incomplete\n' >&2
  printf '%s\n' "$incomplete_out" >&2
  exit 1
}

echo "doctor legacy provenance checks passed"

# ---------------------------------------------------------------------------
# F-01: the update preflight must be fail-closed. It may continue ONLY for a
# recognised, migratable legacy condition; every other doctor failure aborts
# before any destructive step. This exercises the real update.sh boundary by
# extracting and running the exact preflight block with doctor.sh stubbed, so no
# system state is touched.
# ---------------------------------------------------------------------------

update_preflight_block="$(awk '/^if \(\(RUN_DOCTOR == 1\)\); then$/{f=1} f{print} f&&/^fi$/{exit}' "$ROOT_DIR/update.sh")"
[[ -n "$update_preflight_block" ]] || { printf 'FAIL: could not extract update preflight\n' >&2; exit 1; }

run_preflight() {
  # $1 = stub doctor exit code, $2 = stub doctor stdout
  local rc="$1" out="$2" dir got
  dir="$(mktemp -d)"
  mkdir -p "$dir/lib"
  cp "$ROOT_DIR/lib/"*.sh "$dir/lib/" 2>/dev/null || true
  # Stub doctor.sh: emit the configured output and exit with the configured code.
  {
    printf '#!/usr/bin/env bash\n'
    printf 'printf "%%s\\n" %q\n' "$out"
    printf 'exit %s\n' "$rc"
  } >"$dir/doctor.sh"
  chmod +x "$dir/doctor.sh"
  set +e
  ROOT_DIR="$dir" RUN_DOCTOR=1 bash -c '
    set -euo pipefail
    fail() { printf "[FAIL] %s\n" "$*" >&2; }
    warn() { printf "[WARN] %s\n" "$*" >&2; }
    print_section() { :; }
    '"$update_preflight_block"'
  ' >/dev/null 2>&1
  got=$?
  set -e
  rm -rf "$dir"
  printf '%s' "$got"
}

# (a) recognised legacy migratable state must reach the next stage (exit 0)
[[ "$(run_preflight 0 'LEGACY_MIGRATABLE=1')" == "0" ]] || {
  printf 'FAIL: recognised legacy migratable state must not abort the update\n' >&2; exit 1; }

# (b)+(c) incomplete/malformed/unverifiable provenance (doctor exit 1) aborts
[[ "$(run_preflight 1 'FAIL')" != "0" ]] || {
  printf 'FAIL: non-zero doctor exit must abort the update\n' >&2; exit 1; }

# (d) healthy host: doctor exit 0 without the legacy signal still proceeds safely
[[ "$(run_preflight 0 'OK=1 WARN=0 FAIL=0')" == "0" ]] || {
  printf 'FAIL: healthy doctor exit 0 must allow the update\n' >&2; exit 1; }

# Wiring assertions for the precise boundary.
assert_contains "$ROOT_DIR/doctor.sh" "printf 'LEGACY_MIGRATABLE=%d\n' \"\$DOCTOR_LEGACY_MIGRATABLE\"" "doctor must emit the machine-readable legacy signal"
assert_contains "$ROOT_DIR/update.sh" "if (( doctor_preflight_rc != 0 )); then" "updater must abort on a non-zero doctor exit"
assert_contains "$ROOT_DIR/update.sh" "if grep -Fxq 'LEGACY_MIGRATABLE=1' <<<\"\$doctor_preflight_output\"; then" "updater must continue only on the recognised legacy signal"

echo "update preflight boundary checks passed"
