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

# Recognised legacy marker. The outcome depends on whether an installed runtime
# (a product binary) is present on this host: with a runtime, doctor warns and
# signals LEGACY_MIGRATABLE=1; without a runtime, doctor reports a lone
# preserved marker and signals 0 (F-06). Both are correct; assert whichever the
# host's state implies, and never the inverse.
printf 'commit=cafebabecafebabecafebabecafebabecafebabe\ninstalled_at=2026-01-01T00:00:00Z\n' >"$tmp/legacy-installed-version"
legacy_result="$(run_doctor)"
legacy_out="${legacy_result#*$'\n---'$'\n'}"
runtime_present=0
for b in /usr/local/bin/watchdog /usr/local/bin/watchdogvpn /usr/local/bin/watchdogvpn-daemon /usr/local/bin/vpnctl /usr/local/bin/vpn_truth_check; do
  [[ -e "$b" ]] && runtime_present=1
done
legacy_signal="$(grep -o 'LEGACY_MIGRATABLE=[01]' <<<"$legacy_out" | tail -1)"
legacy_fails="$(grep -oE 'FAIL=[0-9]+' <<<"$legacy_out" | tail -1)"
if (( runtime_present == 1 && legacy_fails == 0 )); then
  grep -Fq '[WARN] installed runtime uses a legacy layout without schema-2 hashed provenance' <<<"$legacy_out" || {
    printf 'FAIL: with a runtime, a recognised legacy layout must be a migratable warning\n' >&2
    printf '%s\n' "$legacy_out" >&2
    exit 1
  }
  [[ "$legacy_signal" == "LEGACY_MIGRATABLE=1" ]] || {
    printf 'FAIL: with a runtime, legacy-only must emit LEGACY_MIGRATABLE=1\n' >&2
    printf '%s\n' "$legacy_out" >&2; exit 1; }
else
  grep -Fq 'only a preserved version marker is present; no installed runtime detected' <<<"$legacy_out" || {
    printf 'FAIL: without a runtime, a lone preserved marker must be reported as no installed runtime\n' >&2
    printf '%s\n' "$legacy_out" >&2
    exit 1
  }
  [[ "$legacy_signal" == "LEGACY_MIGRATABLE=0" ]] || {
    printf 'FAIL: without a runtime, the legacy signal must be 0\n' >&2
    printf '%s\n' "$legacy_out" >&2; exit 1; }
fi
grep -Fq 'no attributable hashed provenance' <<<"$legacy_out" && {
  printf 'FAIL: recognised legacy layout must not be reported as a missing-provenance failure\n' >&2
  printf '%s\n' "$legacy_out" >&2
  exit 1
} || true
if [[ "$legacy_fails" != "FAIL=0" && "$legacy_signal" != "LEGACY_MIGRATABLE=0" ]]; then
  printf 'FAIL: legacy signal must be 0 when other failures are present\n' >&2
  printf '%s\n' "$legacy_out" >&2
  exit 1
fi

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

# (c2) legacy signal MUST be suppressed when other failures are present:
# doctor.sh forces LEGACY_MIGRATABLE=0 whenever FAIL_COUNT>0, so an update on a
# host with real failures cannot continue even if the layout is legacy.
assert_contains "$ROOT_DIR/doctor.sh" 'if (( FAIL_COUNT > 0 )); then
  DOCTOR_LEGACY_MIGRATABLE=0
fi' "doctor must suppress the legacy signal when any failure is present"

# (d) healthy host: doctor exit 0 without the legacy signal still proceeds safely
[[ "$(run_preflight 0 'OK=1 WARN=0 FAIL=0')" == "0" ]] || {
  printf 'FAIL: healthy doctor exit 0 must allow the update\n' >&2; exit 1; }

# Wiring assertions for the precise boundary.
assert_contains "$ROOT_DIR/doctor.sh" "printf 'LEGACY_MIGRATABLE=%d\n' \"\$DOCTOR_LEGACY_MIGRATABLE\"" "doctor must emit the machine-readable legacy signal"
assert_contains "$ROOT_DIR/update.sh" "if (( doctor_preflight_rc != 0 )); then" "updater must abort on a non-zero doctor exit"
assert_contains "$ROOT_DIR/update.sh" "if grep -Fxq 'LEGACY_MIGRATABLE=1' <<<\"\$doctor_preflight_output\"; then" "updater must continue only on the recognised legacy signal"

echo "update preflight boundary checks passed"

# ---------------------------------------------------------------------------
# F-06: a preserved legacy marker with no installed runtime must NOT be
# reported as a migratable installation. installed_runtime_present() is the
# gate; prove it is false when no product binary exists and that doctor.sh
# consults it.
# ---------------------------------------------------------------------------
assert_contains "$ROOT_DIR/lib/version_marker.sh" 'installed_runtime_present()' "version_marker must define an installed-runtime presence check"
assert_contains "$ROOT_DIR/doctor.sh" 'elif ! installed_runtime_present; then' "doctor must gate the legacy signal on an installed runtime being present"
assert_contains "$ROOT_DIR/doctor.sh" 'only a preserved version marker is present; no installed runtime detected' "doctor must explain a lone preserved marker"

# Behavioural: with no product binaries on PATH-ish standard locations, the
# helper must return non-zero. Run in a subshell with a stubbed check by
# sourcing the lib and overriding nothing but relying on the real filesystem;
# use the lib function directly against a fake root via its fixed paths is not
# possible, so assert the predicate logic on the current host is consistent:
# if all five binaries are absent then the helper must fail (return 1).
binaries_present=0
for b in /usr/local/bin/watchdog /usr/local/bin/watchdogvpn /usr/local/bin/watchdogvpn-daemon /usr/local/bin/vpnctl /usr/local/bin/vpn_truth_check; do
  [[ -e "$b" ]] && binaries_present=1
done
set +e
( . "$ROOT_DIR/lib/common.sh" 2>/dev/null || true; . "$ROOT_DIR/lib/version_marker.sh"; installed_runtime_present )
pred_rc=$?
set -e
if (( binaries_present == 0 )); then
  [[ "$pred_rc" -ne 0 ]] || { printf 'FAIL: installed_runtime_present must be false with no binaries\n' >&2; exit 1; }
else
  [[ "$pred_rc" -eq 0 ]] || { printf 'FAIL: installed_runtime_present must be true when binaries exist\n' >&2; exit 1; }
fi

echo "residual-marker detection checks passed"
