#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

assert_contains() {
  local expected="$1"
  local actual="$2"
  local label="$3"
  if [[ "$actual" != *"$expected"* ]]; then
    printf 'FAIL %s: expected to contain %q\n' "$label" "$expected" >&2
    printf 'Actual output:\n%s\n' "$actual" >&2
    exit 1
  fi
}

# Build an isolated doctor tree where lib/distro.sh is a mock.
# Use real copies (never symlinks) so the mock replacement cannot write
# through to the repository files.
mkdir -p "$TMP_DIR/lib"
cp "$ROOT_DIR/doctor.sh" "$TMP_DIR/doctor.sh"
for lib in "$ROOT_DIR/lib"/*.sh; do
  cp "$lib" "$TMP_DIR/lib/$(basename "$lib")"
done

# Replace lib/distro.sh with a deterministic mock.
cat > "$TMP_DIR/lib/distro.sh" <<'MOCK'
detect_distro() {
  DISTRO_ID="${MOCK_DISTRO_ID:-unknown}"
  DISTRO_NAME="${MOCK_DISTRO_NAME:-Unknown Linux}"
  DISTRO_ADAPTER_ID="${MOCK_DISTRO_ADAPTER_ID:-$DISTRO_ID}"
  DISTRO_FAMILY="${MOCK_DISTRO_FAMILY:-$DISTRO_ID}"
  DISTRO_PACKAGE_MANAGER="${MOCK_DISTRO_PACKAGE_MANAGER:-unknown}"
  DISTRO_SUPPORTED="${MOCK_DISTRO_SUPPORTED:-0}"
  DISTRO_FUTURE="${MOCK_DISTRO_FUTURE:-0}"
  DISTRO_UNSUPPORTED="${MOCK_DISTRO_UNSUPPORTED:-0}"
  DISTRO_UNDETERMINED="${MOCK_DISTRO_UNDETERMINED:-0}"
}

distro_adapter_path() {
  printf '%s/distros/%s.sh' "$1" "${DISTRO_ADAPTER_ID:-$DISTRO_ID}"
}
MOCK

run_doctor() {
  (
    cd "$TMP_DIR"
    bash "$TMP_DIR/doctor.sh" 2>&1 || true
  )
}

# Future distro
export MOCK_DISTRO_ID="ubuntu"
export MOCK_DISTRO_NAME="Ubuntu 26.04 LTS"
export MOCK_DISTRO_ADAPTER_ID="ubuntu"
export MOCK_DISTRO_FAMILY="ubuntu"
export MOCK_DISTRO_PACKAGE_MANAGER="apt"
export MOCK_DISTRO_SUPPORTED="0"
export MOCK_DISTRO_FUTURE="1"
export MOCK_DISTRO_UNSUPPORTED="0"
export MOCK_DISTRO_UNDETERMINED="0"
output="$(run_doctor)"
assert_contains "distro support is planned for a future release" "$output" "future distro doctor output"

# Unsupported distro
export MOCK_DISTRO_ID="exampleos"
export MOCK_DISTRO_NAME="ExampleOS"
export MOCK_DISTRO_ADAPTER_ID="exampleos"
export MOCK_DISTRO_FAMILY="exampleos"
export MOCK_DISTRO_PACKAGE_MANAGER="unknown"
export MOCK_DISTRO_SUPPORTED="0"
export MOCK_DISTRO_FUTURE="0"
export MOCK_DISTRO_UNSUPPORTED="1"
export MOCK_DISTRO_UNDETERMINED="0"
output="$(run_doctor)"
assert_contains "unsupported distro for this release" "$output" "unsupported distro doctor output"

# Undetermined distro (engine unavailable)
export MOCK_DISTRO_ID="exampleos"
export MOCK_DISTRO_NAME="ExampleOS"
export MOCK_DISTRO_ADAPTER_ID="exampleos"
export MOCK_DISTRO_FAMILY="exampleos"
export MOCK_DISTRO_PACKAGE_MANAGER="unknown"
export MOCK_DISTRO_SUPPORTED="0"
export MOCK_DISTRO_FUTURE="0"
export MOCK_DISTRO_UNSUPPORTED="0"
export MOCK_DISTRO_UNDETERMINED="1"
output="$(run_doctor)"
assert_contains "unsupported distro for this release" "$output" "undetermined distro doctor output treated as unsupported"

printf 'doctor distro state checks passed\n'
