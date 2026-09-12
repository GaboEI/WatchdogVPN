#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

# shellcheck source=../../lib/common.sh
. "$ROOT_DIR/lib/common.sh"

assert_contains() {
  local expected="$1"
  local actual="$2"
  local label="$3"
  if [[ "$actual" != *"$expected"* ]]; then
    printf 'FAIL %s: expected to contain %q, got %q\n' "$label" "$expected" "$actual" >&2
    exit 1
  fi
}

DISTRO_NAME="ExampleOS"
DISTRO_ID="exampleos"

unsupported_output="$(print_unsupported_distro)"
assert_contains "unsupported distro" "$unsupported_output" "unsupported_distro headline"
assert_contains "currently supports Ubuntu" "$unsupported_output" "unsupported_distro hint"

future_output="$(print_future_distro)"
assert_contains "planned for a future release" "$future_output" "future_distro headline"
assert_contains "not yet supported" "$future_output" "future_distro body"

undetermined_output="$(print_undetermined_distro)"
assert_contains "cannot be determined" "$undetermined_output" "undetermined_distro headline"
assert_contains "compat/compatibility.json" "$undetermined_output" "undetermined_distro manifest hint"

printf 'shell distro state checks passed\n'
