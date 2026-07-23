#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

# shellcheck source=../../lib/common.sh
. "$ROOT_DIR/lib/common.sh"

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

# Fakes an interpreter reporting a specific simulated (3, MINOR) version,
# without depending on the real system python3's actual version: it parses
# the `(3, N)` required-minor out of the -c code _watchdogvpn_python_ok
# passes and compares against its own simulated minor entirely in bash.
make_fake_python() {
  local name="$1" simulated_minor="$2"
  local path="$TMP_DIR/$name"
  {
    # Absolute shebang, not "#!/usr/bin/env bash": the fallthrough check
    # below deliberately restricts PATH to only $TMP_DIR, and env resolves
    # its own argument (bash) through that same restricted PATH too.
    printf '#!/bin/bash\n'
    printf 'if [[ "$1" == "-c" ]]; then\n'
    printf '  if [[ "$2" =~ \\(3,\\ ([0-9]+)\\) ]]; then\n'
    printf '    [[ %s -ge "${BASH_REMATCH[1]}" ]] && exit 0 || exit 1\n' "$simulated_minor"
    printf '  fi\n'
    printf 'fi\n'
    printf 'exit 0\n'
  } >"$path"
  chmod 0755 "$path"
}

# Rocky Linux 9's platform python3 is 3.9: new enough for `from __future__
# import annotations` (3.7+) but one minor version short of
# dataclass(slots=True), used throughout this codebase, added in 3.10.
# Regression guard for the real bug this exposed: WATCHDOGVPN_MIN_PYTHON_MINOR
# used to default to 9, so the resolver wrongly accepted a 3.9 system python3
# as adequate, and the daemon crashed at startup with
# "dataclass() got an unexpected keyword argument 'slots'".
make_fake_python python3.9-like 9
make_fake_python python3.10-like 10

unset _WATCHDOGVPN_PYTHON_RESOLVED
if PATH="$TMP_DIR:$PATH" _watchdogvpn_python_ok python3.9-like; then
  printf 'FAIL: a 3.9 interpreter must not satisfy the resolver minimum\n' >&2
  exit 1
fi

unset _WATCHDOGVPN_PYTHON_RESOLVED
if ! PATH="$TMP_DIR:$PATH" _watchdogvpn_python_ok python3.10-like; then
  printf 'FAIL: a 3.10 interpreter must satisfy the resolver minimum\n' >&2
  exit 1
fi

if [[ "$WATCHDOGVPN_MIN_PYTHON_MINOR" != "10" ]]; then
  printf 'FAIL: WATCHDOGVPN_MIN_PYTHON_MINOR must default to 10, got %s\n' \
    "$WATCHDOGVPN_MIN_PYTHON_MINOR" >&2
  exit 1
fi

# watchdogvpn_python() must skip an inadequate system python3 and fall
# through to a newer explicitly-provided candidate rather than accepting it.
# PATH is restricted to only $TMP_DIR (not $PATH too) so the real system's
# own newer python3.X binaries cannot mask the fallthrough being tested.
ln -sf "$TMP_DIR/python3.9-like" "$TMP_DIR/python3"
ln -sf "$TMP_DIR/python3.10-like" "$TMP_DIR/python3.10"
resolved="$(bash -c "PATH=\"$TMP_DIR\"; source \"$ROOT_DIR/lib/common.sh\"; watchdogvpn_python")"
if [[ "$resolved" != "$TMP_DIR/python3.10" ]]; then
  printf 'FAIL: watchdogvpn_python must fall through a too-old system python3 to a newer python3.X, got %s\n' \
    "$resolved" >&2
  exit 1
fi

echo "watchdogvpn python resolver checks passed"
