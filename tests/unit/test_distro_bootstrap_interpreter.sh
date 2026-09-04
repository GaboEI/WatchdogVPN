#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

# shellcheck source=../../lib/common.sh
. "$ROOT_DIR/lib/common.sh"
# shellcheck source=../../lib/distro.sh
. "$ROOT_DIR/lib/distro.sh"
# shellcheck source=../../lib/install_files.sh
. "$ROOT_DIR/lib/install_files.sh"
# shellcheck source=../../lib/packages.sh
. "$ROOT_DIR/lib/packages.sh"

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

REAL_PYTHON="$(command -v python3)"
if [[ -z "$REAL_PYTHON" ]]; then
  printf 'FAIL: this test requires a real python3 on the host\n' >&2
  exit 1
fi

assert_eq() {
  local expected="$1" actual="$2" label="$3"
  if [[ "$expected" != "$actual" ]]; then
    printf 'FAIL %s: expected %s, got %s\n' "$label" "$expected" "$actual" >&2
    exit 1
  fi
}

# Simulate openSUSE Leap 15.6: default python3 reports (3,6), so the detection
# gate (3.7+) rejects it and the engine cannot run.
mkdir -p "$TMP_DIR/bin"
{
  printf '#!/bin/bash\n'
  printf 'if [[ "$1" == "-c" ]]; then\n'
  printf '  if [[ "$2" =~ \\(3,\\ ([0-9]+)\\) ]]; then\n'
  printf '    [[ 6 -ge "${BASH_REMATCH[1]}" ]] && exit 0 || exit 1\n'
  printf '  fi\n'
  printf '  exit 1\n'
  printf 'fi\n'
  printf 'exit 1\n'
} > "$TMP_DIR/bin/python3"
chmod +x "$TMP_DIR/bin/python3"

# The engine wrapper uses the external `timeout` command, which must be visible
# inside the restricted-PATH subshells below. Provide a thin wrapper that execs
# the real timeout so the detection gate still only sees the fake python3.
TIMEOUT_REAL="$(command -v timeout)"
{
  printf '#!/bin/bash\n'
  printf 'exec %s "$@"\n' "$TIMEOUT_REAL"
} > "$TMP_DIR/bin/timeout"
chmod +x "$TMP_DIR/bin/timeout"

printf 'ID="opensuse-leap"\nID_LIKE="suse opensuse"\nVERSION_ID="15.6"\nPRETTY_NAME="openSUSE Leap 15.6"\n' \
  > "$TMP_DIR/os-release-leap"

# Fake opensuse adapter declaring its pinned interpreter bootstrap package.
# distro_adapter_path is overridden so the bootstrap loads this adapter.
cat > "$TMP_DIR/adapter-opensuse.sh" <<'EOF'
DISTRO_PACKAGE_MANAGER="zypper"
DISTRO_PYTHON="python3.11"
distro_python_bootstrap_package() {
  printf '%s\n' "python311"
}
EOF
distro_adapter_path() {
  printf '%s\n' "$TMP_DIR/adapter-opensuse.sh"
}

INSTALL_PACKAGE_SET_CALLS=0
REAL_LN="$(command -v ln)"
install_package_set() {
  INSTALL_PACKAGE_SET_CALLS=$((INSTALL_PACKAGE_SET_CALLS + 1))
  # Simulate a successful zypper install of python311: expose the host's real
  # python3 (>= 3.7) as python3.11 so the engine can then run for real.
  "$REAL_LN" -sf "$REAL_PYTHON" "$TMP_DIR/bin/python3.11"
  return 0
}

# 1. With a 3.6-only interpreter the engine is blocked and the bootstrap
#    installs the adapter-declared interpreter package, then re-runs
#    authoritative detection with the engine (never the Bash fallback).
(
  PATH="$TMP_DIR/bin"
  OS_RELEASE_FILE="$TMP_DIR/os-release-leap"
  detect_distro
  assert_eq "1" "$DISTRO_ENGINE_BLOCKED" "blocked: engine blocked"
  assert_eq "interpreter_missing" "$DISTRO_ENGINE_BLOCKED_REASON" "blocked: reason"
  assert_eq "1" "$DISTRO_UNDETERMINED" "blocked: undetermined"
  assert_eq "opensuse" "$DISTRO_ADAPTER_ID" "blocked: adapter"
  assert_eq "zypper" "$DISTRO_PACKAGE_MANAGER" "blocked: package manager"

  distro_bootstrap_interpreter_if_needed
  assert_eq "1" "$INSTALL_PACKAGE_SET_CALLS" "bootstrap: install_package_set called once"
  assert_eq "0" "$DISTRO_ENGINE_BLOCKED" "bootstrap: engine unlocked"
  assert_eq "0" "$DISTRO_UNDETERMINED" "bootstrap: resolved"
  assert_eq "1" "$DISTRO_SUPPORTED" "bootstrap: classified supported"
)

# 2. dry-run must simulate/omit the new bootstrap step: install_package_set is
#    never called and no interpreter is materialized.
INSTALL_PACKAGE_SET_CALLS=0
rm -f "$TMP_DIR/bin/python3.11"
(
  PATH="$TMP_DIR/bin"
  OS_RELEASE_FILE="$TMP_DIR/os-release-leap"
  INSTALL_DRY_RUN=1
  detect_distro
  assert_eq "1" "$DISTRO_ENGINE_BLOCKED" "dry-run: engine blocked"
  distro_bootstrap_interpreter_if_needed
  assert_eq "0" "$INSTALL_PACKAGE_SET_CALLS" "dry-run: install_package_set NOT called"
  if [[ -e "$TMP_DIR/bin/python3.11" ]]; then
    printf 'FAIL dry-run: python3.11 must not be created\n' >&2
    exit 1
  fi
)

# 3. Non-operation: when the engine already ran (not blocked), the bootstrap is
#    a no-op and never touches the package manager. This is the no-regression
#    guard for all eight certified distros and Tumbleweed: their default
#    python3 is >= 3.7, so the new bootstrap step must stay non-operative.
cat > "$TMP_DIR/adapter-nohook.sh" <<'EOF'
DISTRO_PACKAGE_MANAGER="apt"
DISTRO_PYTHON="python3"
EOF
distro_adapter_path() {
  printf '%s\n' "$TMP_DIR/adapter-nohook.sh"
}
INSTALL_PACKAGE_SET_CALLS=0
(
  OS_RELEASE_FILE="$TMP_DIR/os-release-leap"
  detect_distro
  assert_eq "0" "$DISTRO_ENGINE_BLOCKED" "noop: engine not blocked (real host python >=3.7)"
  distro_bootstrap_interpreter_if_needed
  assert_eq "0" "$INSTALL_PACKAGE_SET_CALLS" "noop: install_package_set NOT called"
)

printf 'distro bootstrap interpreter checks passed\n'