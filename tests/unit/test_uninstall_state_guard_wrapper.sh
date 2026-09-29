#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
UNINSTALLER="$ROOT_DIR/uninstall.sh"
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

FAKE_BIN="$TMP_DIR/fake-bin"
mkdir -p "$FAKE_BIN"
cat >"$FAKE_BIN/sudo" <<'SUDO'
#!/usr/bin/env bash
set -euo pipefail
[[ "${1:-}" == "-n" ]] || exit 97
shift
if [[ "${1:-}" == "-v" ]]; then
  exit 0
fi
"$@"
SUDO
chmod 0755 "$FAKE_BIN/sudo"
export PATH="$FAKE_BIN:$PATH"

WRAPPER="/usr/local/bin/watchdogvpn-state-guard"
etc_dir="$TMP_DIR/etc/watchdogvpn"
mkdir -p "$etc_dir"

# PR25-F2: the state-guard wrapper is installed by this change set, so the
# supported uninstall must plan its removal. The dry run reports the exact
# removal decision for every product runtime path, so the wrapper must appear
# there instead of being silently ignored.
uninstall_output="$(WATCHDOGVPN_ETC_CONFIG_DIR="$etc_dir" "$UNINSTALLER" --dry-run --yes 2>&1)"
if ! grep -Fq -- "$WRAPPER" <<<"$uninstall_output"; then
  printf 'FAIL: supported uninstall does not address %s\n' "$WRAPPER" >&2
  exit 1
fi

# Behavioural control: the removal primitive the uninstaller uses for a listed
# root path really deletes it (stubbed sudo, isolated temporary file).
(
  # shellcheck source=../../lib/common.sh
  . "$ROOT_DIR/lib/common.sh"
  # shellcheck source=../../lib/install_files.sh
  . "$ROOT_DIR/lib/install_files.sh"

  sudo() { "$@"; }
  REMOVE_ROOT_PATH_BACKUPS=0
  INSTALL_DRY_RUN=0

  victim="$TMP_DIR/state-guard-wrapper"
  printf 'wrapper\n' >"$victim"
  remove_root_path "$victim" >/dev/null
  if [[ -e "$victim" ]]; then
    printf 'FAIL: remove_root_path left %s in place\n' "$victim" >&2
    exit 1
  fi
)

echo "uninstall state-guard wrapper checks passed"
