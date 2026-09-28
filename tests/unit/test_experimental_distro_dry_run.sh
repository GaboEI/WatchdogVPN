#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

# shellcheck source=../../lib/common.sh
. "$ROOT_DIR/lib/common.sh"
# shellcheck source=../../lib/distro.sh
. "$ROOT_DIR/lib/distro.sh"

fail() {
  printf 'FAIL: %s\n' "$1" >&2
  exit 1
}

assert_contains() {
  local haystack="$1" needle="$2" label="$3"
  [[ "$haystack" == *"$needle"* ]] || {
    printf 'FAIL %s: expected to contain %q\n%s\n' "$label" "$needle" "$haystack" >&2
    exit 1
  }
}

assert_eq() {
  local expected="$1" actual="$2" label="$3"
  [[ "$expected" == "$actual" ]] || {
    printf 'FAIL %s: expected %q, got %q\n' "$label" "$expected" "$actual" >&2
    exit 1
  }
}

# Byte-level state snapshot: path, kind, mode, size and content hash.
snapshot_tree() {
  local root="$1"
  if [[ ! -e "$root" ]]; then
    printf 'ABSENT %s\n' "$root"
    return 0
  fi
  find "$root" -print0 | sort -z | while IFS= read -r -d '' path; do
    if [[ -f "$path" ]]; then
      printf 'F %s %s %s %s\n' "$path" "$(stat -c '%a' "$path")" "$(stat -c '%s' "$path")" \
        "$(sha256sum "$path" | awk '{print $1}')"
    elif [[ -d "$path" ]]; then
      printf 'D %s %s\n' "$path" "$(stat -c '%a' "$path")"
    else
      printf 'O %s\n' "$path"
    fi
  done
}

# ---------------------------------------------------------------------------
# 1. Helper-level dry-run: the acceptance is simulated, nothing is persisted.
# ---------------------------------------------------------------------------
MARKER_DIR="$TMP_DIR/state"
MARKER="$MARKER_DIR/.experimental-distro-override"
WATCHDOGVPN_EXPERIMENTAL_OVERRIDE_MARKER="$MARKER"
DISTRO_ID="tpr23future"
DISTRO_NAME="T-PR23 Future Linux"

before="$(snapshot_tree "$TMP_DIR")"
INSTALL_DRY_RUN=1
dry_out="$(distro_record_experimental_override "via --accept-experimental-distro-risk" 2>&1)"
after="$(snapshot_tree "$TMP_DIR")"

assert_eq "$before" "$after" "helper dry-run: byte-for-byte zero mutation of designated state"
[[ ! -e "$MARKER" ]] || fail "helper dry-run: marker must not be created"
[[ ! -d "$MARKER_DIR" ]] || fail "helper dry-run: marker parent directory must not be created"
assert_contains "$dry_out" "is simulated only to produce this plan" "helper dry-run: simulated wording"
assert_contains "$dry_out" "NOT persisted" "helper dry-run: not-persisted wording"
assert_contains "$dry_out" "via --accept-experimental-distro-risk" "helper dry-run: trigger named"
if [[ "$dry_out" == *"risk accepted via --accept-experimental-distro-risk"* ]]; then
  fail "helper dry-run: output must not claim the acceptance was persisted"
fi

# ---------------------------------------------------------------------------
# 2. Helper-level real execution (isolated, redirected marker): the marker is
#    created with the expected content, permissions and distro binding.
# ---------------------------------------------------------------------------
INSTALL_DRY_RUN=0
real_out="$(distro_record_experimental_override "via --accept-experimental-distro-risk" 2>&1)"
[[ -f "$MARKER" ]] || fail "real run: marker must be created"
assert_eq "tpr23future" "$(head -n 1 "$MARKER")" "real run: marker records DISTRO_ID"
assert_contains "$(cat "$MARKER")" "T-PR23 Future Linux" "real run: marker records DISTRO_NAME"
assert_eq "3" "$(wc -l < "$MARKER")" "real run: marker has id, name and timestamp lines"
assert_eq "600" "$(stat -c '%a' "$MARKER")" "real run: marker mode 0600"
assert_eq "700" "$(stat -c '%a' "$MARKER_DIR")" "real run: marker directory mode 0700"
assert_contains "$real_out" "risk accepted via --accept-experimental-distro-risk" "real run: persisted wording"

# ---------------------------------------------------------------------------
# 3. Cross-distro regression: an acceptance never transfers to another distro.
# ---------------------------------------------------------------------------
distro_experimental_override_accepted || fail "same distro: recorded acceptance must be honored"
DISTRO_ID="zorin"
DISTRO_NAME="Zorin OS"
if distro_experimental_override_accepted; then
  fail "cross-distro: acceptance must not transfer to a different distro"
fi
DISTRO_ID="tpr23future"
DISTRO_NAME="T-PR23 Future Linux"
distro_experimental_override_accepted || fail "same distro again: acceptance must survive"

# Restore a fresh, marker-less baseline before the full-flow dry-run checks.
rm -f "$MARKER"
rmdir "$MARKER_DIR" 2>/dev/null || true

# ---------------------------------------------------------------------------
# 4/5. Full install.sh and update.sh dry-run flows with
#      --accept-experimental-distro-risk on an experimental distro fixture:
#      designated state paths stay byte-for-byte identical and the output
#      communicates that the acceptance is simulated and not persisted.
# ---------------------------------------------------------------------------
FAKE_BIN="$TMP_DIR/fake-bin"
mkdir -p "$FAKE_BIN"

cat >"$FAKE_BIN/sudo" <<'SUDO'
#!/usr/bin/env bash
set -euo pipefail
non_interactive=0
validate=0
while (($#)); do
  case "$1" in
    -n) non_interactive=1; shift ;;
    -v) validate=1; shift ;;
    --) shift; break ;;
    *) break ;;
  esac
done
if ((non_interactive == 0)); then
  printf 'interactive-sudo-invoked\n' >&2
  exit 97
fi
((validate == 0)) || exit 0
"$@"
SUDO
chmod 0755 "$FAKE_BIN/sudo"

# Report a verifiable committed tree so the provenance preflight can run while
# this test executes from a developer checkout. Everything else delegates to
# the real git.
cat >"$FAKE_BIN/git" <<'GIT'
#!/usr/bin/env bash
if [[ "${1:-}" == "-C" ]]; then
  shift 2
fi
case "${1:-}" in
  rev-parse)
    shift
    if [[ "${1:-}" == "--verify" ]]; then
      shift
    fi
    case "${1:-}" in
      HEAD|'HEAD^{commit}')
        printf '%040d\n' 0
        exit 0
        ;;
    esac
    ;;
  status)
    exit 0
    ;;
esac
exec /usr/bin/git "$@"
GIT
chmod 0755 "$FAKE_BIN/git"

cat >"$TMP_DIR/os-release-ubuntu26" <<'OSREL'
ID=ubuntu
PRETTY_NAME="Ubuntu 26.04 LTS"
VERSION_ID="26.04"
VERSION_CODENAME=resolute
UBUNTU_CODENAME=resolute
OSREL

mkdir -p "$TMP_DIR/etc-config" "$TMP_DIR/preflight-root" \
  "$TMP_DIR/shared-state" "$TMP_DIR/legacy-state" "$TMP_DIR/home/.local/bin"
: >"$TMP_DIR/home/.local/bin/VPN"

flow_env=(
  env
  "PATH=$FAKE_BIN:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
  "HOME=$TMP_DIR/home"
  "OS_RELEASE_FILE=$TMP_DIR/os-release-ubuntu26"
  "WATCHDOGVPN_ETC_CONFIG_DIR=$TMP_DIR/etc-config"
  "WATCHDOGVPN_CONFIG_FILE=$TMP_DIR/etc-config/config.toml"
  "WATCHDOGVPN_EXPERIMENTAL_OVERRIDE_MARKER=$MARKER"
  "WATCHDOGVPN_PREFLIGHT_ROOT=$TMP_DIR/preflight-root"
  "WATCHDOGVPN_SHARED_STATE_DIR=$TMP_DIR/shared-state"
  "WATCHDOGVPN_LEGACY_CONFIG_DIR=$TMP_DIR/legacy-state"
)

run_dry_flow() {
  local script="$1"
  "${flow_env[@]}" "$ROOT_DIR/$script" \
    --dry-run --yes --skip-doctor --accept-experimental-distro-risk 2>&1
}

for flow in install.sh update.sh; do
  state_before="$(snapshot_tree "$TMP_DIR/state"; snapshot_tree "$TMP_DIR/etc-config")"
  flow_out="$(run_dry_flow "$flow")"
  state_after="$(snapshot_tree "$TMP_DIR/state"; snapshot_tree "$TMP_DIR/etc-config")"

  assert_eq "$state_before" "$state_after" "$flow dry-run: byte-for-byte zero mutation of designated state"
  [[ ! -e "$MARKER" ]] || fail "$flow dry-run: marker must not be created"
  [[ ! -d "$MARKER_DIR" ]] || fail "$flow dry-run: marker parent directory must not be created"
  assert_contains "$flow_out" "is simulated only to produce this plan" "$flow dry-run: simulated wording"
  assert_contains "$flow_out" "NOT persisted" "$flow dry-run: not-persisted wording"
  assert_contains "$flow_out" "via --accept-experimental-distro-risk" "$flow dry-run: trigger named"
  if [[ "$flow_out" == *"risk accepted via --accept-experimental-distro-risk"* ]]; then
    fail "$flow dry-run: output must not claim the acceptance was persisted"
  fi
  assert_contains "$flow_out" "dry-run mode: no system changes will be made" "$flow dry-run: plan still produced"
done

printf 'experimental distro dry-run integrity checks passed\n'
