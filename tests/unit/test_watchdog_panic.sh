#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

# Coverage for the WatchdogVPN panic button (bin/watchdog_panic): a
# dedicated "sleep everything until I explicitly wake it" state, distinct
# from `watchdog disconnect` (only tears down the active tunnel) and from
# disabling autostart (only affects the next boot). See docs/security.md
# "WatchdogVPN Panic Button".

# shellcheck source=../../lib/install_files.sh
. "$ROOT_DIR/lib/install_files.sh"
# shellcheck source=../../lib/systemd.sh
. "$ROOT_DIR/lib/systemd.sh"

sudo() { "$@"; }

assert_contains() {
  local file="$1" pattern="$2" message="$3"
  if ! grep -Fq "$pattern" "$file"; then
    printf 'FAIL: %s\n' "$message" >&2
    exit 1
  fi
}

assert_not_contains() {
  local file="$1" pattern="$2" message="$3"
  if grep -Fq "$pattern" "$file"; then
    printf 'FAIL: %s\n' "$message" >&2
    exit 1
  fi
}

# --- static wiring ---

bash -n "$ROOT_DIR/bin/watchdog_panic"

assert_contains "$ROOT_DIR/lib/systemd.sh" 'enable_watchdogvpn_service_unless_hibernating' \
  "enable_systemd_units must call the hibernate-aware daemon enabler"
assert_contains "$ROOT_DIR/lib/systemd.sh" 'for unit in "${SYSTEMD_ENABLE_UNITS[@]}" watchdogvpn.service vpn-domain-bypass.timer' \
  "disable_systemd_units must still disable watchdogvpn.service on uninstall regardless of hibernate state"
assert_contains "$ROOT_DIR/lib/systemd.sh" 'remove_kill_switch_rules' \
  "lib/systemd.sh must define kill switch firewall cleanup"
assert_contains "$ROOT_DIR/uninstall.sh" 'remove_kill_switch_rules' \
  "uninstall must remove kill switch firewall rules before removing files"
assert_contains "$ROOT_DIR/uninstall.sh" 'remove_root_path /usr/local/bin/watchdog_panic' \
  "uninstall must remove the panic button script"
assert_contains "$ROOT_DIR/lib/runtime.sh" 'watchdog_panic' \
  "runtime install must ship watchdog_panic"
assert_contains "$ROOT_DIR/lib/runtime.sh" 'WATCHDOGVPN_HIBERNATE_MARKER' \
  "daemon smoke test must be aware of the hibernate marker"
assert_contains "$ROOT_DIR/bin/watchdog_panic" 'HIBERNATE_MARKER' \
  "panic script must write/read the hibernate marker"
assert_contains "$ROOT_DIR/bin/watchdog_panic" 'KILL_SWITCH_NFT_TABLE' \
  "panic script must clean up kill switch firewall state"

# Regression: the user's own manual incident-recovery script had to pkill
# leftover processes directly (systemctl stop alone wasn't enough to
# convince them everything was actually down). The precise, safe equivalent
# is scoping to the dedicated `watchdogvpn` system user (systemd/watchdogvpn.service
# User=/Group=watchdogvpn; drivers/singbox_driver.py never switches users),
# never a name/command-line match that could hit an unrelated sing-box the
# user runs independently.
assert_contains "$ROOT_DIR/bin/watchdog_panic" 'pkill -u watchdogvpn' \
  "sleep must defensively pkill leftover processes scoped to the watchdogvpn system user"
assert_contains "$ROOT_DIR/bin/watchdog_panic" 'id -u watchdogvpn' \
  "the pkill -u watchdogvpn cleanup must guard on the system user actually existing"

# Regression: found live while manually testing this script - `systemctl
# is-enabled`/`is-active` already print "not-found"/"disabled"/"inactive"
# themselves and exit non-zero even for a real, valid disabled/inactive
# unit, so `|| echo "not-found"` double-prints the state line. The
# established correct pattern in this codebase is `|| true`
# (doctor.sh::systemd_active_state/systemd_enabled_state).
assert_not_contains "$ROOT_DIR/bin/watchdog_panic" '|| echo "not-found"' \
  "must not double-print systemctl state; use '|| true' like doctor.sh does"
assert_not_contains "$ROOT_DIR/bin/vpn_domain_bypass_rescue" '|| echo "not-found"' \
  "must not double-print systemctl state; use '|| true' like doctor.sh does"

# Regression: found live on a Rocky Linux 9 certification VM (Task
# 23.6.5b). `sudo watchdog_panic sleep`'s own internal `watchdog disconnect`
# step resolves "watchdog" by bare name; sudo's default secure_path on
# several distros strips /usr/local/bin, so `have watchdog` silently
# returned false there, the disconnect step never actually ran despite
# printing as if it had, vpn_desired_state stayed "on", and the daemon's own
# fail-safe shutdown handler then re-applied the very kill switch this
# command exists to remove - confirmed live via
# `sudo watchdog disconnect` -> "sudo: watchdog: command not found", and
# `sudo journalctl -u watchdogvpn.service` showing
# kill_switch_atomic_apply_succeeded during the same systemctl stop this
# script triggers.
assert_contains "$ROOT_DIR/bin/watchdog_panic" 'PATH="${WATCHDOGVPN_PANIC_PATH_PREFIX:-/usr/local/bin:/usr/local/sbin}:$PATH"' \
  "panic script must extend its own PATH so bare-name lookups (watchdog, etc.) work even under sudo's stripped secure_path"

# --- behavioral: enable_watchdogvpn_service_unless_hibernating() ---

marker="$TMP_DIR/hibernating"
STUB_ENABLE_CALLED=0
systemctl() {
  case "$1" in
    enable)
      STUB_ENABLE_CALLED=1
      ;;
    *)
      return 0
      ;;
  esac
}
INSTALL_DRY_RUN=0

# Marker present: must not enable/start the daemon.
: > "$marker"
STUB_ENABLE_CALLED=0
WATCHDOGVPN_HIBERNATE_MARKER="$marker" enable_watchdogvpn_service_unless_hibernating >/dev/null
if ((STUB_ENABLE_CALLED == 1)); then
  echo "FAIL: must not enable watchdogvpn.service while the hibernate marker is present" >&2
  exit 1
fi

# Marker absent: must enable/start the daemon normally.
rm -f "$marker"
STUB_ENABLE_CALLED=0
WATCHDOGVPN_HIBERNATE_MARKER="$marker" enable_watchdogvpn_service_unless_hibernating >/dev/null
if ((STUB_ENABLE_CALLED != 1)); then
  echo "FAIL: must enable watchdogvpn.service when not hibernating" >&2
  exit 1
fi

# --- behavioral: remove_kill_switch_rules() tolerates a system with none of
#     nft/iptables/ip6tables available (run in a subshell so overriding the
#     `command` builtin cannot affect anything after this check) ---

(
  command() { return 1; }
  INSTALL_DRY_RUN=0
  remove_kill_switch_rules
) || {
  echo "FAIL: remove_kill_switch_rules must not fail when no firewall backend is available" >&2
  exit 1
}

# --- behavioral: sleep's graceful disconnect step must find "watchdog"
#     even when invoked with sudo's stripped secure_path (Rocky regression
#     above) - full subprocess run, not a sourced-function override, since
#     bin/watchdog_panic is a standalone script, and this is exactly the
#     "sudo watchdog_panic sleep" invocation shape that broke live. ---

fakebin="$TMP_DIR/fakebin"
mkdir -p "$fakebin"
disconnect_marker="$TMP_DIR/watchdog-disconnect-called"

cat >"$fakebin/watchdog" <<EOF
#!/usr/bin/env bash
if [[ "\$1" == "disconnect" ]]; then
  : > "$disconnect_marker"
fi
exit 0
EOF
chmod +x "$fakebin/watchdog"

# No-op stand-ins for every other external command sleep_watchdogvpn()
# touches, so the full script can actually run to completion in this
# sandbox without hitting real sudo/systemd/nft/iptables state.
for stub in sudo systemctl nft iptables ip6tables pkill vpn_domain_bypass_rescue; do
  cat >"$fakebin/$stub" <<'EOF'
#!/usr/bin/env bash
exit 0
EOF
  chmod +x "$fakebin/$stub"
done

rm -f "$disconnect_marker"
WATCHDOGVPN_PANIC_PATH_PREFIX="$fakebin" \
  HIBERNATE_MARKER="$TMP_DIR/hibernating-marker" \
  PATH="/usr/bin:/bin" \
  bash "$ROOT_DIR/bin/watchdog_panic" sleep >/dev/null 2>&1 || true

if [[ ! -e "$disconnect_marker" ]]; then
  echo "FAIL: sleep must invoke 'watchdog disconnect' via WATCHDOGVPN_PANIC_PATH_PREFIX even when the inherited PATH lacks it (the sudo secure_path scenario)" >&2
  exit 1
fi

# --- regression: sudo itself cannot find watchdog_panic by bare name -----
#
# Found live on the same Rocky Linux 9 VM while validating the fix above,
# during Task 23.6.5b's evidence closure pass: even with bin/watchdog_panic's
# own internal PATH prepend in place, a real `sudo watchdog_panic sleep`
# (bare name, exactly as documented in docs/security.md) still failed with
# "sudo: watchdog_panic: command not found", because sudo's own secure_path
# lookup of the script happens *before* the script ever runs, so nothing
# inside the script can fix it. /etc/sudoers there: "Defaults secure_path =
# /sbin:/bin:/usr/sbin:/usr/bin" - confirmed via `sudo which watchdog_panic`
# failing while a plain (non-sudo) `command -v watchdog_panic` succeeded.

SUDOERS_FRAGMENT="$ROOT_DIR/etc/sudoers.d/99-watchdogvpn-secure-path"
[[ -f "$SUDOERS_FRAGMENT" ]] || {
  echo "FAIL: missing $SUDOERS_FRAGMENT" >&2
  exit 1
}
assert_contains "$SUDOERS_FRAGMENT" 'Defaults secure_path' \
  "sudoers fragment must extend secure_path, not just document the problem"
assert_contains "$SUDOERS_FRAGMENT" '/usr/local/bin' \
  "sudoers fragment must add /usr/local/bin to secure_path"
assert_contains "$SUDOERS_FRAGMENT" '/usr/local/sbin' \
  "sudoers fragment must add /usr/local/sbin to secure_path"
if command -v visudo >/dev/null 2>&1; then
  visudo -cf "$SUDOERS_FRAGMENT" >/dev/null || {
    echo "FAIL: $SUDOERS_FRAGMENT does not pass visudo -cf; a malformed sudoers.d file can break sudo system-wide" >&2
    exit 1
  }
fi

assert_contains "$ROOT_DIR/lib/runtime.sh" 'install_sudoers_secure_path' \
  "install_runtime_files must install the sudoers secure_path fix"
assert_contains "$ROOT_DIR/lib/runtime.sh" "visudo -cf \"\$src\"" \
  "install_sudoers_secure_path must validate the fragment before installing it"
assert_contains "$ROOT_DIR/lib/runtime.sh" "visudo -cf \"\$dest\"" \
  "install_sudoers_secure_path must re-validate the installed copy and remove it if that ever fails"
assert_contains "$ROOT_DIR/uninstall.sh" 'remove_root_path /etc/sudoers.d/99-watchdogvpn-secure-path' \
  "uninstall must remove the sudoers secure_path fragment"

# --- behavioral: install_sudoers_secure_path() validates, installs, and
#     fails safe if the installed copy somehow does not validate -----------

if command -v visudo >/dev/null 2>&1; then
(
  set -euo pipefail
  # shellcheck disable=SC1090
  source "$ROOT_DIR/lib/install_files.sh"
  # shellcheck disable=SC1090
  source "$ROOT_DIR/lib/runtime.sh"

  sudo() {
    if [[ "$1" == "install" ]]; then
      shift
      local -a filtered=()
      while (($#)); do
        case "$1" in
          -o | -g) shift 2 ;;
          *) filtered+=("$1"); shift ;;
        esac
      done
      command install "${filtered[@]}"
      return
    fi
    "$@"
  }
  INSTALL_DRY_RUN=0

  # Valid fragment: installs successfully and the installed copy itself
  # independently passes visudo -cf (not just trusted because the source did).
  CANDIDATE_ROOT="$TMP_DIR/candidate-valid"
  mkdir -p "$CANDIDATE_ROOT/etc/sudoers.d"
  cp "$SUDOERS_FRAGMENT" "$CANDIDATE_ROOT/etc/sudoers.d/99-watchdogvpn-secure-path"
  WATCHDOGVPN_RUNTIME_CANDIDATE_ROOT="$CANDIDATE_ROOT"
  DEST="$TMP_DIR/installed-sudoers-fragment"
  WATCHDOGVPN_SUDOERS_SECURE_PATH="$DEST"
  install_sudoers_secure_path
  [[ -f "$DEST" ]] || { echo "FAIL: install_sudoers_secure_path did not install a valid fragment" >&2; exit 1; }
  visudo -cf "$DEST" >/dev/null || { echo "FAIL: installed fragment does not independently pass visudo -cf" >&2; exit 1; }

  # Invalid fragment: must refuse to install anything at all, rather than
  # ever leaving a broken sudoers.d file in place - this is the one failure
  # mode that could break sudo system-wide if it silently proceeded.
  BROKEN_ROOT="$TMP_DIR/candidate-broken"
  mkdir -p "$BROKEN_ROOT/etc/sudoers.d"
  printf 'this is not valid sudoers syntax {{{\n' >"$BROKEN_ROOT/etc/sudoers.d/99-watchdogvpn-secure-path"
  WATCHDOGVPN_RUNTIME_CANDIDATE_ROOT="$BROKEN_ROOT"
  BROKEN_DEST="$TMP_DIR/installed-broken-fragment"
  WATCHDOGVPN_SUDOERS_SECURE_PATH="$BROKEN_DEST"
  if install_sudoers_secure_path 2>/dev/null; then
    echo "FAIL: install_sudoers_secure_path must refuse a fragment that fails visudo -cf" >&2
    exit 1
  fi
  [[ ! -e "$BROKEN_DEST" ]] || { echo "FAIL: a fragment that fails validation must never be installed" >&2; exit 1; }
) || {
  echo "FAIL: install_sudoers_secure_path behavioral test failed" >&2
  exit 1
}
fi

printf 'watchdog panic checks passed\n'
